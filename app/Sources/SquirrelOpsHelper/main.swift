import Foundation
#if canImport(Darwin)
import Darwin
#endif
import os

// Optional dedicated service account the sensor may run as (provisioned by the
// installer for a non-root .pkg deployment). Resolved at startup if present.
let sensorServiceAccount = "_squirrelops"

let logger = Logger(subsystem: "com.squirrelops.helper", category: "main")

let socketPath = "/var/run/squirrelops-helper.sock"
let clientSocketTimeoutSeconds = 10

// Set up router
let router = RPCRouter()
registerMethods(router: router)

// Remove stale socket file
unlink(socketPath)

// Create Unix domain socket
let serverFd = socket(AF_UNIX, SOCK_STREAM, 0)
guard serverFd >= 0 else {
    logger.error("Failed to create socket: \(String(cString: strerror(errno)))")
    exit(1)
}

var addr = sockaddr_un()
addr.sun_family = sa_family_t(AF_UNIX)
withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
    let pathPtr = UnsafeMutableRawPointer(ptr).bindMemory(to: CChar.self, capacity: 104)
    socketPath.withCString { src in
        _ = strlcpy(pathPtr, src, 104)
    }
}

let bindResult = withUnsafePointer(to: &addr) { ptr in
    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
        Darwin.bind(serverFd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
    }
}

guard bindResult == 0 else {
    logger.error("Failed to bind socket: \(String(cString: strerror(errno)))")
    exit(1)
}

// Fail closed if the dedicated service group is unavailable. A normal package
// install creates _squirrelops and restarts this helper before the sensor runs.
if let group = getgrnam(sensorServiceAccount) {
    let serviceGID = group.pointee.gr_gid
    guard chown(socketPath, 0, serviceGID) == 0, chmod(socketPath, 0o660) == 0 else {
        logger.error("Failed to secure helper socket: \(String(cString: strerror(errno)))")
        unlink(socketPath)
        exit(1)
    }
} else {
    logger.error("Service group _squirrelops is unavailable; helper socket is root-only")
    guard chown(socketPath, 0, 0) == 0, chmod(socketPath, 0o600) == 0 else {
        unlink(socketPath)
        exit(1)
    }
}

guard listen(serverFd, 5) == 0 else {
    logger.error("Failed to listen: \(String(cString: strerror(errno)))")
    exit(1)
}

logger.info("com.squirrelops.helper listening on \(socketPath)")

// Handle SIGTERM for graceful shutdown
signal(SIGTERM) { _ in
    unlink(socketPath)
    exit(0)
}

// Accept loop
while true {
    let clientFd = accept(serverFd, nil, nil)
    guard clientFd >= 0 else {
        logger.warning("accept() failed: \(String(cString: strerror(errno)))")
        continue
    }
    guard configureNoSigPipe(fd: clientFd) else {
        logger.warning(
            "Failed to protect client fd \(clientFd) from SIGPIPE: \(String(cString: strerror(errno)))"
        )
        close(clientFd)
        continue
    }

    // Only root and the dedicated sensor account may drive privileged network
    // operations. Desktop users are deliberately excluded because any process
    // in their login session could otherwise obtain the same authority.
    var peerUID: uid_t = 0
    var peerGID: gid_t = 0
    guard getpeereid(clientFd, &peerUID, &peerGID) == 0 else {
        logger.warning("getpeereid() failed for client fd \(clientFd): \(String(cString: strerror(errno)))")
        close(clientFd)
        continue
    }
    guard isAuthorizedPeer(peerUID) else {
        logger.warning("Rejected RPC connection from unauthorized UID \(peerUID)")
        close(clientFd)
        continue
    }

    // Bound both directions before handling the synchronous connection. The
    // absolute deadlines in readLineFromSocket/sendAll also stop a slow-drip
    // peer from extending this per-system-call timeout indefinitely.
    guard configureClientSocketTimeouts(
        fd: clientFd,
        timeoutSeconds: clientSocketTimeoutSeconds
    ) else {
        logger.warning(
            "Failed to configure client socket timeouts for fd \(clientFd): \(String(cString: strerror(errno)))"
        )
        close(clientFd)
        continue
    }

    // Read one line directly from the fd (recv), so a read timeout surfaces as
    // a clean nil rather than a FileHandle exception.
    guard let data = readLineFromSocket(
        fd: clientFd,
        timeoutSeconds: TimeInterval(clientSocketTimeoutSeconds)
    ) else {
        close(clientFd)
        continue
    }

    // Parse and dispatch
    let response: Data
    do {
        let request = try RPCRequest(from: data)
        logger.info("RPC: \(request.method) (id=\(request.id))")
        response = router.dispatch(request)
    } catch {
        response = rpcErrorResponse(id: nil, error: .invalidRequest)
    }

    // Write response and close.
    if !sendAll(
        fd: clientFd,
        data: response,
        timeoutSeconds: TimeInterval(clientSocketTimeoutSeconds)
    ) {
        logger.warning("Timed out or failed writing response to client fd \(clientFd)")
    }
    close(clientFd)
}

/// UID of the optional dedicated service account, if it has been provisioned.
func serviceAccountUID() -> uid_t? {
    guard let pw = getpwnam(sensorServiceAccount) else { return nil }
    return pw.pointee.pw_uid
}

/// Whether a connecting peer UID is allowed to drive privileged operations.
/// Permits root and the provisioned sensor service account.
func isAuthorizedPeer(_ uid: uid_t) -> Bool {
    isAuthorizedPeer(uid, serviceUID: serviceAccountUID())
}

/// Pure authorization rule used by the socket server and regression tests.
func isAuthorizedPeer(_ uid: uid_t, serviceUID: uid_t?) -> Bool {
    if uid == 0 { return true }
    if let serviceUID, uid == serviceUID { return true }
    return false
}

/// Apply a finite timeout to both reads and writes on an accepted client.
func configureClientSocketTimeouts(
    fd: Int32,
    timeoutSeconds: Int
) -> Bool {
    guard timeoutSeconds > 0 else { return false }
    guard configureNonBlocking(fd: fd) else { return false }
    var timeout = timeval(tv_sec: timeoutSeconds, tv_usec: 0)
    let timeoutSize = socklen_t(MemoryLayout<timeval>.size)
    guard setsockopt(
        fd,
        SOL_SOCKET,
        SO_RCVTIMEO,
        &timeout,
        timeoutSize
    ) == 0 else {
        return false
    }
    return setsockopt(
        fd,
        SOL_SOCKET,
        SO_SNDTIMEO,
        &timeout,
        timeoutSize
    ) == 0
}

/// Keep poll-driven socket I/O from falling back to a blocking send/recv after
/// readiness changes between the poll and the system call.
private func configureNonBlocking(fd: Int32) -> Bool {
    let flags = fcntl(fd, F_GETFL)
    guard flags >= 0 else { return false }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0
}

/// Milliseconds remaining before an absolute monotonic deadline, rounded up
/// so a sub-millisecond remainder still gets one final poll.
private func remainingPollMilliseconds(until deadline: UInt64) -> Int32 {
    let now = DispatchTime.now().uptimeNanoseconds
    guard now < deadline else { return 0 }
    let remainingNanoseconds = deadline - now
    let milliseconds = (remainingNanoseconds + 999_999) / 1_000_000
    return Int32(min(milliseconds, UInt64(Int32.max)))
}

private func monotonicDeadline(after timeoutSeconds: TimeInterval) -> UInt64? {
    guard timeoutSeconds.isFinite, timeoutSeconds > 0 else { return nil }
    let timeoutNanoseconds = timeoutSeconds * 1_000_000_000
    guard timeoutNanoseconds < Double(UInt64.max) else { return nil }
    let now = DispatchTime.now().uptimeNanoseconds
    let delta = UInt64(timeoutNanoseconds)
    guard delta <= UInt64.max - now else { return nil }
    return now + delta
}

/// Read bytes until newline from a socket fd (max 64 KB). Returns nil on EOF,
/// error, absolute timeout, or an over-long line.
func readLineFromSocket(
    fd: Int32,
    timeoutSeconds: TimeInterval = TimeInterval(clientSocketTimeoutSeconds)
) -> Data? {
    guard configureNonBlocking(fd: fd),
          let deadline = monotonicDeadline(after: timeoutSeconds) else {
        return nil
    }
    let maxLineLength = 65536
    var buffer = Data()
    var chunk = [UInt8](repeating: 0, count: 4096)

    while true {
        let pollTimeout = remainingPollMilliseconds(until: deadline)
        guard pollTimeout > 0 else { return nil }

        var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let pollResult = poll(&descriptor, 1, pollTimeout)
        if pollResult == 0 { return nil }
        if pollResult < 0 {
            if errno == EINTR { continue }
            return nil
        }
        if descriptor.revents & Int16(POLLNVAL | POLLERR) != 0 {
            return nil
        }

        let count = chunk.withUnsafeMutableBytes { rawBuffer in
            recv(fd, rawBuffer.baseAddress, rawBuffer.count, MSG_DONTWAIT)
        }
        if count == 0 {
            return buffer.isEmpty ? nil : buffer
        }
        if count < 0 {
            if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK {
                continue
            }
            return nil
        }

        for byte in chunk.prefix(Int(count)) {
            if byte == 0x0A { return buffer }
            buffer.append(byte)
            if buffer.count > maxLineLength { return nil }
        }
    }
}

/// Prevent a client that disconnects before a long RPC finishes from killing
/// the helper process when the response is written.
func configureNoSigPipe(fd: Int32) -> Bool {
    var enabled: Int32 = 1
    return setsockopt(
        fd,
        SOL_SOCKET,
        SO_NOSIGPIPE,
        &enabled,
        socklen_t(MemoryLayout<Int32>.size)
    ) == 0
}

/// Write all bytes of ``data`` before an absolute deadline, handling partial
/// and temporarily blocked sends. Returns false on timeout or socket error.
@discardableResult
func sendAll(
    fd: Int32,
    data: Data,
    timeoutSeconds: TimeInterval = TimeInterval(clientSocketTimeoutSeconds)
) -> Bool {
    guard configureNonBlocking(fd: fd),
          let deadline = monotonicDeadline(after: timeoutSeconds) else {
        return false
    }
    return data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Bool in
        guard var ptr = raw.baseAddress else { return true }
        var remaining = raw.count
        while remaining > 0 {
            let pollTimeout = remainingPollMilliseconds(until: deadline)
            guard pollTimeout > 0 else { return false }

            var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let pollResult = poll(&descriptor, 1, pollTimeout)
            if pollResult == 0 { return false }
            if pollResult < 0 {
                if errno == EINTR { continue }
                return false
            }
            if descriptor.revents & Int16(POLLNVAL | POLLERR | POLLHUP) != 0 {
                return false
            }

            let n = send(fd, ptr, remaining, MSG_DONTWAIT)
            if n < 0 {
                if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK {
                    continue
                }
                return false
            }
            if n == 0 { return false }
            ptr = ptr.advanced(by: n)
            remaining -= n
        }
        return true
    }
}
