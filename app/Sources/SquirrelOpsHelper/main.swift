import Foundation
#if canImport(Darwin)
import Darwin
#endif
import os

let logger = Logger(subsystem: "com.squirrelops.helper", category: "main")

let socketPath = "/var/run/squirrelops-helper.sock"

// Set up router
let router = RPCRouter()
let dnsSniffer = DNSSniffer()
registerMethods(router: router, dnsSniffer: dnsSniffer)

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

// Restrict socket access: owner (root) + group only, no world access. The
// legitimate caller is the SquirrelOps sensor, which runs as a root
// LaunchDaemon, so root is the only identity that ever needs to connect.
chmod(socketPath, 0o660)

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

    // Verify peer credentials: the only legitimate caller is the root sensor,
    // so accept root (UID 0) exclusively. This is the application-layer gate
    // that backs the 0660 socket permissions; even if those were ever loosened,
    // a non-root local process still could not drive privileged operations.
    var peerUID: uid_t = 0
    var peerGID: gid_t = 0
    guard getpeereid(clientFd, &peerUID, &peerGID) == 0 else {
        logger.warning("getpeereid() failed for client fd \(clientFd): \(String(cString: strerror(errno)))")
        close(clientFd)
        continue
    }
    guard peerUID == 0 else {
        logger.warning("Rejected RPC connection from unauthorized UID \(peerUID)")
        close(clientFd)
        continue
    }

    // Bound how long a single connection can hold the (synchronous) server.
    // A receive timeout means a client that connects and never sends a full
    // line is dropped after CLIENT_READ_TIMEOUT_SECONDS instead of stalling
    // the accept loop forever.
    var tv = timeval(tv_sec: 10, tv_usec: 0)
    setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

    // Read one line directly from the fd (recv), so a read timeout surfaces as
    // a clean nil rather than a FileHandle exception.
    guard let data = readLineFromSocket(fd: clientFd) else {
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
    sendAll(fd: clientFd, data: response)
    close(clientFd)
}

/// Read bytes until newline from a socket fd (max 64 KB). Returns nil on EOF,
/// error, receive timeout, or an over-long line.
func readLineFromSocket(fd: Int32) -> Data? {
    let maxLineLength = 65536
    var buffer = Data()
    var byte: UInt8 = 0
    while true {
        let n = recv(fd, &byte, 1, 0)
        if n == 0 { return buffer.isEmpty ? nil : buffer } // EOF
        if n < 0 { return nil } // error or SO_RCVTIMEO timeout (EAGAIN)
        if byte == 0x0A { return buffer } // newline
        buffer.append(byte)
        if buffer.count > maxLineLength { return nil }
    }
}

/// Write all bytes of ``data`` to a socket fd, handling partial sends.
func sendAll(fd: Int32, data: Data) {
    data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
        guard var ptr = raw.baseAddress else { return }
        var remaining = raw.count
        while remaining > 0 {
            let n = send(fd, ptr, remaining, 0)
            if n <= 0 { return }
            ptr = ptr.advanced(by: n)
            remaining -= n
        }
    }
}
