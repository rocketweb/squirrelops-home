import Foundation
#if canImport(Darwin)
import Darwin
#endif

let clientSocketTimeoutSeconds = 10

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
