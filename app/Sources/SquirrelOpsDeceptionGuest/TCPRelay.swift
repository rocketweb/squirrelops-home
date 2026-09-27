import Darwin
import Dispatch
import Foundation
import Virtualization

struct PeerEndpoint: Sendable {
    let address: String
    let port: UInt16
}

final class ConnectionLimiter: @unchecked Sendable {
    private let lock = NSLock()
    private let maximum: Int
    private var active = 0

    init(maximum: Int) {
        self.maximum = maximum
    }

    func acquire() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard active < maximum else { return false }
        active += 1
        return true
    }

    func release() {
        lock.lock()
        active = max(0, active - 1)
        lock.unlock()
    }
}

final class TCPListener: @unchecked Sendable {
    typealias Handler = @Sendable (Int32, PeerEndpoint) -> Void

    let localPort: UInt16
    private let fileDescriptor: Int32
    private let queue: DispatchQueue
    private let handler: Handler
    private var source: DispatchSourceRead?

    init(bindAddress: String, handler: @escaping Handler) throws {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw GuestRuntimeFailure.listenerFailure("socket")
        }
        var reuse: Int32 = 1
        guard setsockopt(
            descriptor,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse,
            socklen_t(MemoryLayout<Int32>.size)
        ) == 0 else {
            close(descriptor)
            throw GuestRuntimeFailure.listenerFailure("setsockopt")
        }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        guard bindAddress.withCString({ inet_pton(AF_INET, $0, &address.sin_addr) }) == 1 else {
            close(descriptor)
            throw GuestRuntimeFailure.listenerFailure("bind address")
        }
        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0, listen(descriptor, 128) == 0 else {
            close(descriptor)
            throw GuestRuntimeFailure.listenerFailure("bind or listen")
        }
        let currentFlags = fcntl(descriptor, F_GETFL)
        guard currentFlags >= 0, fcntl(descriptor, F_SETFL, currentFlags | O_NONBLOCK) == 0 else {
            close(descriptor)
            throw GuestRuntimeFailure.listenerFailure("nonblocking listener")
        }

        var boundAddress = sockaddr_in()
        var boundLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &boundAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(descriptor, $0, &boundLength)
            }
        }
        guard nameResult == 0 else {
            close(descriptor)
            throw GuestRuntimeFailure.listenerFailure("getsockname")
        }

        fileDescriptor = descriptor
        localPort = UInt16(bigEndian: boundAddress.sin_port)
        queue = DispatchQueue(label: "com.squirrelops.deception.listener.\(localPort)")
        self.handler = handler
    }

    func start() {
        guard source == nil else { return }
        let readSource = DispatchSource.makeReadSource(
            fileDescriptor: fileDescriptor,
            queue: queue
        )
        readSource.setEventHandler { [weak self] in
            self?.acceptAvailableConnections()
        }
        readSource.setCancelHandler { [fileDescriptor] in
            close(fileDescriptor)
        }
        source = readSource
        readSource.activate()
    }

    func stop() {
        source?.cancel()
        source = nil
    }

    private func acceptAvailableConnections() {
        while true {
            var peerAddress = sockaddr_in()
            var peerLength = socklen_t(MemoryLayout<sockaddr_in>.size)
            let client = withUnsafeMutablePointer(to: &peerAddress) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(fileDescriptor, $0, &peerLength)
                }
            }
            if client < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK { return }
                if errno == EINTR { continue }
                return
            }
            let flags = fcntl(client, F_GETFL)
            if flags < 0 || fcntl(client, F_SETFL, flags & ~O_NONBLOCK) != 0 {
                close(client)
                continue
            }
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            let address = withUnsafePointer(to: &peerAddress.sin_addr) { pointer in
                inet_ntop(AF_INET, pointer, &buffer, socklen_t(INET_ADDRSTRLEN))
            }
            guard address != nil else {
                close(client)
                continue
            }
            let endIndex = buffer.firstIndex(of: 0) ?? buffer.endIndex
            let endpoint = PeerEndpoint(
                address: String(decoding: buffer[..<endIndex].map(UInt8.init(bitPattern:)), as: UTF8.self),
                port: UInt16(bigEndian: peerAddress.sin_port)
            )
            handler(client, endpoint)
        }
    }
}

protocol RelayGuestConnection: AnyObject {
    var fileDescriptor: Int32 { get }
    func close()
}

extension VZVirtioSocketConnection: RelayGuestConnection {}

struct RelayTimeoutPolicy: Sendable {
    var idle: TimeInterval = 300
    var halfClosedIdle: TimeInterval = 30
    var pollInterval: TimeInterval = 1
}

final class SocketRelay: @unchecked Sendable {
    private let client: RelayConnection
    private let guestConnection: any RelayGuestConnection
    private let lock = NSLock()
    private var closed = false
    private var started = false
    private var finishedPumps = 0
    private var aborting = false
    private let timeoutPolicy: RelayTimeoutPolicy
    private let now: @Sendable () -> TimeInterval
    private var lastProgress: TimeInterval
    private var halfClosed = false
    private var watchdog: DispatchSourceTimer?

    init(
        client: RelayConnection,
        guestConnection: any RelayGuestConnection,
        timeoutPolicy: RelayTimeoutPolicy = RelayTimeoutPolicy(),
        now: @escaping @Sendable () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    ) {
        self.client = client
        self.guestConnection = guestConnection
        self.timeoutPolicy = timeoutPolicy
        self.now = now
        lastProgress = now()
    }

    @discardableResult
    func checkDeadline() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard started, !closed, !aborting else { return false }
        let limit = halfClosed ? timeoutPolicy.halfClosedIdle : timeoutPolicy.idle
        guard now() - lastProgress >= limit else { return false }
        cancelLocked()
        return true
    }

    private func madeProgress() {
        lock.lock()
        lastProgress = now()
        lock.unlock()
    }

    func start(schedule: (@escaping @Sendable () -> Void) -> Void = { work in
        DispatchQueue.global(qos: .utility).async(execute: work)
    }) {
        lock.lock()
        guard !started, !closed else { lock.unlock(); return }
        // Shutdown alone is not a reliable wakeup for every Darwin socket
        // interleaving. Nonblocking I/O plus bounded polls lets each worker
        // observe cancellation without closing a descriptor under the other.
        for descriptor in [client.descriptor, guestConnection.fileDescriptor] {
            let flags = fcntl(descriptor, F_GETFL)
            guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
                cancelLocked()
                lock.unlock()
                return
            }
        }
        started = true
        lastProgress = now()
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + timeoutPolicy.pollInterval,
                       repeating: timeoutPolicy.pollInterval)
        timer.setEventHandler { [weak self] in self?.checkDeadline() }
        watchdog = timer
        timer.activate()
        lock.unlock()
        let clientDescriptor = client.descriptor
        let guestDescriptor = guestConnection.fileDescriptor
        schedule { [self] in
            pump(from: clientDescriptor, to: guestDescriptor)
            finish()
        }
        schedule { [self] in
            pump(from: guestDescriptor, to: clientDescriptor)
            finish()
        }
    }

    private func pump(from source: Int32, to destination: Int32) {
        var buffer = [UInt8](repeating: 0, count: 32 * 1024)
        while waitForIO(source, event: Int16(POLLIN)) {
            let count = Darwin.read(source, &buffer, buffer.count)
            if count == 0 {
                // EOF closes only this direction. The peer may still be preparing
                // a response, and both descriptors remain owned until both pumps exit.
                lock.lock()
                if !aborting {
                    shutdown(destination, SHUT_WR)
                    lastProgress = now()
                    halfClosed = true
                }
                lock.unlock()
                return
            }
            if count < 0 {
                if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
                cancel()
                return
            }
            madeProgress()
            var written = 0
            while written < count {
                guard waitForIO(destination, event: Int16(POLLOUT)) else { return }
                let result = buffer.withUnsafeBytes { bytes in
                    Darwin.write(
                        destination,
                        bytes.baseAddress!.advanced(by: written),
                        count - written
                    )
                }
                if result <= 0 {
                    if result < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { continue }
                    cancel()
                    return
                }
                written += result
                madeProgress()
            }
        }
    }

    private func waitForIO(_ descriptor: Int32, event: Int16) -> Bool {
        while !lock.withLock({ aborting }) {
            var request = pollfd(fd: descriptor, events: event, revents: 0)
            let result = poll(&request, 1, 100)
            if result > 0 { return !lock.withLock { aborting } }
            if result < 0 && errno != EINTR {
                cancel()
                return false
            }
        }
        return false
    }

    /// Interrupt I/O without releasing descriptors a worker could still use.
    func cancel() {
        lock.lock()
        defer { lock.unlock() }
        cancelLocked()
    }

    private func cancelLocked() {
        guard !closed, !aborting else { return }
        aborting = true
        watchdog?.cancel()
        watchdog = nil
        shutdown(client.descriptor, SHUT_RDWR)
        shutdown(guestConnection.fileDescriptor, SHUT_RDWR)
        if !started {
            closed = true
            client.close()
            guestConnection.close()
        }
    }

    private func finish() {
        lock.lock()
        defer { lock.unlock() }
        finishedPumps += 1
        guard finishedPumps == 2, !closed else { return }
        // Neither worker can make another syscall after its completion report.
        // Only now may these descriptor numbers and the admission slot be reused.
        closed = true
        watchdog?.cancel()
        watchdog = nil
        client.close()
        guestConnection.close()
    }
}
