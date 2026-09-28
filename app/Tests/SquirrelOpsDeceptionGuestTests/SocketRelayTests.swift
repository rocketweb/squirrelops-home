import Darwin
import Foundation
import Testing
@testable import SquirrelOpsDeceptionGuest

@Suite("Socket relay lifetime", .serialized)
struct SocketRelayTests {
    @Test("Automatic half-close watchdog preserves progressing responses then cleans up a silent tail")
    func progressingHalfClose() throws {
        let fixture = try RelayFixture(policy: RelayTimeoutPolicy(idle: 0.3, halfClosedIdle: 0.3, pollInterval: 0.01))
        fixture.relay.start()
        defer { fixture.relay.cancel() }
        shutdown(fixture.clientPeer, SHUT_WR)
        #expect(try readThroughEOF(fixture.guestPeer).isEmpty)
        // Total response duration exceeds the idle limit; progress keeps it alive.
        for _ in 0..<10 {
            try writeAll([42], to: fixture.guestPeer)
            var byte: UInt8 = 0
            #expect(Darwin.read(fixture.clientPeer, &byte, 1) == 1)
            #expect(byte == 42)
            Thread.sleep(forTimeInterval: 0.05)
        }
        #expect(try readThroughEOF(fixture.clientPeer).isEmpty)
        // Worker finalization may follow EOF by a scheduler turn.
        for _ in 0..<100 where fixture.guest.closeCount == 0 { Thread.sleep(forTimeInterval: 0.005) }
        #expect(fixture.guest.closeCount == 1)
        #expect(fixture.limiter.acquire())
        fixture.limiter.release()
    }

    @Test("Idle watchdog interrupts a blocked writer without premature descriptor reuse")
    func blockedWriteDeadline() throws {
        let fixture = try RelayFixture(policy: RelayTimeoutPolicy(idle: 0.1, halfClosedIdle: 0.1, pollInterval: 0.01))
        fixture.relay.start()
        defer { fixture.relay.cancel() }
        let finished = DispatchSemaphore(value: 0)
        let peer = fixture.clientPeer
        DispatchQueue.global().async {
            var bytes = [UInt8](repeating: 42, count: 8192)
            while Darwin.write(peer, &bytes, bytes.count) > 0 {}
            finished.signal()
        }
        // Guest deliberately never drains its receive buffer.
        #expect(finished.wait(timeout: .now() + 3) == .success)
        for _ in 0..<100 where fixture.guest.closeCount == 0 { Thread.sleep(forTimeInterval: 0.005) }
        #expect(fixture.guest.closeCount == 1)
        #expect(fixture.limiter.acquire())
        fixture.limiter.release()
    }

    @Test("Guest EOF cannot retain a silent client's admission indefinitely")
    func guestEOFCleanup() throws {
        let clock = RelayTestClock()
        let fixture = try RelayFixture(now: { clock.now })
        var jobs: [@Sendable () -> Void] = []
        fixture.relay.start { jobs.append($0) }
        fixture.closeGuestPeer()
        jobs[1]()
        clock.advance(31)
        #expect(fixture.relay.checkDeadline())
        // Deadline cancellation must retain ownership until the delayed worker exits.
        #expect(fixture.guest.closeCount == 0)
        fixture.relay.cancel() // Bounded cleanup even against the old behavior.
        jobs[0]()
        #expect(fixture.guest.closeCount == 1)
        #expect(fixture.limiter.acquire())
        fixture.limiter.release()
    }

    @Test("Idle connections expire without closing descriptors under a delayed worker")
    func idleCleanup() throws {
        let clock = RelayTestClock()
        let fixture = try RelayFixture(now: { clock.now })
        var jobs: [@Sendable () -> Void] = []
        fixture.relay.start { jobs.append($0) }
        clock.advance(299)
        #expect(!fixture.relay.checkDeadline())
        clock.advance(2)
        #expect(fixture.relay.checkDeadline())
        #expect(fixture.guest.closeCount == 0)
        fixture.relay.cancel()
        jobs.forEach { $0() }
        #expect(fixture.guest.closeCount == 1)
    }

    @Test("Cancel keeps descriptors until every scheduled worker exits; repeated start is inert")
    func cancelWithDelayedWorkers() throws {
        let fixture = try RelayFixture()
        var jobs: [@Sendable () -> Void] = []
        fixture.relay.start { jobs.append($0) }
        fixture.relay.start { jobs.append($0) }
        #expect(jobs.count == 2)
        fixture.relay.cancel()
        fixture.relay.cancel()
        #expect(fixture.guest.closeCount == 0)
        #expect(fcntl(fixture.client.descriptor, F_GETFD) >= 0)
        jobs[0]()
        #expect(fixture.guest.closeCount == 0)
        jobs[1]()
        fixture.relay.cancel()
        #expect(fixture.guest.closeCount == 1)
        #expect(fixture.limiter.acquire())
        #expect(!fixture.limiter.acquire())
        fixture.limiter.release()
    }

    @Test("Cancel interrupts blocked reads and releases admission once")
    func cancelBlockedWorkers() throws {
        let fixture = try RelayFixture()
        let entered = DispatchSemaphore(value: 0)
        let finished = DispatchGroup()
        fixture.relay.start { work in
            finished.enter()
            DispatchQueue.global().async {
                entered.signal()
                work()
                finished.leave()
            }
        }
        #expect(entered.wait(timeout: .now() + 2) == .success)
        #expect(entered.wait(timeout: .now() + 2) == .success)
        fixture.relay.cancel()
        #expect(finished.wait(timeout: .now() + 2) == .success)
        #expect(fixture.guest.closeCount == 1)
        #expect(fixture.limiter.acquire())
        #expect(!fixture.limiter.acquire())
        fixture.limiter.release()
    }

    @Test("Cancel before start closes once without scheduling workers")
    func cancelBeforeStart() throws {
        let fixture = try RelayFixture()
        fixture.relay.cancel()
        fixture.relay.cancel()
        fixture.relay.start { _ in Issue.record("Cancelled relay scheduled work") }
        #expect(fixture.guest.closeCount == 1)
        #expect(fixture.limiter.acquire())
        fixture.limiter.release()
    }

    @Test("Concurrent transfers preserve bytes across small socket buffers")
    func bidirectionalTransfer() throws {
        let fixture = try RelayFixture()
        fixture.relay.start()
        defer { fixture.relay.cancel() }
        let first = (0..<262_144).map { UInt8($0 % 251) }
        let second = (0..<196_608).map { UInt8($0 % 239) }
        let group = DispatchGroup()
        for (descriptor, outgoing, incoming) in [
            (fixture.clientPeer, first, second), (fixture.guestPeer, second, first),
        ] {
            group.enter()
            DispatchQueue.global().async {
                defer { group.leave(); shutdown(descriptor, SHUT_WR) }
                do { try writeAll(outgoing, to: descriptor) }
                catch { Issue.record("Write failed: \(error)") }
            }
            group.enter()
            DispatchQueue.global().async {
                defer { group.leave() }
                do { #expect(try readThroughEOF(descriptor) == incoming) }
                catch { Issue.record("Read failed: \(error)") }
            }
        }
        #expect(group.wait(timeout: .now() + 5) == .success)
    }

    @Test("Write failure shuts down the other direction without leaking the slot")
    func writeFailureAbortsBothPumps() throws {
        let fixture = try RelayFixture()
        var jobs: [@Sendable () -> Void] = []
        fixture.relay.start { jobs.append($0) }
        fixture.closeGuestPeer()
        try writeAll([42], to: fixture.clientPeer)
        jobs[0]()
        #expect(fixture.guest.closeCount == 0)
        jobs[1]()
        #expect(fixture.guest.closeCount == 1)
        #expect(fixture.limiter.acquire())
        fixture.limiter.release()
    }

    @Test("First EOF retains both descriptors and admission until the delayed pump finishes")
    func delayedPumpRetainsOwnership() throws {
        let fixture = try RelayFixture()
        var jobs: [@Sendable () -> Void] = []
        fixture.relay.start { jobs.append($0) }
        try #require(jobs.count == 2)
        #expect(shutdown(fixture.clientPeer, SHUT_WR) == 0)
        jobs[0]()
        #expect(fcntl(fixture.client.descriptor, F_GETFD) >= 0)
        #expect(fcntl(fixture.guest.fileDescriptor, F_GETFD) >= 0)
        let prematurelyAvailable = fixture.limiter.acquire()
        #expect(!prematurelyAvailable)
        if prematurelyAvailable { fixture.limiter.release() }
        #expect(fixture.guest.closeCount == 0)
        shutdown(fixture.guestPeer, SHUT_WR)
        jobs[1]()
        #expect(fixture.guest.closeCount == 1)
        #expect(fixture.limiter.acquire())
        #expect(!fixture.limiter.acquire())
        fixture.limiter.release()
    }

    @Test("A response sent after request EOF is relayed without truncation")
    func halfClosePreservesResponse() throws {
        let fixture = try RelayFixture()
        var jobs: [@Sendable () -> Void] = []
        fixture.relay.start { jobs.append($0) }
        let request = Array("request".utf8)
        #expect(request.withUnsafeBytes { Darwin.write(fixture.clientPeer, $0.baseAddress!, $0.count) } == request.count)
        shutdown(fixture.clientPeer, SHUT_WR)
        jobs[0]()
        #expect(try readThroughEOF(fixture.guestPeer) == request)
        let response = Array("late response".utf8)
        let sent = response.withUnsafeBytes { Darwin.write(fixture.guestPeer, $0.baseAddress!, $0.count) }
        shutdown(fixture.guestPeer, SHUT_WR)
        jobs[1]()
        #expect(sent == response.count)
        #expect(try readThroughEOF(fixture.clientPeer) == response)
    }
}

private func writeAll(_ bytes: [UInt8], to descriptor: Int32) throws {
    var offset = 0
    while offset < bytes.count {
        let count = bytes.withUnsafeBytes {
            Darwin.write(descriptor, $0.baseAddress!.advanced(by: offset), bytes.count - offset)
        }
        if count < 0 && errno == EINTR { continue }
        try #require(count > 0)
        offset += count
    }
}

private func readThroughEOF(_ descriptor: Int32) throws -> [UInt8] {
    var result: [UInt8] = []
    var buffer = [UInt8](repeating: 0, count: 4096)
    while true {
        var ready = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
        try #require(poll(&ready, 1, 2000) > 0, "Timed out waiting for relay EOF")
        let count = Darwin.read(descriptor, &buffer, buffer.count)
        try #require(count >= 0)
        if count == 0 { return result }
        result.append(contentsOf: buffer.prefix(count))
    }
}

private final class TestGuestConnection: RelayGuestConnection {
    let fileDescriptor: Int32
    private let lock = NSLock()
    private var closes = 0
    var closeCount: Int { lock.withLock { closes } }
    init(_ descriptor: Int32) { fileDescriptor = descriptor }
    func close() {
        lock.withLock {
            closes += 1
            if closes == 1 { Darwin.close(fileDescriptor) }
        }
    }
}

private final class RelayFixture {
    let limiter = ConnectionLimiter(maximum: 1)
    let client: RelayConnection
    let guest: TestGuestConnection
    let clientPeer: Int32
    private(set) var guestPeer: Int32
    let relay: SocketRelay

    init(policy: RelayTimeoutPolicy = RelayTimeoutPolicy(),
         now: @escaping @Sendable () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) throws {
        var first = [Int32](repeating: -1, count: 2)
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &first) == 0)
        var second = [Int32](repeating: -1, count: 2)
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &second) == 0)
        for descriptor in first + second {
            var enabled: Int32 = 1
            setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
            var size: Int32 = 4096
            setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
            var deadline = timeval(tv_sec: 2, tv_usec: 0)
            setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &deadline, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &deadline, socklen_t(MemoryLayout<timeval>.size))
        }
        client = try #require(RelayConnection(descriptor: first[0], limiter: limiter))
        guest = TestGuestConnection(second[0])
        clientPeer = first[1]
        guestPeer = second[1]
        relay = SocketRelay(client: client, guestConnection: guest, timeoutPolicy: policy, now: now)
    }

    deinit {
        Darwin.close(clientPeer)
        if guestPeer >= 0 { Darwin.close(guestPeer) }
    }

    func closeGuestPeer() {
        Darwin.close(guestPeer)
        guestPeer = -1
    }
}

private final class RelayTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: TimeInterval = 0
    var now: TimeInterval { lock.withLock { value } }
    func advance(_ seconds: TimeInterval) { lock.withLock { value += seconds } }
}
