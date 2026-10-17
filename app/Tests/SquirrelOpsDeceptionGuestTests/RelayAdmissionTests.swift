import Darwin
import Foundation
import Testing
@testable import SquirrelOpsDeceptionGuest

@Suite("Guest relay admission", .serialized)
@MainActor
struct RelayAdmissionTests {
    @Test("Queued callbacks count toward the connection ceiling before MainActor drains")
    func queuedConnectionsAreBounded() async throws {
        let limiter = ConnectionLimiter(maximum: 2)
        let gate = RelayGate()
        let observed = ConnectionCounter()
        let handler = guestConnectionHandler(limiter: limiter, onConnection: { _, outcome in observed.record(outcome) }) { _, _ in
            await gate.wait()
            return .guestConnected
        }
        var peers: [Int32] = []
        var admitted: [Int32] = []
        defer { peers.forEach { Darwin.close($0) } }
        // No suspension: the MainActor cannot process any queued acceptance yet.
        for _ in 0..<3 {
            var pair = [Int32](repeating: -1, count: 2)
            #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
            peers.append(pair[1])
            admitted.append(pair[0])
            handler(pair[0], PeerEndpoint(address: "127.0.0.1", port: 12345))
        }
        #expect(fcntl(admitted[0], F_GETFD) >= 0)
        #expect(fcntl(admitted[1], F_GETFD) >= 0)
        #expect(peerIsClosed(peers[2]))
        #expect(observed.outcomes == [.capacityRejected])
        let extraSlot = limiter.acquire()
        #expect(!extraSlot)
        if extraSlot { limiter.release() }
        await gate.release()
        for _ in 0..<100 {
            if peerIsClosed(peers[0]) && peerIsClosed(peers[1]) { break }
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(observed.outcomes.filter { $0 == .guestConnected }.count == 2)
        #expect(observed.outcomes.count == 3)
        #expect(limiter.acquire())
        #expect(limiter.acquire())
        #expect(!limiter.acquire())
        limiter.release()
        limiter.release()
    }

    @Test("Closing twice cannot release another connection's allowance or descriptor")
    func closeIsIdempotent() throws {
        let limiter = ConnectionLimiter(maximum: 1)
        var original = [Int32](repeating: -1, count: 2)
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &original) == 0)
        defer { Darwin.close(original[1]) }
        let connection = try #require(RelayConnection(descriptor: original[0], limiter: limiter))
        connection.close()

        var replacement = [Int32](repeating: -1, count: 2)
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &replacement) == 0)
        defer { Darwin.close(replacement[1]) }
        let next = try #require(RelayConnection(descriptor: replacement[0], limiter: limiter))
        defer { next.close() }
        connection.close()
        #expect(fcntl(next.descriptor, F_GETFD) >= 0)
        #expect(!limiter.acquire())
        var byte: UInt8 = 0x42
        #expect(Darwin.write(replacement[1], &byte, 1) == 1)
        var received: UInt8 = 0
        #expect(Darwin.read(next.descriptor, &received, 1) == 1)
        #expect(received == byte)
    }

    @Test("Early receiver exit releases the descriptor and allowance")
    func missingReceiverReleasesConnection() async throws {
        let limiter = ConnectionLimiter(maximum: 1)
        let observed = ConnectionCounter()
        let handler = guestConnectionHandler(limiter: limiter, onConnection: { _, outcome in observed.record(outcome) }) { _, _ in .guestConnectFailed }
        var pair = [Int32](repeating: -1, count: 2)
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
        defer { Darwin.close(pair[1]) }
        handler(pair[0], PeerEndpoint(address: "127.0.0.1", port: 12345))
        for _ in 0..<100 {
            if peerIsClosed(pair[1]) { break }
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(peerIsClosed(pair[1]))
        #expect(observed.outcomes == [.guestConnectFailed])
        #expect(limiter.acquire())
        #expect(!limiter.acquire())
        limiter.release()
    }

    @Test("Runtime cannot acquire a slot before a failing socket-device guard")
    func noLeakingCompoundGuard() throws {
        let app = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(contentsOf: app.appendingPathComponent(
            "Sources/SquirrelOpsDeceptionGuest/VirtualMachineRuntime.swift"), encoding: .utf8)
        #expect(!source.contains("guard limiter.acquire(), let socketDevice"))
        #expect(source.contains("let handler = guestConnectionHandler("))
        #expect(source.contains("TCPListener(bindAddress: bindAddress,"))
        #expect(source.contains("diagnostic: diagnostics.service(service.advertisedPort), handler: handler)"))
    }
}

// Observe the peer we still own, not a closed descriptor number that another
// concurrent suite (or the runtime) may already have reused.
private func peerIsClosed(_ descriptor: Int32) -> Bool {
    var readiness = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
    guard poll(&readiness, 1, 0) > 0 else { return false }
    var byte: UInt8 = 0
    return recv(descriptor, &byte, 1, MSG_PEEK | MSG_DONTWAIT) == 0
}

private final class ConnectionCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value: [RelayOutcome] = []
    var outcomes: [RelayOutcome] {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
    func record(_ outcome: RelayOutcome) {
        lock.lock()
        value.append(outcome)
        lock.unlock()
    }
}

private actor RelayGate {
    private var released = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func wait() async {
        if released { return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func release() {
        released = true
        waiters.forEach { $0.resume() }
        waiters.removeAll()
    }
}
