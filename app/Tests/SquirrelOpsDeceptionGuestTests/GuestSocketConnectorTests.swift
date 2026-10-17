import Darwin
import Foundation
import Testing
@testable import SquirrelOpsDeceptionGuest

@Suite("Guest connection deadline")
@MainActor
struct GuestSocketConnectorTests {
    @Test("A missing callback expires all pending work and refuses new connects")
    func missingCallback() async throws {
        let connector = GuestSocketConnector(timeout: .milliseconds(20))
        var callbacks: [@Sendable (Result<GuestSocketTransfer, any Error>) -> Void] = []
        let first = Task { (try? await connector.connect { callbacks.append($0) }) != nil }
        let second = Task { (try? await connector.connect { callbacks.append($0) }) != nil }
        for _ in 0..<100 where connector.pendingCount < 2 { await Task.yield() }
        #expect(connector.pendingCount == 2)
        try await Task.sleep(for: .milliseconds(100))
        #expect(connector.isUnavailable)
        #expect(connector.pendingCount == 0)
        connector.invalidate() // Ensure bounded cleanup against the unfixed implementation.
        #expect(await first.value == false)
        #expect(await second.value == false)
        do {
            _ = try await connector.connect { _ in Issue.record("Poisoned connector restarted work") }
            Issue.record("Poisoned connector returned a connection")
        } catch {}
        let late = ConnectorTestConnection()
        callbacks[0](.success(GuestSocketTransfer(value: late)))
        for _ in 0..<100 where late.closes == 0 { await Task.yield() }
        #expect(late.closes == 1)
    }

    @Test("Successful connection cancels its deadline and transfers ownership once")
    func success() async throws {
        let connector = GuestSocketConnector(timeout: .milliseconds(20))
        let connection = ConnectorTestConnection()
        let received = try await connector.connect { callback in
            callback(.success(GuestSocketTransfer(value: connection)))
        }
        #expect(received === connection)
        try await Task.sleep(for: .milliseconds(50))
        #expect(!connector.isUnavailable)
        #expect(connector.pendingCount == 0)
        #expect(connection.closes == 0)
        received.close()
    }
}

private final class ConnectorTestConnection: RelayGuestConnection, @unchecked Sendable {
    let fileDescriptor: Int32 = -1
    private let lock = NSLock()
    private var count = 0
    var closes: Int { lock.withLock { count } }
    func close() { lock.withLock { count += 1 } }
}
