import Foundation
import Testing
@testable import SquirrelOpsHome

@Suite("App connection ownership")
@MainActor
struct ConnectionOwnershipTests {
    private func sensor(_ id: Int = 1) -> PairingManager.PairedSensor {
        .init(id: id, name: "Synthetic sensor",
              baseURL: URL(string: "https://192.0.2.\(id):8443")!,
              certFingerprint: "sha256:synthetic-\(id)")
    }

    @Test("Window reopening reuses one connection service")
    func reopeningReusesConnection() throws {
        let owner = SensorConnectionOwner()
        defer { owner.disconnect() }
        var factories = 0
        let factory = {
            factories += 1
            return SensorConnectionService(sensorClient: MockSensorClient(),
                webSocketManager: MockWSManager(), onEvent: { _ in })
        }
        owner.connect(to: sensor(), makeService: factory)
        owner.connect(to: sensor(), makeService: factory)
        #expect(factories == 1)
    }

    @Test("Replacing credentials disconnects the previous live WebSocket first")
    func replacingDisconnectsOldService() async throws {
        let owner = SensorConnectionOwner()
        defer { owner.disconnect() }
        let ws = MockWSManager()
        let service = SensorConnectionService(sensorClient: MockSensorClient(),
            webSocketManager: ws, onEvent: { _ in })
        owner.connect(to: sensor()) { service }
        for _ in 0..<100 where !ws.isConnected {
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(ws.isConnected)
        owner.connect(to: sensor(2)) {
            #expect(!ws.isConnected)
            return SensorConnectionService(sensorClient: MockSensorClient(),
                webSocketManager: MockWSManager(), onEvent: { _ in })
        }
        #expect(!ws.isConnected)
        service.disconnect() // clean up even when the unfixed behavior fails
    }

    @Test("Dashboard requests cannot force-unwrap missing credentials")
    func noForceUnwrappedClients() throws {
        let app = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        for file in ["DecoyStatusView.swift", "AlertFeedView.swift",
                     "DeviceDetailView.swift", "SettingsView.swift"] {
            let source = try String(contentsOf: app.appendingPathComponent(
                "Sources/SquirrelOpsHome/Views/Dashboard/\(file)"), encoding: .utf8)
            #expect(!source.contains("sensorClient!"), "Unchecked client in \(file)")
        }
    }

    @Test("Missing credentials preserve repair state and throw a normal request error")
    func unavailableCredentials() async throws {
        let state = AppState()
        state.pairedSensor = sensor()
        state.connectionState = .authFailed
        #expect(state.isPaired)
        #expect(throws: SensorClientError.self) { try state.requireSensorClient() }
        let client = MockSensorClient()
        state.sensorClient = client
        let _: HealthResponse = try await state.requireSensorClient().request(.health)
        #expect(client.requestedEndpoints == ["/system/health"])
        state.sensorClient = nil
        #expect(throws: SensorClientError.self) { try state.requireSensorClient() }
    }

    @Test("A cancelled startup cannot open a WebSocket after disconnect")
    func cancelledStartupCannotRevive() async throws {
        let owner = SensorConnectionOwner()
        defer { owner.disconnect() }
        let gate = SuspendedHealthGate()
        let ws = MockWSManager()
        let service = SensorConnectionService(sensorClient: SuspendedHealthClient(gate: gate),
            webSocketManager: ws, onEvent: { _ in })
        owner.connect(to: sensor()) { service }
        for _ in 0..<100 {
            if await gate.entered { break }
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(await gate.entered)
        owner.disconnect()
        await gate.release()
        try await Task.sleep(for: .milliseconds(50))
        #expect(!ws.isConnected)
        #expect(service.state == .disconnected)
        service.disconnect()
    }

    @Test("Discarding an owned WebSocket manager invalidates its URLSession")
    func invalidatesOwnedSession() async throws {
        let delegate = SessionInvalidationProbe()
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var manager: WebSocketManager? = WebSocketManager(
            url: URL(string: "wss://192.0.2.1/ws")!, session: session)
        #expect(manager != nil)
        manager = nil
        for _ in 0..<100 where !delegate.invalidated {
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(delegate.invalidated)
    }

    @Test("An empty device page ends startup pagination even when its total is stale")
    func emptyPageCannotStallStartup() async throws {
        let client = EmptyDevicePageClient()
        let ws = MockWSManager()
        let service = SensorConnectionService(sensorClient: client,
            webSocketManager: ws, onEvent: { _ in })
        defer { service.disconnect() }
        await service.connect(baseURL: sensor().baseURL, certFingerprint: "synthetic")
        #expect(client.pageReads == 1)
        #expect(service.state == .live)
        #expect(ws.isConnected)
    }
}

private final class EmptyDevicePageClient: SensorClientProtocol, @unchecked Sendable {
    private let fallback = MockSensorClient()
    private let lock = NSLock()
    private var reads = 0
    var pageReads: Int { lock.withLock { reads } }
    func request<T: Decodable>(_ endpoint: Endpoint) async throws -> T {
        if T.self == PaginatedDevices.self {
            let count = lock.withLock { reads += 1; return reads }
            // Bound the unfixed loop rather than hanging the entire test suite.
            if count > 1 { throw SensorClientError.decodingFailed }
            return PaginatedDevices(items: [], total: 1, limit: 50, offset: 0) as! T
        }
        return try await fallback.request(endpoint)
    }
    func request(_ endpoint: Endpoint) async throws { try await fallback.request(endpoint) }
}

private actor SuspendedHealthGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private(set) var entered = false
    func wait() async {
        entered = true
        await withCheckedContinuation { continuation = $0 }
    }
    func release() { continuation?.resume(); continuation = nil }
}

private final class SuspendedHealthClient: SensorClientProtocol {
    let gate: SuspendedHealthGate
    let base = MockSensorClient()
    init(gate: SuspendedHealthGate) { self.gate = gate }
    func request<T: Decodable>(_ endpoint: Endpoint) async throws -> T {
        if endpoint.path == "/system/health" { await gate.wait() }
        return try await base.request(endpoint)
    }
    func request(_ endpoint: Endpoint) async throws { try await base.request(endpoint) }
}

private final class SessionInvalidationProbe: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var didInvalidate = false
    var invalidated: Bool { lock.withLock { didInvalidate } }
    func urlSession(_ session: URLSession, didBecomeInvalidWithError error: (any Error)?) {
        lock.withLock { didInvalidate = true }
    }
}
