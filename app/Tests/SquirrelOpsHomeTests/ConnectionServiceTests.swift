import Foundation
import Testing

@testable import SquirrelOpsHome

// MARK: - Mock SensorClient

final class MockSensorClient: SensorClientProtocol, @unchecked Sendable {
    private let lock = NSLock()

    private var _requestedEndpoints: [String] = []
    var requestedEndpoints: [String] {
        lock.withLock { _requestedEndpoints }
    }

    private var _shouldFail = false
    var shouldFail: Bool {
        get { lock.withLock { _shouldFail } }
        set { lock.withLock { _shouldFail = newValue } }
    }

    /// Per-endpoint error overrides. Key is the endpoint path (e.g. "/system/status").
    private var _endpointErrors: [String: SensorClientError] = [:]
    func setError(_ error: SensorClientError, for path: String) {
        lock.withLock { _endpointErrors[path] = error }
    }

    func request<T: Decodable>(_ endpoint: Endpoint) async throws -> T {
        lock.withLock { _requestedEndpoints.append(endpoint.path) }

        if let error = lock.withLock({ _endpointErrors[endpoint.path] }) {
            throw error
        }
        if lock.withLock({ _shouldFail }) {
            throw SensorClientError.connectionFailed("Mock connection failure")
        }

        if T.self == HealthResponse.self {
            return HealthResponse(version: "0.1.0", sensorId: "test-sensor", uptimeSeconds: 100.0) as! T
        }
        if T.self == StatusResponse.self {
            return StatusResponse(
                profile: "standard", learningMode: false,
                deviceCount: 5, decoyCount: 2, alertCount: 3
            ) as! T
        }
        if T.self == PaginatedDevices.self {
            return PaginatedDevices(items: [], total: 0, limit: 50, offset: 0) as! T
        }
        if T.self == PaginatedAlerts.self {
            return PaginatedAlerts(items: [], total: 0, limit: 50, offset: 0) as! T
        }
        if T.self == DecoyListResponse.self {
            return DecoyListResponse(items: []) as! T
        }
        if T.self == LearningStatusResponse.self {
            return LearningStatusResponse(enabled: false, hoursElapsed: 48, hoursTotal: 48, phase: "complete") as! T
        }
        throw SensorClientError.decodingFailed
    }

    func request(_ endpoint: Endpoint) async throws {
        lock.withLock { _requestedEndpoints.append(endpoint.path) }
        if lock.withLock({ _shouldFail }) {
            throw SensorClientError.connectionFailed("Mock connection failure")
        }
    }
}

// MARK: - Mock WebSocketManager

final class MockWSManager: WebSocketManagerProtocol, @unchecked Sendable {
    private let lock = NSLock()

    private var _isConnected = false
    var isConnected: Bool { lock.withLock { _isConnected } }

    private var _lastSeq = 0
    var lastSeq: Int { lock.withLock { _lastSeq } }

    private var _authSent = false
    var authSent: Bool { lock.withLock { _authSent } }

    private var _replaySent = false
    var replaySent: Bool { lock.withLock { _replaySent } }

    var framesToDeliver: [WSFrame] = []

    func connect() { lock.withLock { _isConnected = true } }
    func disconnect() { lock.withLock { _isConnected = false } }

    func sendAuth(certFingerprint: String?, token: String?) async throws {
        lock.withLock { _authSent = true }
    }

    func requestReplay(sinceSeq: Int) async throws {
        lock.withLock { _replaySent = true }
    }

    func receiveMessages() -> AsyncStream<WSFrame> {
        let frames = framesToDeliver
        return AsyncStream { continuation in
            for frame in frames { continuation.yield(frame) }
            continuation.finish()
        }
    }
}

// MARK: - Tests

@Suite("Sensor Connection Service")
struct ConnectionServiceTests {

    @Test("Initial state is disconnected")
    func initialStateIsDisconnected() {
        let service = SensorConnectionService(
            sensorClient: MockSensorClient(),
            webSocketManager: MockWSManager(),
            onEvent: { _ in }
        )
        #expect(service.state == .disconnected)
        #expect(service.lastError == nil)
    }

    @Test("Connect transitions to live state")
    func connectTransitionsToLive() async throws {
        let client = MockSensorClient()
        let wsManager = MockWSManager()
        wsManager.framesToDeliver = [.replayComplete(lastSeq: 0)]

        let service = SensorConnectionService(
            sensorClient: client,
            webSocketManager: wsManager,
            onEvent: { _ in }
        )

        await service.connect(
            baseURL: URL(string: "https://192.168.1.50:8443")!,
            certFingerprint: "sha256:test"
        )

        #expect(service.state == .live)
        #expect(client.requestedEndpoints.contains("/system/health"))
        #expect(client.requestedEndpoints.contains("/system/status"))
        #expect(client.requestedEndpoints.contains("/devices"))
        #expect(client.requestedEndpoints.contains("/alerts"))
        #expect(client.requestedEndpoints.contains("/decoys"))
        #expect(wsManager.authSent == true)
        #expect(wsManager.replaySent == true)
    }

    @Test("Failed health check sets state to disconnected with error")
    func failedHealthCheckSetsError() async {
        let client = MockSensorClient()
        client.shouldFail = true
        let wsManager = MockWSManager()

        let service = SensorConnectionService(
            sensorClient: client,
            webSocketManager: wsManager,
            onEvent: { _ in }
        )

        await service.connect(
            baseURL: URL(string: "https://192.168.1.50:8443")!,
            certFingerprint: "sha256:test"
        )

        #expect(service.state == .disconnected)
        #expect(service.lastError != nil)
    }

    @Test("enqueueAction adds to queue when disconnected")
    func enqueueActionAddsToQueue() {
        let service = SensorConnectionService(
            sensorClient: MockSensorClient(),
            webSocketManager: MockWSManager(),
            onEvent: { _ in }
        )

        service.enqueueAction(.approveDevice(id: 1))
        service.enqueueAction(.readAlert(id: 5))

        #expect(service.actionQueue.count == 2)
    }

    @Test("replayQueuedActions sends all queued endpoints and clears queue")
    func replayQueuedActionsSendsAll() async throws {
        let client = MockSensorClient()
        let service = SensorConnectionService(
            sensorClient: client,
            webSocketManager: MockWSManager(),
            onEvent: { _ in }
        )

        service.enqueueAction(.approveDevice(id: 1))
        service.enqueueAction(.readAlert(id: 5))

        await service.replayQueuedActions()

        #expect(client.requestedEndpoints.contains("/devices/1/approve"))
        #expect(client.requestedEndpoints.contains("/alerts/5/read"))
        #expect(service.actionQueue.isEmpty == true)
    }

    @Test("Disconnect sets state to disconnected")
    func disconnectSetsState() async {
        let client = MockSensorClient()
        let wsManager = MockWSManager()
        wsManager.framesToDeliver = [.replayComplete(lastSeq: 0)]

        let service = SensorConnectionService(
            sensorClient: client,
            webSocketManager: wsManager,
            onEvent: { _ in }
        )

        await service.connect(
            baseURL: URL(string: "https://192.168.1.50:8443")!,
            certFingerprint: "sha256:test"
        )
        #expect(service.state == .live)

        service.disconnect()
        #expect(service.state == .disconnected)
    }

    @Test("Connect populates AppState with sync data")
    @MainActor
    func connectPopulatesAppState() async {
        let client = MockSensorClient()
        let wsManager = MockWSManager()
        wsManager.framesToDeliver = [.replayComplete(lastSeq: 0)]
        let appState = AppState()

        let service = SensorConnectionService(
            sensorClient: client,
            webSocketManager: wsManager,
            appState: appState,
            onEvent: { _ in }
        )

        await service.connect(
            baseURL: URL(string: "https://192.168.1.50:8443")!,
            certFingerprint: "sha256:test"
        )

        #expect(appState.sensorInfo != nil)
        #expect(appState.systemStatus != nil)
        #expect(appState.connectionState == .live)
    }

    @Test("Disconnect updates AppState connectionState")
    @MainActor
    func disconnectUpdatesAppState() async {
        let client = MockSensorClient()
        let wsManager = MockWSManager()
        wsManager.framesToDeliver = [.replayComplete(lastSeq: 0)]
        let appState = AppState()

        let service = SensorConnectionService(
            sensorClient: client,
            webSocketManager: wsManager,
            appState: appState,
            onEvent: { _ in }
        )

        await service.connect(
            baseURL: URL(string: "https://192.168.1.50:8443")!,
            certFingerprint: "sha256:test"
        )
        #expect(appState.connectionState == .live)

        service.disconnect()
        await Task.yield()
        #expect(appState.connectionState == .disconnected)
    }

    @Test("403 on status transitions to authFailed, not disconnected")
    @MainActor
    func authFailedOn403() async {
        let client = MockSensorClient()
        client.setError(.badResponse(statusCode: 403), for: "/system/status")
        let wsManager = MockWSManager()
        let appState = AppState()

        let service = SensorConnectionService(
            sensorClient: client,
            webSocketManager: wsManager,
            appState: appState,
            onEvent: { _ in }
        )

        await service.connect(
            baseURL: URL(string: "https://192.168.1.50:8443")!,
            certFingerprint: "sha256:test"
        )

        #expect(service.state == .authFailed)
        #expect(appState.connectionState == .authFailed)
        #expect(service.lastError == "Pairing credentials rejected by sensor")
        // WebSocket should NOT have been set up
        #expect(wsManager.authSent == false)
    }

    @Test("Connect fetches learning status during sync")
    func connectFetchesLearning() async throws {
        let client = MockSensorClient()
        let wsManager = MockWSManager()
        wsManager.framesToDeliver = [.replayComplete(lastSeq: 0)]

        let service = SensorConnectionService(
            sensorClient: client,
            webSocketManager: wsManager,
            onEvent: { _ in }
        )

        await service.connect(
            baseURL: URL(string: "https://192.168.1.50:8443")!,
            certFingerprint: "sha256:test"
        )

        #expect(client.requestedEndpoints.contains("/system/learning"))
    }

    @Test("Connect populates AppState learningStatus")
    @MainActor
    func connectPopulatesLearningStatus() async {
        let client = MockSensorClient()
        let wsManager = MockWSManager()
        wsManager.framesToDeliver = [.replayComplete(lastSeq: 0)]
        let appState = AppState()

        let service = SensorConnectionService(
            sensorClient: client,
            webSocketManager: wsManager,
            appState: appState,
            onEvent: { _ in }
        )

        await service.connect(
            baseURL: URL(string: "https://192.168.1.50:8443")!,
            certFingerprint: "sha256:test"
        )

        #expect(appState.learningStatus != nil)
    }
}

@Suite("DisconnectAlert")
struct DisconnectAlertTests {

    @Test("Synthetic disconnect alert has correct properties")
    @MainActor
    func syntheticAlertProperties() {
        let alert = SensorConnectionService.makeDisconnectAlert()
        #expect(alert.severity == "medium")
        #expect(alert.alertType == "system.sensor_offline")
        #expect(alert.title == "Sensor Disconnected")
        #expect(alert.id < 0)
        #expect(alert.readAt == nil)
    }

    @Test("Synthetic disconnect alerts have unique IDs")
    @MainActor
    func syntheticAlertUniqueIds() {
        let alert1 = SensorConnectionService.makeDisconnectAlert()
        let alert2 = SensorConnectionService.makeDisconnectAlert()
        #expect(alert1.id != alert2.id)
    }
}
