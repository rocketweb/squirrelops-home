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

    private var _statusEventSeq = 0
    var statusEventSeq: Int {
        get { lock.withLock { _statusEventSeq } }
        set { lock.withLock { _statusEventSeq = newValue } }
    }

    private var _statusAPIProtocolVersion: Int? = 2
    var statusAPIProtocolVersion: Int? {
        get { lock.withLock { _statusAPIProtocolVersion } }
        set { lock.withLock { _statusAPIProtocolVersion = newValue } }
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
            return HealthResponse(sensorId: "test-sensor", uptimeSeconds: 100.0) as! T
        }
        if T.self == StatusResponse.self {
            let eventSeq = statusEventSeq
            let protocolField = statusAPIProtocolVersion.map {
                "\"api_protocol_version\": \($0),"
            } ?? ""
            let data = Data(
                """
                {
                  "version": "1.1.4",
                  \(protocolField)
                  "profile": "standard",
                  "learning_mode": false,
                  "device_count": 5,
                  "decoy_count": 2,
                  "alert_count": 3,
                  "event_seq": \(eventSeq)
                }
                """.utf8
            )
            return try JSONDecoder().decode(StatusResponse.self, from: data) as! T
        }
        if T.self == ResourceProfileResponse.self {
            return ResourceProfileResponse(
                profile: "standard",
                scanIntervalSeconds: 300,
                maxDecoys: 8,
                llmClassification: "cloud_llm",
                scoutIntervalMinutes: 60,
                maxMimicDecoys: 10,
                maxVirtualIPs: 10,
                totalDecoyCapacity: 18
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

    private var _requestedReplaySeq: Int?
    var requestedReplaySeq: Int? { lock.withLock { _requestedReplaySeq } }

    var framesToDeliver: [WSFrame] = []

    func connect() { lock.withLock { _isConnected = true } }
    func disconnect() { lock.withLock { _isConnected = false } }

    func sendAuth(certFingerprint: String?, token: String?) async throws {
        lock.withLock { _authSent = true }
    }

    func requestReplay(sinceSeq: Int) async throws {
        lock.withLock {
            _replaySent = true
            _requestedReplaySeq = sinceSeq
        }
    }

    func receiveMessages() -> AsyncStream<WSFrame> {
        let frames = framesToDeliver
        return AsyncStream { continuation in
            for frame in frames { continuation.yield(frame) }
            // A live WebSocket remains open after replay completes. Individual
            // tests disconnect the service, which cancels the consumer task.
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
        defer { service.disconnect() }

        await service.connect(
            baseURL: URL(string: "https://192.168.1.50:8443")!,
            certFingerprint: "sha256:test"
        )

        #expect(service.state == .live)
        #expect(client.requestedEndpoints.contains("/system/health"))
        #expect(client.requestedEndpoints.contains("/system/status"))
        #expect(client.requestedEndpoints.contains("/system/profile"))
        #expect(client.requestedEndpoints.contains("/devices"))
        #expect(client.requestedEndpoints.contains("/alerts"))
        #expect(client.requestedEndpoints.contains("/decoys"))
        #expect(wsManager.authSent == true)
        #expect(wsManager.replaySent == true)
    }

    @Test("Protocol mismatch is terminal and never starts WebSocket")
    func protocolMismatchIsRejected() async {
        let client = MockSensorClient()
        client.statusAPIProtocolVersion = 1
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

        #expect(service.state == .incompatible)
        #expect(service.lastError?.contains("protocol 1") == true)
        #expect(wsManager.isConnected == false)
    }

    @Test("Missing protocol contract is rejected as a pre-2 sensor")
    func missingProtocolIsRejected() async {
        let client = MockSensorClient()
        client.statusAPIProtocolVersion = nil
        let service = SensorConnectionService(
            sensorClient: client,
            webSocketManager: MockWSManager(),
            onEvent: { _ in }
        )

        await service.connect(
            baseURL: URL(string: "https://192.168.1.50:8443")!,
            certFingerprint: "sha256:test"
        )

        #expect(service.state == .incompatible)
        #expect(service.lastError?.contains("predates") == true)
    }

    @Test("Initial REST snapshot replays only events after its server cursor")
    func initialSnapshotUsesServerEventCursor() async {
        let client = MockSensorClient()
        client.statusEventSeq = 9_876
        let wsManager = MockWSManager()
        wsManager.framesToDeliver = [.replayComplete(lastSeq: 9_876)]
        let service = SensorConnectionService(
            sensorClient: client,
            webSocketManager: wsManager,
            onEvent: { _ in }
        )
        defer { service.disconnect() }

        await service.connect(
            baseURL: URL(string: "https://192.168.1.50:8443")!,
            certFingerprint: "sha256:test"
        )

        #expect(wsManager.requestedReplaySeq == 9_876)
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

    @Test("Failed health check with reachable local sensor requires re-pair")
    @MainActor
    func failedHealthCheckWithLocalSensorRequiresRepair() async {
        let client = MockSensorClient()
        client.shouldFail = true
        let appState = AppState()
        let service = SensorConnectionService(
            sensorClient: client,
            webSocketManager: MockWSManager(),
            appState: appState,
            localSensorProbe: { true },
            onEvent: { _ in }
        )

        await service.connect(
            baseURL: URL(string: "https://10.0.0.1:8443")!,
            certFingerprint: "sha256:stale"
        )

        #expect(service.state == .authFailed)
        #expect(appState.connectionState == .authFailed)
        #expect(service.lastError == "Stored pairing does not match the local sensor")
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
        defer { service.disconnect() }

        await service.connect(
            baseURL: URL(string: "https://192.168.1.50:8443")!,
            certFingerprint: "sha256:test"
        )

        #expect(appState.sensorInfo != nil)
        #expect(appState.sensorInfo?.version == "1.1.4")
        #expect(appState.systemStatus != nil)
        #expect(appState.resourceProfile?.totalDecoyCapacity == 18)
        #expect(appState.connectionState == .live)
    }

    @Test("Alert collection failure does not hide version or disconnect")
    @MainActor
    func alertCollectionFailureKeepsAuthenticatedStatus() async {
        let client = MockSensorClient()
        client.setError(
            .connectionFailed("history is slow"),
            for: "/alerts"
        )
        let wsManager = MockWSManager()
        wsManager.framesToDeliver = [.replayComplete(lastSeq: 0)]
        let appState = AppState()
        let service = SensorConnectionService(
            sensorClient: client,
            webSocketManager: wsManager,
            appState: appState,
            onEvent: { _ in }
        )
        defer { service.disconnect() }

        await service.connect(
            baseURL: URL(string: "https://192.168.1.50:8443")!,
            certFingerprint: "sha256:test"
        )

        #expect(service.state == .live)
        #expect(appState.sensorInfo?.version == "1.1.4")
        #expect(appState.systemStatus?.deviceCount == 5)
        #expect(appState.alerts.isEmpty)
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
        defer { service.disconnect() }

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
        defer { service.disconnect() }

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
