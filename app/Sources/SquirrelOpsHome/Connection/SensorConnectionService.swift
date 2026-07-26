import Foundation

// MARK: - Protocol Abstractions

/// Protocol for SensorClient functionality needed by SensorConnectionService.
public protocol SensorClientProtocol: Sendable {
    func request<T: Decodable>(_ endpoint: Endpoint) async throws -> T
    func request(_ endpoint: Endpoint) async throws
}

extension SensorClient: SensorClientProtocol {}

/// Protocol for WebSocketManager functionality needed by SensorConnectionService.
public protocol WebSocketManagerProtocol: Sendable {
    var isConnected: Bool { get }
    var lastSeq: Int { get }
    func connect()
    func disconnect()
    func sendAuth(certFingerprint: String?, token: String?) async throws
    func requestReplay(sinceSeq: Int) async throws
    func receiveMessages() -> AsyncStream<WSFrame>
}

extension WebSocketManager: WebSocketManagerProtocol {}

// MARK: - SensorConnectionService

/// All public methods must be called from the main actor.
/// Full @MainActor isolation deferred to Phase 3 (protocol conformances cross actor boundaries).
@Observable
public final class SensorConnectionService: @unchecked Sendable {

    // MARK: - Public Properties

    public private(set) var state: ConnectionState = .disconnected
    public var actionQueue: ActionQueue = ActionQueue()
    public private(set) var lastError: String?

    // MARK: - Private Properties

    private let sensorClient: any SensorClientProtocol
    private let webSocketManager: any WebSocketManagerProtocol
    private let appState: AppState?
    private let localSensorProbe: @Sendable () async -> Bool
    private let onEvent: @Sendable (WSFrame) -> Void
    private var reconnectTask: Task<Void, Never>?
    private var listenTask: Task<Void, Never>?
    private var learningPollTask: Task<Void, Never>?
    private var disconnectAlertTask: Task<Void, Never>?
    private var reconnectAttempts: Int = 0
    private var baseURL: URL?
    private var certFingerprint: String?

    // MARK: - Init

    public init(
        sensorClient: any SensorClientProtocol,
        webSocketManager: any WebSocketManagerProtocol,
        appState: AppState? = nil,
        localSensorProbe: @escaping @Sendable () async -> Bool = { false },
        onEvent: @escaping @Sendable (WSFrame) -> Void
    ) {
        self.sensorClient = sensorClient
        self.webSocketManager = webSocketManager
        self.appState = appState
        self.localSensorProbe = localSensorProbe
        self.onEvent = onEvent
    }

    // MARK: - Disconnect Alert

    @MainActor private static var syntheticIdCounter: Int = -1

    /// Creates a synthetic "Sensor Disconnected" alert for local display.
    @MainActor public static func makeDisconnectAlert() -> AlertSummary {
        let id = syntheticIdCounter
        syntheticIdCounter -= 1
        return AlertSummary(
            id: id,
            incidentId: nil,
            alertType: "system.sensor_offline",
            severity: "medium",
            title: "Sensor Disconnected",
            sourceIp: nil,
            readAt: nil,
            actionedAt: nil,
            createdAt: ISO8601DateFormatter().string(from: Date()),
            alertCount: nil
        )
    }

    // MARK: - Connection Lifecycle

    public func connect(baseURL: URL, certFingerprint: String) async {
        self.baseURL = baseURL
        self.certFingerprint = certFingerprint
        lastError = nil

        state = .connecting
        await syncStateAsync()

        // Health check
        let health: HealthResponse
        do {
            health = try await sensorClient.request(.health)
        } catch {
            if await localSensorProbe() {
                state = .authFailed
                lastError = "Stored pairing does not match the local sensor"
                await syncStateAsync()
                return
            }
            state = .disconnected
            lastError = "Health check failed: \(error.localizedDescription)"
            await syncStateAsync()
            scheduleReconnect()
            return
        }
        state = .connected
        await syncStateAsync()

        // Sync initial data
        state = .syncing
        await syncStateAsync()
        let status: StatusResponse
        do {
            status = try await sensorClient.request(.status)
        } catch let error as SensorClientError where error.httpStatusCode == 403 {
            // Sensor is reachable but rejected our credentials — pairing is broken.
            // Don't schedule reconnect; user must re-pair.
            state = .authFailed
            lastError = "Pairing credentials rejected by sensor"
            await syncStateAsync()
            return
        } catch {
            state = .disconnected
            lastError = "Initial sync failed: \(error.localizedDescription)"
            await syncStateAsync()
            scheduleReconnect()
            return
        }
        guard SensorAPICompatibility.supports(status.apiProtocolVersion) else {
            state = .incompatible
            lastError = SensorAPICompatibility.errorMessage(
                for: status.apiProtocolVersion
            )
            await syncStateAsync()
            return
        }

        // Apply authenticated version/status immediately. Bulk collections are
        // independent and must not keep Sensor Version blank (or disconnect the
        // app) when a large alert history is slow or one endpoint is degraded.
        let profile = await optionalRequest(
            .profile,
            as: ResourceProfileResponse.self
        )
        await MainActor.run {
            appState?.sensorInfo = HealthResponse(
                version: status.version ?? health.version,
                sensorId: health.sensorId,
                uptimeSeconds: health.uptimeSeconds
            )
            appState?.updateSystemStatus(status)
            if let profile {
                appState?.applyResourceProfile(profile)
            }
        }

        let learning = await optionalRequest(
            .learning,
            as: LearningStatusResponse.self
        )
        let decoys = await optionalRequest(
            .decoys,
            as: DecoyListResponse.self
        )
        let allDevices: [DeviceSummary]? = try? await fetchAllPages {
            [sensorClient] (offset: Int) -> PaginatedDevices in
            try await sensorClient.request(.devices(limit: 50, offset: offset))
        }
        // The status count communicates complete history. Load a bounded recent
        // page for the dashboard instead of blocking initial sync on thousands
        // of old alerts; export and clear operations still cover every row.
        let recentAlerts = await optionalRequest(
            .alerts(limit: 200, offset: 0),
            as: PaginatedAlerts.self
        )
        await MainActor.run {
            if let decoys {
                appState?.decoys = decoys.items
            }
            if let allDevices {
                appState?.devices = AppState.visibleDevices(
                    allDevices,
                    decoys: appState?.decoys ?? []
                )
            }
            if let recentAlerts {
                appState?.alerts = recentAlerts.items
            }
            if let learning {
                appState?.updateLearningStatus(learning)
            }
        }

        // WebSocket setup
        do {
            webSocketManager.connect()
            try await webSocketManager.sendAuth(certFingerprint: certFingerprint, token: nil)
            // A fresh app process has no in-memory WebSocket cursor. The
            // authenticated REST status response supplies a server high-water
            // mark captured before the collection snapshot, so replay covers
            // only concurrent changes instead of the complete event history.
            let replayCursor = status.eventSeq ?? webSocketManager.lastSeq
            try await webSocketManager.requestReplay(sinceSeq: replayCursor)
        } catch {
            state = .disconnected
            lastError = "WebSocket setup failed: \(error.localizedDescription)"
            await syncStateAsync()
            scheduleReconnect()
            return
        }

        // Go live
        state = .live
        await syncStateAsync()
        disconnectAlertTask?.cancel()
        disconnectAlertTask = nil
        reconnectAttempts = 0
        await replayQueuedActions()

        // Start learning progress polling if in learning mode
        if let learning = await MainActor.run(body: { appState?.learningStatus }),
           learning.enabled {
            startLearningPollIfNeeded()
        }

        listenTask = Task { [weak self] in
            guard let self else { return }
            let stream = self.webSocketManager.receiveMessages()
            for await frame in stream {
                self.onEvent(frame)
            }
            // Stream ended — if we were still live, treat as disconnect
            if self.state == .live {
                self.state = .disconnected
                self.lastError = "WebSocket connection lost"
                self.syncState()
                self.scheduleReconnect()
            }
        }
    }

    public func disconnect() {
        reconnectTask?.cancel()
        reconnectTask = nil
        listenTask?.cancel()
        listenTask = nil
        learningPollTask?.cancel()
        learningPollTask = nil
        disconnectAlertTask?.cancel()
        disconnectAlertTask = nil
        webSocketManager.disconnect()
        state = .disconnected
        lastError = nil
        reconnectAttempts = 0
        syncState()
    }

    // MARK: - Action Queue

    public func enqueueAction(_ endpoint: Endpoint) {
        actionQueue.enqueue(endpoint)
    }

    public func replayQueuedActions() async {
        let endpoints = actionQueue.dequeueAll()
        for endpoint in endpoints {
            try? await sensorClient.request(endpoint)
        }
    }

    // MARK: - Learning Poll

    private func startLearningPollIfNeeded() {
        learningPollTask?.cancel()
        learningPollTask = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(30))
                } catch { return }
                guard let self, self.state == .live else { return }
                do {
                    let learning: LearningStatusResponse = try await self.sensorClient.request(.learning)
                    await MainActor.run {
                        self.appState?.updateLearningStatus(learning)
                    }
                    if !learning.enabled {
                        return // Learning complete, stop polling
                    }
                } catch {
                    // Non-fatal — keep polling
                }
            }
        }
    }

    // MARK: - Pagination

    /// Best-effort collection fetch that still asks the generic client for the
    /// concrete wire model. Writing ``try? request`` directly into an optional
    /// local lets Swift infer ``T == Optional<Model>``, which strict clients
    /// cannot decode and which caused profile/learning/decoy state to vanish
    /// during an otherwise successful sync.
    private func optionalRequest<T: Decodable>(
        _ endpoint: Endpoint,
        as type: T.Type
    ) async -> T? {
        do {
            let value: T = try await sensorClient.request(endpoint)
            return value
        } catch {
            return nil
        }
    }

    private func fetchAllPages<P: PaginatedResponse>(
        fetch: @Sendable (Int) async throws -> P
    ) async throws -> [P.Item] {
        var all: [P.Item] = []
        var offset = 0
        while true {
            let page = try await fetch(offset)
            all.append(contentsOf: page.pageItems)
            if offset + page.pageItems.count >= page.pageTotal {
                break
            }
            offset += page.pageItems.count
        }
        return all
    }

    // MARK: - State Sync

    /// Fire-and-forget variant for synchronous contexts (e.g. disconnect()).
    private func syncState() {
        guard let appState else { return }
        let currentState = state
        Task { @MainActor in
            appState.connectionState = currentState
        }
    }

    /// Awaitable variant for async contexts (e.g. connect()) — guarantees
    /// the MainActor write completes before returning.
    private func syncStateAsync() async {
        guard let appState else { return }
        let currentState = state
        await MainActor.run {
            appState.connectionState = currentState
        }
    }

    // MARK: - Reconnection

    private func scheduleReconnect() {
        guard let baseURL, let certFingerprint else { return }
        let delay = reconnectDelay()
        reconnectAttempts += 1
        reconnectTask = Task { [weak self, baseURL, certFingerprint] in
            do {
                try await Task.sleep(for: .seconds(delay))
            } catch { return }
            guard let self, !Task.isCancelled else { return }
            await self.connect(baseURL: baseURL, certFingerprint: certFingerprint)
        }

        // Start 5-minute alert timer if not already running
        if disconnectAlertTask == nil {
            disconnectAlertTask = Task { [weak self] in
                do {
                    try await Task.sleep(for: .seconds(300))
                } catch { return }
                guard let self, self.state == .disconnected else { return }
                await MainActor.run {
                    let alert = SensorConnectionService.makeDisconnectAlert()
                    self.appState?.addAlert(alert)
                }
            }
        }
    }

    private func reconnectDelay() -> Int {
        30
    }
}
