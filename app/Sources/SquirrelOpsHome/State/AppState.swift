import Foundation

// MARK: - MenuBarStatus

public enum MenuBarStatus: Sendable, Equatable {
    case connected
    case alertsPresent
    case criticalAlert
    case disconnected
}

// MARK: - DashboardSection

public enum DashboardSection: String, CaseIterable, Identifiable, Sendable {
    case dashboard = "Dashboard"
    case devices = "Devices"
    case alerts = "Alerts"
    case decoys = "Decoys"
    case scouts = "Scouts"
    case settings = "Settings"

    public var id: Self { self }
}

// MARK: - AppState

@MainActor
@Observable
public final class AppState {

    public var connectionState: ConnectionState = .disconnected
    public var sensorInfo: HealthResponse?
    public var devices: [DeviceSummary] = []
    public var alerts: [AlertSummary] = [] {
        didSet {
            reconcileReviewedCriticalAlertRevisions()
        }
    }
    public var incidents: [IncidentDetail] = []
    public var decoys: [DecoySummary] = []
    public var systemStatus: StatusResponse?
    public var resourceProfile: ResourceProfileResponse?
    public var learningStatus: LearningStatusResponse?
    public var pairedSensor: PairingManager.PairedSensor?
    public var selectedDashboardSection: DashboardSection? = .dashboard

    /// The active sensor client, set after connection. Views use this for actions.
    public var sensorClient: (any SensorClientProtocol)?

    public var silenceUntil: Date?

    private struct CriticalAlertRevision: Hashable {
        let id: Int
        let createdAt: String
        let severity: String
        let title: String
        let sourceIp: String?
        let issueKey: String?
        let alertCount: Int?
        let deviceCount: Int?

        init(_ alert: AlertSummary) {
            id = alert.id
            createdAt = alert.createdAt
            severity = alert.severity
            title = alert.title
            sourceIp = alert.sourceIp
            issueKey = alert.issueKey
            alertCount = alert.alertCount
            deviceCount = alert.deviceCount
        }
    }

    /// Revisions the user chose to review without dismissing. A grouped alert
    /// that later changes count receives a new revision and can surface again.
    private var reviewedCriticalAlertRevisions: Set<CriticalAlertRevision> = []

    public var isSilenced: Bool {
        guard let until = silenceUntil else { return false }
        return until > Date()
    }

    public var isPaired: Bool { pairedSensor != nil }

    /// Closure called when the user requests re-pairing from the auth-failed banner.
    /// Set by App.swift to wire up credential cleanup and navigation.
    public var onRepairRequested: (() -> Void)?

    /// Called for newly inserted or materially revised live alerts. Initial
    /// REST synchronization intentionally does not call this hook.
    public var onAlertNotificationsRequested: (([AlertSummary]) -> Void)?

    public var menuBarStatus: MenuBarStatus {
        switch connectionState {
        case .live, .connected, .syncing:
            if isSilenced { return .connected }
            if hasCriticalAlert { return .criticalAlert }
            else if hasUnreadAlerts { return .alertsPresent }
            else { return .connected }
        case .disconnected, .connecting, .authFailed, .incompatible:
            return .disconnected
        }
    }

    public var unreadAlertCounts: [String: Int] {
        var counts: [String: Int] = [:]
        for alert in alerts where alert.readAt == nil {
            counts[alert.severity, default: 0] += 1
        }
        return counts
    }

    public var hasUnreadAlerts: Bool {
        alerts.contains { $0.readAt == nil }
    }

    public var hasCriticalAlert: Bool {
        alerts.contains { $0.readAt == nil && ($0.severity == "critical" || $0.severity == "high") }
    }

    public var presentedCriticalAlerts: [AlertSummary] {
        guard !isSilenced else { return [] }
        return alerts.filter { alert in
            alert.readAt == nil
                && (alert.severity == "critical" || alert.severity == "high")
                && !reviewedCriticalAlertRevisions.contains(
                    CriticalAlertRevision(alert)
                )
        }
    }

    public var shouldPresentCriticalAlertModal: Bool {
        !presentedCriticalAlerts.isEmpty
    }

    public var firstCriticalAlert: AlertSummary? {
        presentedCriticalAlerts.first
    }

    public init() {}

    public static func decoyDeviceIPs(in decoys: [DecoySummary]) -> Set<String> {
        Set(decoys.compactMap { decoy in
            guard decoy.decoyType == "mimic", decoy.status == "active" else {
                return nil
            }
            guard !["", "0.0.0.0", "127.0.0.1", "::"].contains(decoy.bindAddress) else {
                return nil
            }
            return decoy.bindAddress
        })
    }

    /// Count deployed network identities, not the per-port rows used to model
    /// each virtual host's services.
    public static func activeDecoyDeploymentCount(
        in decoys: [DecoySummary]
    ) -> Int {
        DecoyDeploymentSummary.active(in: decoys).deploymentCount
    }

    public static func visibleDevices(
        _ devices: [DeviceSummary],
        decoys: [DecoySummary]
    ) -> [DeviceSummary] {
        let decoyIPs = decoyDeviceIPs(in: decoys)
        guard !decoyIPs.isEmpty else { return devices }
        return devices.filter { !decoyIPs.contains($0.ipAddress) }
    }

    // MARK: - Mutation Methods

    public func applySyncData(
        sensorInfo: HealthResponse,
        status: StatusResponse,
        devices: [DeviceSummary],
        alerts: [AlertSummary],
        decoys: DecoyListResponse
    ) {
        self.sensorInfo = HealthResponse(
            version: status.version ?? sensorInfo.version,
            sensorId: sensorInfo.sensorId,
            uptimeSeconds: sensorInfo.uptimeSeconds
        )
        self.systemStatus = status
        self.decoys = decoys.items
        self.devices = Self.visibleDevices(devices, decoys: decoys.items)
        self.alerts = alerts
    }

    public func updateDevice(_ device: DeviceSummary) {
        if Self.decoyDeviceIPs(in: decoys).contains(device.ipAddress) {
            devices.removeAll { $0.id == device.id || $0.ipAddress == device.ipAddress }
            return
        }

        if let index = devices.firstIndex(where: { $0.id == device.id }) {
            devices[index] = device
        } else {
            devices.append(device)
        }
    }

    public func setDeviceOnline(_ deviceId: Int, online: Bool) {
        if let index = devices.firstIndex(where: { $0.id == deviceId }) {
            var items = devices
            let old = items[index]
            items[index] = DeviceSummary(
                id: old.id, ipAddress: old.ipAddress, macAddress: old.macAddress,
                hostname: old.hostname, vendor: old.vendor, deviceType: old.deviceType,
                modelName: old.modelName, area: old.area, customName: old.customName,
                trustStatus: old.trustStatus,
                isOnline: online, firstSeen: old.firstSeen, lastSeen: old.lastSeen
            )
            devices = items
        }
    }

    public func addAlert(_ alert: AlertSummary) {
        alerts.insert(alert, at: 0)
    }

    private static let iso8601 = ISO8601DateFormatter()

    public func markAlertRead(_ alertId: Int) {
        if let index = alerts.firstIndex(where: { $0.id == alertId }) {
            let old = alerts[index]
            alerts[index] = AlertSummary(
                id: old.id, incidentId: old.incidentId, alertType: old.alertType,
                severity: old.severity, title: old.title, sourceIp: old.sourceIp,
                readAt: AppState.iso8601.string(from: Date()),
                actionedAt: old.actionedAt, createdAt: old.createdAt,
                alertCount: old.alertCount,
                deviceCount: old.deviceCount, issueKey: old.issueKey
            )
        }
    }

    /// Keep the current modal batch unread and take the user to its full list.
    ///
    /// Suppression is revision-based rather than ID-only so a later grouped
    /// update to the same alert can open the modal again.
    @discardableResult
    public func reviewPresentedCriticalAlerts() -> [Int] {
        let presented = presentedCriticalAlerts
        reviewedCriticalAlertRevisions.formUnion(
            presented.map(CriticalAlertRevision.init)
        )
        selectedDashboardSection = .alerts
        return presented.map(\.id)
    }

    /// Mark only the alerts represented by the current modal batch as read.
    @discardableResult
    public func clearPresentedCriticalAlerts() -> [Int] {
        let alertIds = presentedCriticalAlerts.map(\.id)
        for alertId in alertIds {
            markAlertRead(alertId)
        }
        return alertIds
    }

    /// Replace an existing alert in-place (used for grouped alert updates via WebSocket).
    public func updateAlert(_ alert: AlertSummary) {
        if let index = alerts.firstIndex(where: { $0.id == alert.id }) {
            alerts[index] = alert
        } else {
            // New alert we haven't seen — insert at top
            alerts.insert(alert, at: 0)
        }
    }

    /// Upsert a decoy: update existing or append if new (from auto-deploy WS events).
    public func updateDecoy(_ decoy: DecoySummary) {
        if decoy.status == "removed" {
            decoys.removeAll(where: { $0.id == decoy.id })
        } else if let index = decoys.firstIndex(where: { $0.id == decoy.id }) {
            decoys[index] = decoy
        } else {
            decoys.append(decoy)
        }
        devices = Self.visibleDevices(devices, decoys: decoys)
    }

    public func refreshDecoys() async {
        guard let client = sensorClient else { return }
        do {
            let response: DecoyListResponse = try await client.request(.decoys)
            self.decoys = response.items
            self.devices = Self.visibleDevices(devices, decoys: response.items)
        } catch {
            // Silently fail — stale data is better than no data
        }
    }

    public func refreshSystemStatus() async throws {
        guard let client = sensorClient else {
            throw SensorClientError.connectionFailed("Sensor is not connected")
        }
        let status: StatusResponse = try await client.request(.status)
        updateSystemStatus(status)
    }

    public func refreshAlerts() async throws {
        guard let client = sensorClient else {
            throw SensorClientError.connectionFailed("Sensor is not connected")
        }

        var refreshed: [AlertSummary] = []
        var offset = 0
        while true {
            let page: PaginatedAlerts = try await client.request(.alerts(limit: 50, offset: offset))
            refreshed.append(contentsOf: page.items)
            if offset + page.items.count >= page.total || page.items.isEmpty {
                break
            }
            offset += page.items.count
        }
        alerts = refreshed
    }

    public func clearAlertHistory() async throws -> AlertHistoryClearResponse {
        guard let client = sensorClient else {
            throw SensorClientError.connectionFailed("Sensor is not connected")
        }

        let response: AlertHistoryClearResponse = try await client.request(.clearAlertHistory)
        applyAlertHistoryClear(response)

        // Confirm the post-delete state without turning a successful clear into
        // a reported failure if a follow-up refresh is temporarily unavailable.
        try? await refreshAlerts()
        try? await refreshSystemStatus()
        return response
    }

    public func applyAlertHistoryClear(_ response: AlertHistoryClearResponse) {
        applyAlertHistoryClearedEvent()
    }

    public func applyAlertHistoryClearedEvent(throughSequence: Int? = nil) {
        WSEventProcessor.discardPendingAlertUpdates(throughSequence: throughSequence)
        alerts.removeAll()
        incidents.removeAll()
        reviewedCriticalAlertRevisions.removeAll()
        if let status = systemStatus {
            systemStatus = StatusResponse(
                profile: status.profile,
                learningMode: status.learningMode,
                deviceCount: status.deviceCount,
                decoyCount: status.decoyCount,
                alertCount: 0,
                version: status.version,
                apiProtocolVersion: status.apiProtocolVersion
            )
        }
    }

    public func applyResourceProfile(_ profile: ResourceProfileResponse) {
        resourceProfile = profile
        if let status = systemStatus {
            systemStatus = StatusResponse(
                profile: profile.profile,
                learningMode: status.learningMode,
                deviceCount: status.deviceCount,
                decoyCount: status.decoyCount,
                alertCount: status.alertCount,
                version: status.version,
                apiProtocolVersion: status.apiProtocolVersion
            )
        }
    }

    public func updateSystemStatus(_ status: StatusResponse) {
        self.systemStatus = status
        guard let version = status.version, let info = sensorInfo else { return }
        sensorInfo = HealthResponse(
            version: version,
            sensorId: info.sensorId,
            uptimeSeconds: info.uptimeSeconds
        )
    }

    public func updateLearningStatus(_ status: LearningStatusResponse) {
        self.learningStatus = status
    }

    public func addIncident(_ incident: IncidentDetail) {
        if let index = incidents.firstIndex(where: { $0.id == incident.id }) {
            incidents[index] = incident
        } else {
            incidents.append(incident)
        }
    }

    private func reconcileReviewedCriticalAlertRevisions() {
        let current = Set(alerts.map(CriticalAlertRevision.init))
        reviewedCriticalAlertRevisions.formIntersection(current)
    }
}
