import Foundation

// MARK: - MenuBarStatus

public enum MenuBarStatus: Sendable, Equatable {
    case connected
    case alertsPresent
    case criticalAlert
    case disconnected
}

// MARK: - AppState

@MainActor
@Observable
public final class AppState {

    public var connectionState: ConnectionState = .disconnected
    public var sensorInfo: HealthResponse?
    public var devices: [DeviceSummary] = []
    public var alerts: [AlertSummary] = []
    public var incidents: [IncidentDetail] = []
    public var decoys: [DecoySummary] = []
    public var systemStatus: StatusResponse?
    public var learningStatus: LearningStatusResponse?
    public var pairedSensor: PairingManager.PairedSensor?

    /// The active sensor client, set after connection. Views use this for actions.
    public var sensorClient: (any SensorClientProtocol)?

    public var silenceUntil: Date?

    public var isSilenced: Bool {
        guard let until = silenceUntil else { return false }
        return until > Date()
    }

    public var isPaired: Bool { pairedSensor != nil }

    /// Closure called when the user requests re-pairing from the auth-failed banner.
    /// Set by App.swift to wire up credential cleanup and navigation.
    public var onRepairRequested: (() -> Void)?

    public var menuBarStatus: MenuBarStatus {
        switch connectionState {
        case .live, .connected, .syncing:
            if isSilenced { return .connected }
            if hasCriticalAlert { return .criticalAlert }
            else if hasUnreadAlerts { return .alertsPresent }
            else { return .connected }
        case .disconnected, .connecting, .authFailed:
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

    public var firstCriticalAlert: AlertSummary? {
        guard !isSilenced else { return nil }
        return alerts.first { $0.readAt == nil && ($0.severity == "critical" || $0.severity == "high") }
    }

    public init() {}

    // MARK: - Mutation Methods

    public func applySyncData(
        sensorInfo: HealthResponse,
        status: StatusResponse,
        devices: [DeviceSummary],
        alerts: [AlertSummary],
        decoys: DecoyListResponse
    ) {
        self.sensorInfo = sensorInfo
        self.systemStatus = status
        self.devices = devices
        self.alerts = alerts
        self.decoys = decoys.items
    }

    public func updateDevice(_ device: DeviceSummary) {
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
                alertCount: old.alertCount
            )
        }
    }

    /// Upsert a decoy: update existing or append if new (from auto-deploy WS events).
    public func updateDecoy(_ decoy: DecoySummary) {
        if let index = decoys.firstIndex(where: { $0.id == decoy.id }) {
            decoys[index] = decoy
        } else {
            decoys.append(decoy)
        }
    }

    public func refreshDecoys() async {
        guard let client = sensorClient else { return }
        do {
            let response: DecoyListResponse = try await client.request(.decoys)
            self.decoys = response.items
        } catch {
            // Silently fail — stale data is better than no data
        }
    }

    public func updateSystemStatus(_ status: StatusResponse) {
        self.systemStatus = status
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
}
