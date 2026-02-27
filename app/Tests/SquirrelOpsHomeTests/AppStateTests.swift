import Foundation
import Testing
@testable import SquirrelOpsHome

@Suite("AppState Tests")
@MainActor
struct AppStateTests {

    // MARK: - Helpers

    private func makeAlert(
        id: Int = 1,
        severity: String = "medium",
        readAt: String? = nil
    ) -> AlertSummary {
        AlertSummary(
            id: id,
            alertType: "device.new",
            severity: severity,
            title: "Test Alert \(id)",
            createdAt: "2026-01-01T00:00:00Z",
            alertCount: 1
        )
    }

    private func makeReadAlert(
        id: Int = 1,
        severity: String = "medium"
    ) -> AlertSummary {
        AlertSummary(
            id: id,
            alertType: "device.new",
            severity: severity,
            title: "Test Alert \(id)",
            readAt: "2026-01-01T01:00:00Z",
            createdAt: "2026-01-01T00:00:00Z",
            alertCount: 1
        )
    }

    // MARK: - Initial State

    @Test("Initial state has correct defaults")
    func initialStateDefaults() {
        let state = AppState()

        #expect(state.connectionState == .disconnected)
        #expect(state.sensorInfo == nil)
        #expect(state.devices.isEmpty)
        #expect(state.alerts.isEmpty)
        #expect(state.incidents.isEmpty)
        #expect(state.decoys.isEmpty)
        #expect(state.systemStatus == nil)
        #expect(state.pairedSensor == nil)
    }

    // MARK: - isPaired

    @Test("isPaired is false when pairedSensor is nil")
    func isPairedFalseWhenNil() {
        let state = AppState()
        #expect(state.isPaired == false)
    }

    @Test("isPaired is true when pairedSensor is set")
    func isPairedTrueWhenSet() {
        let state = AppState()
        state.pairedSensor = PairingManager.PairedSensor(
            id: 1,
            name: "Test Sensor",
            baseURL: URL(string: "https://192.168.1.100:8443")!,
            certFingerprint: "sha256:abc123"
        )
        #expect(state.isPaired == true)
    }

    // MARK: - menuBarStatus

    @Test("menuBarStatus returns .disconnected for disconnected state")
    func menuBarStatusDisconnected() {
        let state = AppState()
        state.connectionState = .disconnected
        #expect(state.menuBarStatus == .disconnected)
    }

    @Test("menuBarStatus returns .disconnected for connecting state")
    func menuBarStatusConnecting() {
        let state = AppState()
        state.connectionState = .connecting
        #expect(state.menuBarStatus == .disconnected)
    }

    @Test("menuBarStatus returns .connected when live with no unread alerts")
    func menuBarStatusConnectedNoAlerts() {
        let state = AppState()
        state.connectionState = .live
        #expect(state.menuBarStatus == .connected)
    }

    @Test("menuBarStatus returns .connected when live with all alerts read")
    func menuBarStatusConnectedAllRead() {
        let state = AppState()
        state.connectionState = .live
        state.alerts = [
            makeReadAlert(id: 1, severity: "medium"),
            makeReadAlert(id: 2, severity: "high"),
        ]
        #expect(state.menuBarStatus == .connected)
    }

    @Test("menuBarStatus returns .alertsPresent with unread medium alerts")
    func menuBarStatusAlertsPresent() {
        let state = AppState()
        state.connectionState = .live
        state.alerts = [
            makeAlert(id: 1, severity: "medium"),
        ]
        #expect(state.menuBarStatus == .alertsPresent)
    }

    @Test("menuBarStatus returns .criticalAlert with unread critical alert")
    func menuBarStatusCriticalAlert() {
        let state = AppState()
        state.connectionState = .live
        state.alerts = [
            makeAlert(id: 1, severity: "critical"),
        ]
        #expect(state.menuBarStatus == .criticalAlert)
    }

    @Test("menuBarStatus returns .criticalAlert with unread high alert")
    func menuBarStatusHighAlert() {
        let state = AppState()
        state.connectionState = .live
        state.alerts = [
            makeAlert(id: 1, severity: "high"),
        ]
        #expect(state.menuBarStatus == .criticalAlert)
    }

    // MARK: - unreadAlertCounts

    @Test("unreadAlertCounts groups correctly by severity, skipping read alerts")
    func unreadAlertCountsGrouping() {
        let state = AppState()
        state.alerts = [
            makeAlert(id: 1, severity: "medium"),
            makeAlert(id: 2, severity: "medium"),
            makeAlert(id: 3, severity: "high"),
            makeReadAlert(id: 4, severity: "critical"),
        ]

        let counts = state.unreadAlertCounts
        #expect(counts["medium"] == 2)
        #expect(counts["high"] == 1)
        #expect(counts["critical"] == nil)
    }

    // MARK: - hasUnreadAlerts

    @Test("hasUnreadAlerts is true when unread alerts exist")
    func hasUnreadAlertsTrue() {
        let state = AppState()
        state.alerts = [makeAlert(id: 1)]
        #expect(state.hasUnreadAlerts == true)
    }

    @Test("hasUnreadAlerts is false when all alerts are read")
    func hasUnreadAlertsFalse() {
        let state = AppState()
        state.alerts = [makeReadAlert(id: 1)]
        #expect(state.hasUnreadAlerts == false)
    }

    // MARK: - hasCriticalAlert

    @Test("hasCriticalAlert is true with unread critical alert")
    func hasCriticalAlertTrue() {
        let state = AppState()
        state.alerts = [makeAlert(id: 1, severity: "critical")]
        #expect(state.hasCriticalAlert == true)
    }

    @Test("hasCriticalAlert is true with unread high alert")
    func hasCriticalAlertTrueForHigh() {
        let state = AppState()
        state.alerts = [makeAlert(id: 1, severity: "high")]
        #expect(state.hasCriticalAlert == true)
    }

    @Test("hasCriticalAlert is false with only medium alerts")
    func hasCriticalAlertFalseForMedium() {
        let state = AppState()
        state.alerts = [makeAlert(id: 1, severity: "medium")]
        #expect(state.hasCriticalAlert == false)
    }

    @Test("hasCriticalAlert is false when critical alert is read")
    func hasCriticalAlertFalseWhenRead() {
        let state = AppState()
        state.alerts = [makeReadAlert(id: 1, severity: "critical")]
        #expect(state.hasCriticalAlert == false)
    }

    // MARK: - Mutation Methods

    @Test("applySyncData populates all fields")
    func applySyncDataPopulates() {
        let state = AppState()
        let health = HealthResponse(version: "1.0", sensorId: "s1", uptimeSeconds: 60)
        let status = StatusResponse(profile: "standard", learningMode: false, deviceCount: 1, decoyCount: 1, alertCount: 1)
        let device = DeviceSummary(
            id: 1, ipAddress: "192.168.1.10", macAddress: "AA:BB:CC:DD:EE:FF",
            hostname: "test", vendor: nil, deviceType: "computer", customName: nil,
            trustStatus: "unknown", isOnline: true, firstSeen: "2026-01-01", lastSeen: "2026-01-01"
        )
        let decoy = DecoySummary(
            id: 1, name: "Dev Server", decoyType: "dev_server", bindAddress: "0.0.0.0",
            port: 3000, status: "active", connectionCount: 0, credentialTripCount: 0,
            createdAt: "2026-01-01", updatedAt: "2026-01-01"
        )
        let decoys = DecoyListResponse(items: [decoy])

        state.applySyncData(sensorInfo: health, status: status, devices: [device], alerts: [makeAlert(id: 1)], decoys: decoys)

        #expect(state.sensorInfo?.version == "1.0")
        #expect(state.systemStatus?.profile == "standard")
        #expect(state.devices.count == 1)
        #expect(state.alerts.count == 1)
        #expect(state.decoys.count == 1)
    }

    @Test("updateDevice replaces existing or appends new")
    func updateDeviceReplaceOrAppend() {
        let state = AppState()
        let d1 = DeviceSummary(
            id: 1, ipAddress: "192.168.1.10", macAddress: nil, hostname: "a",
            vendor: nil, deviceType: "computer", customName: nil,
            trustStatus: "unknown", isOnline: true, firstSeen: "2026-01-01", lastSeen: "2026-01-01"
        )
        state.devices = [d1]

        // Update existing
        let d1Updated = DeviceSummary(
            id: 1, ipAddress: "192.168.1.10", macAddress: nil, hostname: "a-updated",
            vendor: nil, deviceType: "computer", customName: nil,
            trustStatus: "approved", isOnline: true, firstSeen: "2026-01-01", lastSeen: "2026-01-02"
        )
        state.updateDevice(d1Updated)
        #expect(state.devices.count == 1)
        #expect(state.devices[0].hostname == "a-updated")

        // Append new
        let d2 = DeviceSummary(
            id: 2, ipAddress: "192.168.1.11", macAddress: nil, hostname: "b",
            vendor: nil, deviceType: "phone", customName: nil,
            trustStatus: "unknown", isOnline: true, firstSeen: "2026-01-01", lastSeen: "2026-01-01"
        )
        state.updateDevice(d2)
        #expect(state.devices.count == 2)
    }

    @Test("addAlert prepends to front")
    func addAlertPrepends() {
        let state = AppState()
        state.alerts = [makeAlert(id: 1)]
        state.addAlert(makeAlert(id: 2))
        #expect(state.alerts.count == 2)
        #expect(state.alerts[0].id == 2)
    }

    @Test("markAlertRead sets readAt timestamp")
    func markAlertReadSetsTimestamp() {
        let state = AppState()
        state.alerts = [makeAlert(id: 1)]
        #expect(state.alerts[0].readAt == nil)
        state.markAlertRead(1)
        #expect(state.alerts[0].readAt != nil)
    }

    // MARK: - Learning Status

    @Test("Initial learningStatus is nil")
    func learningStatusInitialNil() {
        let state = AppState()
        #expect(state.learningStatus == nil)
    }

    @Test("updateLearningStatus sets learningStatus")
    func updateLearningStatusSets() {
        let state = AppState()
        let status = LearningStatusResponse(enabled: true, hoursElapsed: 12.5, hoursTotal: 48, phase: "learning")
        state.updateLearningStatus(status)
        #expect(state.learningStatus?.enabled == true)
        #expect(state.learningStatus?.hoursElapsed == 12.5)
        #expect(state.learningStatus?.hoursTotal == 48)
        #expect(state.learningStatus?.phase == "learning")
    }

    // MARK: - Incidents

    @Test("addIncident inserts new incident")
    func addIncidentInsertsNew() {
        let state = AppState()
        let incident = IncidentDetail(
            id: 1, sourceIp: "10.0.0.5", sourceMac: "AA:BB:CC:DD:EE:FF",
            status: "active", severity: "high", alertCount: 2,
            firstAlertAt: "2026-01-01T00:00:00Z", lastAlertAt: "2026-01-01T01:00:00Z",
            closedAt: nil, summary: nil, alerts: []
        )
        state.addIncident(incident)
        #expect(state.incidents.count == 1)
        #expect(state.incidents[0].id == 1)
    }

    @Test("addIncident replaces existing incident with same id")
    func addIncidentReplacesExisting() {
        let state = AppState()
        let incident1 = IncidentDetail(
            id: 1, sourceIp: "10.0.0.5", sourceMac: nil,
            status: "active", severity: "medium", alertCount: 1,
            firstAlertAt: "2026-01-01T00:00:00Z", lastAlertAt: "2026-01-01T00:00:00Z",
            closedAt: nil, summary: nil, alerts: []
        )
        state.addIncident(incident1)

        let incident1Updated = IncidentDetail(
            id: 1, sourceIp: "10.0.0.5", sourceMac: nil,
            status: "active", severity: "high", alertCount: 3,
            firstAlertAt: "2026-01-01T00:00:00Z", lastAlertAt: "2026-01-01T02:00:00Z",
            closedAt: nil, summary: "Updated", alerts: []
        )
        state.addIncident(incident1Updated)
        #expect(state.incidents.count == 1)
        #expect(state.incidents[0].alertCount == 3)
        #expect(state.incidents[0].summary == "Updated")
    }
}
