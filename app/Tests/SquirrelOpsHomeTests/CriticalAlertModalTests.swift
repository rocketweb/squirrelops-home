import Testing
@testable import SquirrelOpsHome

@Suite("CriticalAlertModal")
struct CriticalAlertModalTests {

    @Test("firstCriticalAlert returns first unread critical alert")
    @MainActor
    func firstCriticalAlertReturnsCritical() {
        let state = AppState()
        state.alerts = [
            AlertSummary(
                id: 1, incidentId: nil, alertType: "decoy.trip",
                severity: "critical", title: "Decoy SSH tripped",
                sourceIp: "192.168.1.50", readAt: nil,
                actionedAt: nil, createdAt: "2026-02-24T10:00:00Z",
                alertCount: nil
            ),
            AlertSummary(
                id: 2, incidentId: nil, alertType: "device.new",
                severity: "low", title: "New device",
                sourceIp: "192.168.1.51", readAt: nil,
                actionedAt: nil, createdAt: "2026-02-24T09:00:00Z",
                alertCount: nil
            ),
        ]
        let result = state.firstCriticalAlert
        #expect(result?.id == 1)
    }

    @Test("firstCriticalAlert returns first unread high alert")
    @MainActor
    func firstCriticalAlertReturnsHigh() {
        let state = AppState()
        state.alerts = [
            AlertSummary(
                id: 3, incidentId: nil, alertType: "decoy.credential_trip",
                severity: "high", title: "Credential attempt",
                sourceIp: "192.168.1.60", readAt: nil,
                actionedAt: nil, createdAt: "2026-02-24T10:00:00Z",
                alertCount: nil
            ),
        ]
        let result = state.firstCriticalAlert
        #expect(result?.id == 3)
    }

    @Test("firstCriticalAlert returns nil when no unread critical/high alerts")
    @MainActor
    func firstCriticalAlertNilWhenNoCritical() {
        let state = AppState()
        state.alerts = [
            AlertSummary(
                id: 4, incidentId: nil, alertType: "device.new",
                severity: "medium", title: "New device",
                sourceIp: "192.168.1.70", readAt: nil,
                actionedAt: nil, createdAt: "2026-02-24T10:00:00Z",
                alertCount: nil
            ),
        ]
        let result = state.firstCriticalAlert
        #expect(result == nil)
    }

    @Test("firstCriticalAlert skips read critical alerts")
    @MainActor
    func firstCriticalAlertSkipsRead() {
        let state = AppState()
        state.alerts = [
            AlertSummary(
                id: 5, incidentId: nil, alertType: "decoy.trip",
                severity: "critical", title: "Old trip",
                sourceIp: "192.168.1.80", readAt: "2026-02-24T09:00:00Z",
                actionedAt: nil, createdAt: "2026-02-24T08:00:00Z",
                alertCount: nil
            ),
        ]
        let result = state.firstCriticalAlert
        #expect(result == nil)
    }

    @Test("acknowledgeAlert marks alert as read and clears hasCriticalAlert")
    @MainActor
    func acknowledgeMarksRead() async {
        let state = AppState()
        state.alerts = [
            AlertSummary(
                id: 10, incidentId: nil, alertType: "decoy.trip",
                severity: "critical", title: "Trip",
                sourceIp: "192.168.1.50", readAt: nil,
                actionedAt: nil, createdAt: "2026-02-24T10:00:00Z",
                alertCount: nil
            ),
        ]

        #expect(state.hasCriticalAlert == true)
        state.markAlertRead(10)
        #expect(state.hasCriticalAlert == false)
        #expect(state.alerts[0].readAt != nil)
    }
}
