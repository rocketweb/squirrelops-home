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

    @Test("Review preserves alerts, suppresses the current batch, and navigates")
    @MainActor
    func reviewPreservesAndNavigates() {
        let state = AppState()
        state.alerts = [
            AlertSummary(
                id: 10, incidentId: nil, alertType: "decoy.trip",
                severity: "critical", title: "Trip",
                sourceIp: "192.168.1.50", readAt: nil,
                actionedAt: nil, createdAt: "2026-02-24T10:00:00Z",
                alertCount: nil
            ),
            AlertSummary(
                id: 11, incidentId: nil, alertType: "device.mac_changed",
                severity: "high", title: "MAC changed",
                sourceIp: "192.168.1.51", readAt: nil,
                actionedAt: nil, createdAt: "2026-02-24T10:01:00Z",
                alertCount: nil
            ),
        ]

        let reviewedIds = state.reviewPresentedCriticalAlerts()

        #expect(reviewedIds == [10, 11])
        #expect(state.alerts.count == 2)
        #expect(state.alerts.allSatisfy { $0.readAt == nil })
        #expect(state.hasCriticalAlert)
        #expect(!state.shouldPresentCriticalAlertModal)
        #expect(state.firstCriticalAlert == nil)
        #expect(state.selectedDashboardSection == .alerts)
    }

    @Test("A new critical alert reopens the modal after Review")
    @MainActor
    func newAlertReopensAfterReview() {
        let state = AppState()
        state.alerts = [
            AlertSummary(
                id: 20, incidentId: nil, alertType: "decoy.trip",
                severity: "critical", title: "First trip",
                sourceIp: "192.168.1.60", readAt: nil,
                actionedAt: nil, createdAt: "2026-02-24T10:00:00Z",
                alertCount: nil
            ),
        ]
        state.reviewPresentedCriticalAlerts()

        state.addAlert(
            AlertSummary(
                id: 21, incidentId: nil, alertType: "decoy.trip",
                severity: "high", title: "New trip",
                sourceIp: "192.168.1.61", readAt: nil,
                actionedAt: nil, createdAt: "2026-02-24T10:05:00Z",
                alertCount: nil
            )
        )

        #expect(state.shouldPresentCriticalAlertModal)
        #expect(state.firstCriticalAlert?.id == 21)
        #expect(state.presentedCriticalAlerts.map(\.id) == [21])
        #expect(state.alerts.first(where: { $0.id == 20 })?.readAt == nil)
    }

    @Test("A new grouped revision reopens the modal after Review")
    @MainActor
    func groupedRevisionReopensAfterReview() {
        let state = AppState()
        state.alerts = [
            AlertSummary(
                id: 30, incidentId: nil, alertType: "security.port_risk",
                severity: "high", title: "Risky service",
                sourceIp: nil, readAt: nil, actionedAt: nil,
                createdAt: "2026-02-24T10:00:00Z", alertCount: 2,
                deviceCount: 2, issueKey: "port-risk:23"
            ),
        ]
        state.reviewPresentedCriticalAlerts()

        state.updateAlert(
            AlertSummary(
                id: 30, incidentId: nil, alertType: "security.port_risk",
                severity: "high", title: "Risky service",
                sourceIp: nil, readAt: nil, actionedAt: nil,
                createdAt: "2026-02-24T10:00:00Z", alertCount: 3,
                deviceCount: 3, issueKey: "port-risk:23"
            )
        )

        #expect(state.shouldPresentCriticalAlertModal)
        #expect(state.firstCriticalAlert?.id == 30)
    }

    @Test("Clear marks only the presented modal batch read without deleting history")
    @MainActor
    func clearMarksPresentedBatchRead() {
        let state = AppState()
        state.alerts = [
            AlertSummary(
                id: 40, incidentId: nil, alertType: "decoy.trip",
                severity: "critical", title: "Trip",
                sourceIp: "192.168.1.70", readAt: nil,
                actionedAt: nil, createdAt: "2026-02-24T10:00:00Z",
                alertCount: nil
            ),
            AlertSummary(
                id: 41, incidentId: nil, alertType: "device.new",
                severity: "medium", title: "New device",
                sourceIp: "192.168.1.71", readAt: nil,
                actionedAt: nil, createdAt: "2026-02-24T10:01:00Z",
                alertCount: nil
            ),
        ]

        let clearedIds = state.clearPresentedCriticalAlerts()

        #expect(clearedIds == [40])
        #expect(state.alerts.count == 2)
        #expect(state.alerts.first(where: { $0.id == 40 })?.readAt != nil)
        #expect(state.alerts.first(where: { $0.id == 41 })?.readAt == nil)
        #expect(!state.shouldPresentCriticalAlertModal)
        #expect(!state.hasCriticalAlert)
        #expect(state.hasUnreadAlerts)
    }

    @Test("Clear after Review leaves the reviewed alert unread")
    @MainActor
    func clearLeavesReviewedAlertUnread() {
        let state = AppState()
        state.alerts = [
            AlertSummary(
                id: 50, incidentId: nil, alertType: "decoy.trip",
                severity: "critical", title: "Reviewed trip",
                sourceIp: "192.168.1.80", readAt: nil,
                actionedAt: nil, createdAt: "2026-02-24T10:00:00Z",
                alertCount: nil
            ),
        ]
        state.reviewPresentedCriticalAlerts()
        state.addAlert(
            AlertSummary(
                id: 51, incidentId: nil, alertType: "decoy.trip",
                severity: "critical", title: "New trip",
                sourceIp: "192.168.1.81", readAt: nil,
                actionedAt: nil, createdAt: "2026-02-24T10:05:00Z",
                alertCount: nil
            )
        )

        #expect(state.clearPresentedCriticalAlerts() == [51])
        #expect(state.alerts.first(where: { $0.id == 50 })?.readAt == nil)
        #expect(state.alerts.first(where: { $0.id == 51 })?.readAt != nil)
    }
}
