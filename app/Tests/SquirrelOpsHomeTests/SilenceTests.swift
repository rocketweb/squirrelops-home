import Foundation
import Testing
@testable import SquirrelOpsHome

@Suite("AlertSilencing")
struct AlertSilencingTests {

    @Test("silenceUntil nil by default")
    @MainActor
    func defaultNotSilenced() {
        let state = AppState()
        #expect(state.silenceUntil == nil)
        #expect(state.isSilenced == false)
    }

    @Test("isSilenced true when silenceUntil is in the future")
    @MainActor
    func silencedWhenFuture() {
        let state = AppState()
        state.silenceUntil = Date().addingTimeInterval(3600)
        #expect(state.isSilenced == true)
    }

    @Test("isSilenced false when silenceUntil is in the past")
    @MainActor
    func notSilencedWhenPast() {
        let state = AppState()
        state.silenceUntil = Date().addingTimeInterval(-1)
        #expect(state.isSilenced == false)
    }

    @Test("menuBarStatus returns connected when silenced with unread alerts")
    @MainActor
    func menuBarSilenced() {
        let state = AppState()
        state.connectionState = .live
        state.alerts = [AlertSummary(
            id: 1, incidentId: nil, alertType: "decoy.trip", severity: "critical",
            title: "Test", sourceIp: nil, readAt: nil, actionedAt: nil,
            createdAt: "2026-01-01T00:00:00Z", alertCount: nil
        )]
        state.silenceUntil = Date().addingTimeInterval(3600)
        #expect(state.menuBarStatus == .connected)
    }

    @Test("firstCriticalAlert returns nil when silenced")
    @MainActor
    func criticalAlertSuppressedWhenSilenced() {
        let state = AppState()
        state.alerts = [AlertSummary(
            id: 1, incidentId: nil, alertType: "decoy.trip", severity: "critical",
            title: "Test", sourceIp: nil, readAt: nil, actionedAt: nil,
            createdAt: "2026-01-01T00:00:00Z", alertCount: nil
        )]
        state.silenceUntil = Date().addingTimeInterval(3600)
        #expect(state.firstCriticalAlert == nil)
    }
}
