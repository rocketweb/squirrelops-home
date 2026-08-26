import AppKit
import SwiftUI
import Testing
@testable import SquirrelOpsHome

@Suite("Desktop experience")
@MainActor
struct DesktopExperienceTests {
    @Test("First-launch setup uses a compact fixed window")
    func firstLaunchSetupUsesCompactWindow() {
        let setup = MainWindowPresentation.setup
        let dashboard = MainWindowPresentation.dashboard

        #expect(setup.contentSize == NSSize(width: 640, height: 520))
        #expect(!setup.isResizable)
        #expect(setup.contentSize.width < dashboard.contentSize.width)
        #expect(setup.contentSize.height < dashboard.contentSize.height)
        #expect(dashboard.isResizable)
        #expect(MainWindowPresentation.forPairingState(isPaired: false) == setup)
        #expect(MainWindowPresentation.forPairingState(isPaired: true) == dashboard)
    }

    @Test("Open Dashboard activates an existing dashboard window")
    func activatesExistingDashboard() {
        let dashboard = FakeWindow(title: AppWindow.dashboard.title, isMiniaturized: true)
        let other = FakeWindow(title: "Other Window")

        let activated = WindowActivationController.activateExistingWindow(
            AppWindow.dashboard,
            windows: [other, dashboard]
        )

        #expect(activated)
        #expect(dashboard.didDeminiaturize)
        #expect(dashboard.didMakeKeyAndOrderFront)
        #expect(dashboard.didOrderFrontRegardless)
        #expect(!other.didMakeKeyAndOrderFront)
    }

    @Test("Open Dashboard reports when it must create the window")
    func reportsMissingDashboard() {
        let activated = WindowActivationController.activateExistingWindow(
            AppWindow.dashboard,
            windows: [FakeWindow(title: "SquirrelOps Home Help")]
        )

        #expect(!activated)
    }

    @Test("Empty alert menu uses compact sizing")
    func emptyAlertMenuIsCompact() {
        let empty = MenuBarLayoutMetrics(hasUnreadAlerts: false, severityCount: 0)
        let populated = MenuBarLayoutMetrics(hasUnreadAlerts: true, severityCount: 4)

        #expect(!empty.reservesFlexibleAlertSpace)
        #expect(empty.preferredHeight < populated.preferredHeight)
    }

    @Test("Empty menu's rendered intrinsic height contains no alert-sized gap")
    func renderedEmptyMenuIsCompact() {
        let emptyState = AppState()
        emptyState.connectionState = .live
        let populatedState = AppState()
        populatedState.connectionState = .live
        populatedState.alerts = [
            makeAlert(id: 1, severity: "critical"),
            makeAlert(id: 2, severity: "high"),
            makeAlert(id: 3, severity: "medium"),
            makeAlert(id: 4, severity: "low"),
        ]

        let emptyHost = NSHostingView(rootView: MenuBarView(appState: emptyState))
        let populatedHost = NSHostingView(rootView: MenuBarView(appState: populatedState))

        #expect(emptyHost.fittingSize.height < populatedHost.fittingSize.height)
        #expect(emptyHost.fittingSize.height < 300)
    }

    @Test("Help guide covers every major operator workflow")
    func helpGuideCoverage() {
        let topics = Set(HelpGuideContent.sections.map(\.id))

        #expect(topics.isSuperset(of: [
            "getting-started",
            "dashboard",
            "devices",
            "alerts-notifications",
            "decoys",
            "scouts",
            "home-assistant",
            "llm",
            "settings",
            "troubleshooting",
            "privacy-security",
            "updates-verification",
        ]))
        #expect(HelpGuideContent.sections.allSatisfy {
            !$0.title.isEmpty && !$0.blocks.isEmpty
        })
        let gettingStarted = HelpGuideContent.sections.first {
            $0.id == "getting-started"
        }
        #expect(gettingStarted?.blocks.contains {
            $0.body.contains("--show-pairing-code")
                && $0.body.contains("sudo -u _squirrelops")
        } == true)
    }

    @Test("Help menu exposes every guide section")
    func helpMenuCoverage() {
        #expect(
            SquirrelOpsHelpCommands.sectionIDs
                == HelpGuideContent.sections.map(\.id)
        )
    }

    @Test("Notification policy respects enablement, silence, read state, and severity")
    func notificationPolicy() {
        let high = makeAlert(id: 1, severity: "high")
        let medium = makeAlert(id: 2, severity: "medium")
        let read = makeAlert(id: 3, severity: "critical", readAt: "2026-07-25T12:00:00Z")

        #expect(MacNotificationPolicy.shouldNotify(
            high, enabled: true, minimumSeverity: "high", isSilenced: false
        ))
        #expect(!MacNotificationPolicy.shouldNotify(
            medium, enabled: true, minimumSeverity: "high", isSilenced: false
        ))
        #expect(!MacNotificationPolicy.shouldNotify(
            high, enabled: false, minimumSeverity: "low", isSilenced: false
        ))
        #expect(!MacNotificationPolicy.shouldNotify(
            high, enabled: true, minimumSeverity: "low", isSilenced: true
        ))
        #expect(!MacNotificationPolicy.shouldNotify(
            read, enabled: true, minimumSeverity: "low", isSilenced: false
        ))
    }

    @Test("A new WebSocket alert requests a native notification once")
    func newWebSocketAlertRequestsNotification() {
        let state = AppState()
        var requested: [AlertSummary] = []
        state.onAlertNotificationsRequested = { requested.append(contentsOf: $0) }
        let payload: [String: AnyCodableValue] = [
            "id": .int(99),
            "alert_type": .string("decoy.trip"),
            "severity": .string("high"),
            "title": .string("Decoy connection detected"),
            "created_at": .string("2026-07-25T12:00:00Z"),
        ]

        WSEventProcessor.process(
            .event(seq: 99, eventType: "alert.new", payload: payload),
            into: state
        )
        WSEventProcessor.flushPendingUpdates(into: state)

        #expect(requested.map(\.id) == [99])

        WSEventProcessor.process(
            .event(seq: 100, eventType: "alert.new", payload: payload),
            into: state
        )
        WSEventProcessor.flushPendingUpdates(into: state)

        #expect(requested.map(\.id) == [99])
    }

    private func makeAlert(
        id: Int,
        severity: String,
        readAt: String? = nil
    ) -> AlertSummary {
        AlertSummary(
            id: id,
            alertType: "decoy.trip",
            severity: severity,
            title: "Test alert",
            readAt: readAt,
            createdAt: "2026-07-25T12:00:00Z"
        )
    }
}

@MainActor
private final class FakeWindow: WindowActivating {
    let title: String
    var isMiniaturized: Bool
    private(set) var didDeminiaturize = false
    private(set) var didMakeKeyAndOrderFront = false
    private(set) var didOrderFrontRegardless = false

    init(title: String, isMiniaturized: Bool = false) {
        self.title = title
        self.isMiniaturized = isMiniaturized
    }

    func deminiaturize(_ sender: Any?) {
        didDeminiaturize = true
        isMiniaturized = false
    }

    func makeKeyAndOrderFront(_ sender: Any?) {
        didMakeKeyAndOrderFront = true
    }

    func orderFrontRegardless() {
        didOrderFrontRegardless = true
    }
}
