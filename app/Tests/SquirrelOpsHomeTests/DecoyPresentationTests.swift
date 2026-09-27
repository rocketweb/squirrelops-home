import AppKit
import SwiftUI
import Testing
@testable import SquirrelOpsHome

@Suite("Decoy presentation")
struct DecoyPresentationTests {
    @Test("Connection evidence distinguishes guest admission from rejected attempts")
    func relayOutcomeLabels() {
        #expect(AlertSummary.relayOutcomeDescription("ssh.guest_connected") == "Guest connected")
        #expect(AlertSummary.relayOutcomeDescription("smb.capacity_rejected") == "Rejected: guest at capacity")
        #expect(AlertSummary.relayOutcomeDescription("ssh.guest_connect_failed") == "Guest connection failed")
        #expect(AlertSummary.relayOutcomeDescription("smb.guest_connect_timeout") == "Guest connection timed out")
        // Old .connection events were ambiguous; never relabel them as successful.
        #expect(AlertSummary.relayOutcomeDescription("ssh.connection") == nil)
        #expect(AlertSummary.relayOutcomeDescription("http.guest_connected") == nil)
    }

    @Test("Routine Studio states do not occupy the message area", arguments: ["active", "stopped", "disabled"])
    func routineStatesAreQuiet(status: String) {
        #expect(DeepDecoyStatus(status: status, reason: nil).operationalNote == nil)
    }

    @Test("Disabled configuration does not become a warning")
    func disabledReasonIsQuiet() {
        #expect(DeepDecoyStatus(status: "disabled", reason: "Disabled in sensor configuration.").operationalNote == nil)
    }

    @Test("Startup and failures keep useful notes", arguments: ["starting", "degraded", "unavailable"])
    func actionableStatesRemainVisible(status: String) {
        #expect(DeepDecoyStatus(status: status, reason: nil).operationalNote != nil)
        #expect(DeepDecoyStatus(status: status, reason: "Waiting for a verified address.").operationalNote?.contains("Waiting for a verified address.") == true)
    }

    @Test("Only a deliberate pull from the top refreshes once")
    func pullGestureBoundaries() {
        var gesture = PullRefreshGesture()
        gesture.begin(atTop: false, isRefreshing: false)
        gesture.update(distance: 100)
        let fromMiddle = gesture.end()
        #expect(!fromMiddle)
        gesture.begin(atTop: true, isRefreshing: false)
        gesture.update(distance: 20)
        let shortPull = gesture.end()
        #expect(!shortPull)
        gesture.begin(atTop: true, isRefreshing: false)
        gesture.update(distance: PullRefreshGesture.threshold)
        let fullPull = gesture.end()
        let repeatedEnd = gesture.end()
        #expect(fullPull)
        #expect(!repeatedEnd)
        gesture.begin(atTop: true, isRefreshing: true)
        gesture.update(distance: 100)
        let whileRefreshing = gesture.end()
        #expect(!whileRefreshing)
    }

    @MainActor
    @Test("Refresh loads both the decoy list and system status")
    func refreshLoadsBoth() async throws {
        let client = MockSensorClient()
        let state = AppState()
        state.sensorClient = client
        try await state.refreshDecoyInventory()
        #expect(client.requestedEndpoints == ["/decoys", "/system/status"])
        #expect(state.systemStatus != nil)
    }

    @MainActor
    @Test("Failed manual refresh retains the list and reports the error")
    func failedRefreshRetainsData() async {
        let client = MockSensorClient()
        client.shouldFail = true
        let state = PreviewData.populatedAppState()
        state.sensorClient = client
        let originalIDs = state.decoys.map(\.id)
        do {
            try await state.refreshDecoyInventory()
            Issue.record("Refresh should report connection failure")
        } catch {
            #expect(error is SensorClientError)
        }
        #expect(state.decoys.map(\.id) == originalIDs)
    }

    @MainActor
    @Test("Captured short-pull deltas alone must not arm a refresh", arguments: [
        [1, 7, 12, 22, 29, 39, 48, 65, 72, 68, 66, 57, 33, 29],
        [13, 18, 35, 76, 98, 84, 67, 65],
    ])
    func acceleratedInputIsNotVisibleDistance(deltas: [Int32]) throws {
        // Physical short pulls captured on macOS 27. Accelerated event totals
        // were 548 and 456, while the content-position observer stayed at zero.
        // Input alone is not evidence that the visible pull threshold was met.
        let coordinator = ScrollRefreshObserver.Coordinator()
        let scroll = makePullTestScrollView()
        coordinator.attach(to: scroll)
        defer { coordinator.attach(to: nil) }
        var refreshCount = 0
        coordinator.onRefresh = { refreshCount += 1 }
        for (index, delta) in (deltas + [0]).enumerated() {
            let phase: CGScrollPhase = index == 0 ? .began : (index == deltas.count ? .ended : .changed)
            let cg = try #require(CGEvent(scrollWheelEvent2Source: nil, units: .pixel, wheelCount: 1, wheel1: delta, wheel2: 0, wheel3: 0))
            cg.setIntegerValueField(.scrollWheelEventScrollPhase, value: Int64(phase.rawValue))
            coordinator.handleScrollEvent(try #require(NSEvent(cgEvent: cg)))
        }
        #expect(refreshCount == 0)
    }

    @MainActor
    @Test("Native scroll events refresh once; momentum and cancellation do not")
    func nativePullRefresh() async throws {
        var refreshCount = 0
        let coordinator = ScrollRefreshObserver.Coordinator()
        let scroll = makePullTestScrollView()
        coordinator.attach(to: scroll)
        defer { coordinator.attach(to: nil) }
        coordinator.onRefresh = { refreshCount += 1 }
        func event(_ phase: NSEvent.Phase, delta: Int32 = 0, momentum: Bool = false) throws -> NSEvent {
            let cg = try #require(CGEvent(scrollWheelEvent2Source: nil, units: .pixel, wheelCount: 1, wheel1: delta, wheel2: 0, wheel3: 0))
            // CGScrollPhase and NSEvent.Phase use different bit values.
            let cgPhase: CGScrollPhase
            switch phase {
            case .began: cgPhase = .began
            case .changed: cgPhase = .changed
            case .ended: cgPhase = .ended
            default: cgPhase = .cancelled
            }
            cg.setIntegerValueField(.scrollWheelEventScrollPhase, value: Int64(cgPhase.rawValue))
            if momentum { cg.setIntegerValueField(.scrollWheelEventMomentumPhase, value: 1) }
            let native = try #require(NSEvent(cgEvent: cg))
            #expect(native.phase == phase)
            return native
        }
        coordinator.handleScrollEvent(try event(.began))
        scroll.contentView.bounds.origin.y = -80
        coordinator.handleScrollEvent(try event(.changed, delta: 80))
        coordinator.handleScrollEvent(try event(.ended))
        #expect(refreshCount == 1)
        coordinator.handleScrollEvent(try event(.ended))
        scroll.contentView.bounds.origin.y = 0
        coordinator.handleScrollEvent(try event(.began))
        coordinator.handleScrollEvent(try event(.changed, delta: 80, momentum: true))
        coordinator.handleScrollEvent(try event(.ended))
        coordinator.handleScrollEvent(try event(.began))
        scroll.contentView.bounds.origin.y = -80
        coordinator.handleScrollEvent(try event(.changed, delta: 80))
        coordinator.handleScrollEvent(try event(.cancelled))
        coordinator.handleScrollEvent(try event(.ended))
        #expect(refreshCount == 1)
    }

    @MainActor
    @Test("Only measured overscroll arms; mid-list movement and residual bounce cannot")
    func measuredPullBoundaries() throws {
        let scroll = makePullTestScrollView()
        let coordinator = ScrollRefreshObserver.Coordinator()
        coordinator.attach(to: scroll)
        defer { coordinator.attach(to: nil) }
        var refreshes = 0
        var visiblePull: CGFloat = 0
        coordinator.onRefresh = { refreshes += 1 }
        coordinator.onPull = { visiblePull = $0 }
        func send(_ phase: CGScrollPhase) throws {
            let cg = try #require(CGEvent(scrollWheelEvent2Source: nil, units: .pixel, wheelCount: 1, wheel1: 0, wheel2: 0, wheel3: 0))
            cg.setIntegerValueField(.scrollWheelEventScrollPhase, value: Int64(phase.rawValue))
            coordinator.handleScrollEvent(try #require(NSEvent(cgEvent: cg)))
        }

        #expect(coordinator.contentTop == 0)
        try send(.began)
        #expect(coordinator.gesture.isTracking)
        // The first captured sequence reached only 38 visible points on replay.
        for top: CGFloat in [0, 1, 3, 5, 8, 11, 16, 21, 25, 30, 33, 36, 38] {
            scroll.contentView.bounds.origin.y = -top
            try send(.changed)
            #expect(coordinator.contentTop == top)
        }
        #expect(visiblePull == 38)
        #expect(!coordinator.gesture.isArmed)
        try send(.ended)
        #expect(refreshes == 0)
        #expect(visiblePull == 0)

        scroll.contentView.bounds.origin.y = 200
        try send(.began)
        scroll.contentView.bounds.origin.y = -100
        try send(.changed)
        try send(.ended)
        #expect(refreshes == 0)

        scroll.contentView.bounds.origin.y = -70
        #expect(coordinator.contentTop == 70)
        try send(.began)
        scroll.contentView.bounds.origin.y = -75
        try send(.changed)
        #expect(visiblePull == 5)
        try send(.ended)
        #expect(refreshes == 0)

        scroll.contentView.bounds.origin.y = 0
        try send(.began)
        scroll.contentView.bounds.origin.y = -(PullRefreshGesture.threshold - 1)
        try send(.changed)
        #expect(!coordinator.gesture.isArmed)
        scroll.contentView.bounds.origin.y = -PullRefreshGesture.threshold
        try send(.changed)
        #expect(coordinator.gesture.isArmed)
        #expect(visiblePull == PullRefreshGesture.threshold)
        try send(.ended)
        try send(.ended)
        #expect(refreshes == 1)

        scroll.contentView.bounds.origin.y = 0
        try send(.began)
        scroll.contentView.bounds.origin.y = -80
        coordinator.isRefreshing = true
        try send(.ended)
        #expect(refreshes == 1)
    }

    @MainActor
    @Test("Captured full pull refreshes without extra finger travel")
    func capturedFullPullRefreshes() throws {
        let scroll = makePullTestScrollView()
        let coordinator = ScrollRefreshObserver.Coordinator()
        coordinator.attach(to: scroll)
        defer { coordinator.attach(to: nil) }
        var refreshes = 0
        coordinator.onRefresh = { refreshes += 1 }
        // Native clip positions from the physical non-refreshing full pull,
        // not accelerated wheel deltas or hand-picked threshold values.
        let positions: [CGFloat] = [0, 0, 0, 2, 4, 9, 16, 23, 30, 35, 39, 42,
            44, 46, 47, 48, 49, 49, 49, 50, 50, 50, 50, 50, 51, 51, 51, 51, 51, 52, 52]
        for (index, top) in positions.enumerated() {
            scroll.contentView.bounds.origin.y = -top
            let phase: CGScrollPhase = index == 0 ? .began : (index == positions.count - 1 ? .ended : .changed)
            let cg = try #require(CGEvent(scrollWheelEvent2Source: nil, units: .pixel, wheelCount: 1, wheel1: 0, wheel2: 0, wheel3: 0))
            cg.setIntegerValueField(.scrollWheelEventScrollPhase, value: Int64(phase.rawValue))
            coordinator.handleScrollEvent(try #require(NSEvent(cgEvent: cg)))
        }
        #expect(refreshes == 1)
    }

    @MainActor
    @Test("Native observer restores its clip notification and elasticity settings")
    func observerCleanup() {
        let scroll = makePullTestScrollView()
        scroll.contentView.postsBoundsChangedNotifications = false
        scroll.verticalScrollElasticity = .none
        let coordinator = ScrollRefreshObserver.Coordinator()
        coordinator.attach(to: scroll)
        #expect(scroll.contentView.postsBoundsChangedNotifications)
        #expect(scroll.verticalScrollElasticity == .allowed)
        coordinator.attach(to: nil)
        #expect(!scroll.contentView.postsBoundsChangedNotifications)
        #expect(scroll.verticalScrollElasticity == .none)
        #expect(coordinator.monitor == nil)
        #expect(coordinator.contentTop == nil)
    }

    @MainActor
    @Test("Decoy notes render in light and dark appearances", arguments: ["stopped", "starting", "degraded"], [false, true])
    func noticeVisuals(status: String, dark: Bool) throws {
        let state = PreviewData.populatedAppState()
        state.updateSystemStatus(StatusResponse(
            profile: "standard", learningMode: false, deviceCount: 5, decoyCount: state.decoys.count,
            alertCount: 0, deepDecoy: DeepDecoyStatus(
                status: status, reason: status == "degraded" ? "No verified virtual IP is available. Startup will retry on a later network scan." : nil
            )
        ))
        let hosting = NSHostingView(rootView: DecoyStatusView(appState: state)
            .environment(\.colorScheme, dark ? .dark : .light)
            .frame(width: 880, height: 720))
        hosting.frame = NSRect(x: 0, y: 0, width: 880, height: 720)
        hosting.layoutSubtreeIfNeeded()
        let bitmap = try #require(hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds))
        hosting.cacheDisplay(in: hosting.bounds, to: bitmap)
        let data = try #require(bitmap.representation(using: .png, properties: [:]))
        #expect(data.count > 10_000)
        if let directory = ProcessInfo.processInfo.environment["SQUIRRELOPS_DECOY_UI_OUTPUT_DIR"] {
            try data.write(to: URL(fileURLWithPath: directory).appendingPathComponent("\(status)-\(dark ? "dark" : "light").png"))
        }
    }
}

@MainActor
private func makePullTestScrollView() -> NSScrollView {
    let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 400, height: 300))
    // Offscreen AppKit clamps programmatic bounds changes outside a live
    // gesture. Allow the test to supply the measured elastic positions.
    scroll.contentView = PullTestClipView(frame: scroll.bounds)
    scroll.documentView = PullTestDocument(frame: NSRect(x: 0, y: 0, width: 400, height: 1000))
    scroll.contentView.bounds.origin.y = 0
    return scroll
}

private final class PullTestDocument: NSView {
    override var isFlipped: Bool { true }
}

private final class PullTestClipView: NSClipView {
    override func constrainBoundsRect(_ proposedBounds: NSRect) -> NSRect { proposedBounds }
}
