import AppKit
import SwiftUI
import Testing
@testable import SquirrelOpsHome

@MainActor
@Suite("Decoy refresh feedback")
struct DecoyRefreshFeedbackTests {
    @Test("Successful explicit refresh confirms even unchanged data")
    func confirmsSuccessfulRefresh() async throws {
        let state = AppState()
        let client = MockSensorClient()
        state.sensorClient = client
        let feedback = DecoyRefreshFeedback()
        #expect(feedback.confirmationID == nil)
        try await feedback.refresh { try await state.refreshDecoyInventory() }
        #expect(client.requestedEndpoints == ["/decoys", "/system/status"])
        #expect(feedback.confirmationID != nil)
        #expect(!feedback.isRefreshing)
        #expect(DecoyRefreshFeedback.confirmationText == "Updated just now")
        #expect(DecoyRefreshFeedback.displayDuration == .seconds(3))
    }

    @Test("Failure clears old success and never confirms a partial refresh")
    func failureClearsConfirmation() async throws {
        let feedback = DecoyRefreshFeedback()
        let state = AppState()
        let client = MockSensorClient()
        state.sensorClient = client
        try await feedback.refresh { try await state.refreshDecoyInventory() }
        #expect(feedback.confirmationID != nil)
        client.setError(.connectionFailed("Status request failed"), for: "/system/status")
        do {
            try await feedback.refresh {
                #expect(feedback.isRefreshing)
                #expect(feedback.confirmationID == nil)
                try await state.refreshDecoyInventory()
            }
            Issue.record("Failure must remain an error")
        } catch {
            #expect(error is SensorClientError)
        }
        #expect(feedback.confirmationID == nil)
        #expect(!feedback.isRefreshing)
        #expect(client.requestedEndpoints == ["/decoys", "/system/status", "/decoys", "/system/status"])
    }

    @Test("An old dismissal cannot hide a newer refresh confirmation")
    func dismissalIsScopedToRefresh() async throws {
        let feedback = DecoyRefreshFeedback()
        try await feedback.refresh {}
        let first = try #require(feedback.confirmationID)
        try await feedback.refresh {}
        let second = try #require(feedback.confirmationID)
        #expect(first != second)
        feedback.dismissConfirmation(first)
        #expect(feedback.confirmationID == second)
        feedback.dismissConfirmation(second)
        #expect(feedback.confirmationID == nil)
    }

    @Test("An in-flight refresh is not duplicated")
    func coalescesRefresh() async throws {
        let feedback = DecoyRefreshFeedback()
        var calls = 0
        try await feedback.refresh {
            calls += 1
            #expect(feedback.isRefreshing)
            #expect(feedback.confirmationID == nil)
            try await feedback.refresh { calls += 1 }
        }
        #expect(calls == 1)
        #expect(feedback.confirmationID != nil)
    }

    @Test("Cancellation does not show success even if the client ignores cancellation")
    func cancellationDoesNotConfirm() async {
        let feedback = DecoyRefreshFeedback()
        let task = Task {
            do {
                try await feedback.refresh {}
                Issue.record("Cancelled refresh should not finish successfully")
            } catch {
                #expect(error is CancellationError)
            }
        }
        task.cancel()
        await task.value
        #expect(feedback.confirmationID == nil)
        #expect(!feedback.isRefreshing)
    }

    @Test("Leaving the screen clears the transient confirmation")
    func clearsOnExit() async throws {
        let feedback = DecoyRefreshFeedback()
        try await feedback.refresh {}
        #expect(feedback.confirmationID != nil)
        feedback.clearConfirmation()
        #expect(feedback.confirmationID == nil)
    }

    @Test("Confirmation renders at narrow, standard and wide content sizes in both appearances",
          arguments: [560.0, 880.0, 1400.0], [false, true])
    func confirmationVisuals(width: Double, dark: Bool) throws {
        FontRegistration.registerAllFonts()
        let scheme: ColorScheme = dark ? .dark : .light
        let host = NSHostingView(rootView:
            PullToRefreshScrollView(isRefreshing: false, showsRefreshConfirmation: true, refresh: {}) {
                Text("Decoy inventory remains unchanged")
                    .font(Typography.body)
                    .padding(.top, 80)
                    .frame(maxWidth: .infinity, minHeight: 200)
            }
            .background(Theme.background(scheme))
            .environment(\.colorScheme, scheme)
            .frame(width: width, height: 200)
        )
        host.frame = NSRect(x: 0, y: 0, width: width, height: 200)
        host.layoutSubtreeIfNeeded()
        let bitmap = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: bitmap)
        let data = try #require(bitmap.representation(using: .png, properties: [:]))
        #expect(data.count > 1_000)
        if let output = ProcessInfo.processInfo.environment["SQUIRRELOPS_REFRESH_UI_OUTPUT"] {
            try FileManager.default.createDirectory(atPath: output, withIntermediateDirectories: true)
            try data.write(to: URL(fileURLWithPath: output)
                .appendingPathComponent("confirmation-\(Int(width))-\(dark ? "dark" : "light").png"))
        }
    }
}
