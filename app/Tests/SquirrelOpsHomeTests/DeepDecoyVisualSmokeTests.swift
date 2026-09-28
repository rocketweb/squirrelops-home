import AppKit
import Testing
import SwiftUI

@testable import SquirrelOpsHome

@Suite("Deep decoy visual smoke")
struct DeepDecoyVisualSmokeTests {
    @MainActor
    @Test("Missing Studio startup diagnostics render even with no decoy cards")
    func missingStudioDiagnosticsRender() throws {
        let state = AppState()
        state.updateSystemStatus(StatusResponse(
            profile: "standard", learningMode: false, deviceCount: 0, decoyCount: 0,
            alertCount: 0, deepDecoy: DeepDecoyStatus(
                status: "degraded",
                reason: "No verified virtual IP is available. Startup will retry on a later network scan."
            )
        ))
        let hostingView = NSHostingView(rootView: DecoyStatusView(appState: state)
            .frame(width: 880, height: 720))
        hostingView.frame = NSRect(x: 0, y: 0, width: 880, height: 720)
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try #require(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let data = try #require(bitmap.representation(using: .png, properties: [:]))
        #expect(data.count > 10_000)
        if let path = ProcessInfo.processInfo.environment["SQUIRRELOPS_STUDIO_DIAGNOSTIC_OUTPUT"] {
            try data.write(to: URL(fileURLWithPath: path), options: .atomic)
        }
    }

    @MainActor
    @Test("Studio Build Mac inventory renders from the release preview")
    func studioBuildMacInventoryRenders() throws {
        let size = NSSize(width: 880, height: 720)
        let hostingView = NSHostingView(
            rootView: DecoyStatusView(appState: PreviewData.populatedAppState())
                .frame(width: 880, height: 720)
        )
        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.layoutSubtreeIfNeeded()

        let bitmap = try #require(
            hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds)
        )
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let pngData = try #require(bitmap.representation(using: .png, properties: [:]))
        #expect(pngData.count > 50_000)

        if let outputPath = ProcessInfo.processInfo.environment[
            "SQUIRRELOPS_VISUAL_OUTPUT"
        ] {
            try pngData.write(to: URL(fileURLWithPath: outputPath), options: .atomic)
        }
    }
}
