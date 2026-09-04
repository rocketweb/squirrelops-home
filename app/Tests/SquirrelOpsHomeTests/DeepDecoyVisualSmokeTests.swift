import AppKit
import Testing
import SwiftUI

@testable import SquirrelOpsHome

@Suite("Deep decoy visual smoke")
struct DeepDecoyVisualSmokeTests {
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
