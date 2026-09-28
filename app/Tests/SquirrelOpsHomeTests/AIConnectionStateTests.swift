import Foundation
import AppKit
import SwiftUI
import Testing
@testable import SquirrelOpsHome

@Suite("AI connection diagnostics")
struct AIConnectionStateTests {
    private func response(_ status: String = "ok") throws -> AIProbeResponse {
        let json = #"{"status":"STATUS","message":"Test result","models":[{"id":"chat","name":"Chat"}],"elapsed_ms":1200,"checks":{"classification":true,"naming":true}}"#
            .replacingOccurrences(of: "STATUS", with: status)
        return try JSONDecoder().decode(AIProbeResponse.self, from: Data(json.utf8))
    }

    @Test @MainActor
    func editsDiscardOldResultsAndUnlockControls() throws {
        let state = AIConnectionState()
        let token = try #require(state.begin())
        state.invalidate(clearModels: true)
        state.finish(try response(), token: token, discovery: false)
        #expect(state.testResult == nil)
        #expect(!state.isBusy)
    }

    @Test @MainActor
    func modelEditPreservesCatalogButClearsValidation() throws {
        let state = AIConnectionState()
        state.finish(try response(), token: try #require(state.begin()), discovery: true)
        state.finish(try response(), token: try #require(state.begin()), discovery: false)
        #expect(state.testResult?.status == "ok")
        state.invalidate(clearModels: false)
        #expect(state.models.count == 1)
        #expect(state.testResult == nil)
        state.invalidate(clearModels: true)
        #expect(state.models.isEmpty)
    }

    @Test @MainActor
    func discoveryDoesNotValidateModelAndDuplicateClickIsIgnored() throws {
        let state = AIConnectionState()
        let token = try #require(state.begin())
        #expect(state.begin() == nil)
        state.finish(try response(), token: token, discovery: true)
        #expect(state.discoveryResult != nil)
        #expect(state.testResult == nil)
    }

    @Test @MainActor
    func oldFailureCannotUnlockNewOperation() throws {
        let state = AIConnectionState()
        let old = try #require(state.begin())
        state.invalidate(clearModels: true)
        let current = try #require(state.begin())
        state.fail("Old error", token: old)
        #expect(state.isBusy)
        #expect(state.error == nil)
        state.fail("Current error", token: current)
        #expect(!state.isBusy)
        #expect(state.error == "Current error")
    }

    @Test
    func endpointsAreExplicitPostOperations() {
        #expect(Endpoint.aiModels.path == "/config/ai/models")
        #expect(Endpoint.aiTest.path == "/config/ai/test")
        #expect(Endpoint.aiModels.method == "POST")
        #expect(Endpoint.aiTest.method == "POST")
    }

    @Test("AI controls render at narrow, standard, and wide sizes", arguments: [320.0, 560.0, 760.0], [false, true])
    @MainActor
    func controlsRender(width: Double, dark: Bool) throws {
        FontRegistration.registerAllFonts()
        let state = AIConnectionState()
        state.finish(try response(), token: try #require(state.begin()), discovery: true)
        state.finish(try response(), token: try #require(state.begin()), discovery: false)
        let scheme: ColorScheme = dark ? .dark : .light
        let host = NSHostingView(rootView: AIConnectionControls(
            state: state, model: .constant("chat"), disabled: false, run: { _ in }
        ).padding(16).frame(width: width, alignment: .leading)
            .environment(\.colorScheme, scheme).background(Theme.background(scheme)))
        host.frame = NSRect(x: 0, y: 0, width: width, height: host.fittingSize.height)
        host.layoutSubtreeIfNeeded()
        #expect(host.fittingSize.height < 500)
        let bitmap = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: bitmap)
        let data = try #require(bitmap.representation(using: .png, properties: [:]))
        #expect(data.count > 1000)
        if let output = ProcessInfo.processInfo.environment["SQUIRRELOPS_AI_UI_OUTPUT"] {
            try FileManager.default.createDirectory(atPath: output, withIntermediateDirectories: true)
            try data.write(to: URL(fileURLWithPath: output)
                .appendingPathComponent("ai-controls-\(Int(width))-\(dark ? "dark" : "light").png"))
        }
    }
}
