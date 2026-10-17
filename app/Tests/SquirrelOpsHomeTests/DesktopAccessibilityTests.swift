import Testing
@testable import SquirrelOpsHome

@Suite("Desktop accessibility labels")
struct DesktopAccessibilityTests {
    @Test("Lifecycle names distinguish a whole fake host from one listener")
    func lifecycleScopeNames() throws {
        let host = try #require(PreviewData.decoys.first { $0.isDeepDecoy })
        let listener = try #require(PreviewData.decoys.first { $0.isHostListener })
        #expect(host.enableControlLabel == "Enable fake host studio-mini.local at 192.168.1.240")
        #expect(listener.enableControlLabel == "Enable listener dev_server at 192.168.1.100:8080")
    }

    @Test("Missing hostnames fall back to the decoy name", arguments: [nil, "", "  "] as [String?])
    func unnamedHost(hostname: String?) {
        let decoy = DecoySummary(id: 1, name: "Studio Build Mac", decoyType: "deep",
            bindAddress: "192.168.1.240", port: 22, status: "stopped", connectionCount: 0,
            credentialTripCount: 0, createdAt: "2026-09-26", updatedAt: "2026-09-26",
            hostname: hostname)
        #expect(decoy.enableControlLabel == "Enable fake host Studio Build Mac at 192.168.1.240")
    }

    @Test("Wildcard listener names retain the sensor-interface scope")
    func wildcardListener() {
        let decoy = DecoySummary(id: 1, name: "Development server", decoyType: "dev_server",
            bindAddress: "0.0.0.0", port: 8080, status: "active", connectionCount: 0,
            credentialTripCount: 0, createdAt: "2026-09-26", updatedAt: "2026-09-26")
        #expect(decoy.enableControlLabel == "Enable listener Development server at All sensor interfaces · port 8080")
    }
}
