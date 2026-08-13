import Foundation
import Testing
@testable import SquirrelOpsHome

/// Group E: app behavior.
///
/// 18 of 22 cases were already covered by 281 existing tests. Only the modules
/// with zero test references are here. See qa/FINDINGS.md for the mapping.
///
/// Asserts the behavior the product should have. A failure is a finding.
@Suite("FunctionalGroupE")
struct FunctionalGroupETests {

    // MARK: - E-14: protocol compatibility gate

    @Test("Only the exact supported protocol is accepted")
    func acceptsOnlyTheCurrentProtocol() {
        #expect(SensorAPICompatibility.supports(SensorAPICompatibility.current))
    }

    @Test("An older or newer protocol is refused", arguments: [0, 1, 3, 4, 99, -1])
    func refusesMismatchedProtocol(version: Int) {
        #expect(SensorAPICompatibility.supports(version) == false)
    }

    @Test("A sensor that reports no protocol is refused")
    func refusesMissingProtocol() {
        // Predates the compatibility contract, so it cannot be trusted to
        // speak the current API even if every endpoint appears to answer.
        #expect(SensorAPICompatibility.supports(nil) == false)
    }

    @Test("The error names both sides so the user knows which to update")
    func errorMessageNamesBothVersions() {
        let message = SensorAPICompatibility.errorMessage(for: 1)
        #expect(message.contains("\(SensorAPICompatibility.current)"))
        #expect(message.contains("1"))
    }

    @Test("A missing protocol produces its own distinct message")
    func missingProtocolHasItsOwnMessage() {
        let missing = SensorAPICompatibility.errorMessage(for: nil)
        let mismatch = SensorAPICompatibility.errorMessage(for: 1)
        #expect(missing != mismatch)
        #expect(missing.isEmpty == false)
    }

    // MARK: - E-03: decoy addresses must never render as devices

    @MainActor
    private func decoy(
        id: Int,
        type: String,
        status: String,
        bind: String
    ) -> DecoySummary {
        DecoySummary(
            id: id,
            name: "d\(id)",
            decoyType: type,
            bindAddress: bind,
            port: 80,
            status: status,
            connectionCount: 0,
            credentialTripCount: 0,
            createdAt: "2026-08-07T00:00:00Z",
            updatedAt: "2026-08-07T00:00:00Z"
        )
    }

    @Test("Active mimic addresses are collected for filtering")
    @MainActor
    func activeMimicAddressesAreCollected() {
        let ips = AppState.decoyDeviceIPs(in: [
            decoy(id: 1, type: "mimic", status: "active", bind: "192.168.1.200"),
            decoy(id: 2, type: "mimic", status: "active", bind: "192.168.1.201"),
        ])
        #expect(ips == ["192.168.1.200", "192.168.1.201"])
    }

    @Test("A non-mimic decoy is not treated as a fake host address")
    @MainActor
    func nonMimicDecoysAreExcluded() {
        let ips = AppState.decoyDeviceIPs(in: [
            decoy(id: 1, type: "http", status: "active", bind: "192.168.1.200"),
        ])
        #expect(ips.isEmpty)
    }

    @Test("Placeholder bind addresses are never treated as device IPs",
          arguments: ["", "0.0.0.0", "127.0.0.1", "::"])
    @MainActor
    func placeholderAddressesAreExcluded(bind: String) {
        // Filtering on 0.0.0.0 would hide every device on the network.
        let ips = AppState.decoyDeviceIPs(in: [
            decoy(id: 1, type: "mimic", status: "active", bind: bind),
        ])
        #expect(ips.isEmpty)
    }

    @Test("A degraded mimic address is still not shown as a real device")
    @MainActor
    func degradedMimicIsStillADecoy() {
        // A degraded host keeps its alias, so showing it as a device would put
        // a fake host in the user's inventory.
        let ips = AppState.decoyDeviceIPs(in: [
            decoy(id: 1, type: "mimic", status: "degraded", bind: "192.168.1.200"),
        ])
        #expect(ips.contains("192.168.1.200"))
    }
}
