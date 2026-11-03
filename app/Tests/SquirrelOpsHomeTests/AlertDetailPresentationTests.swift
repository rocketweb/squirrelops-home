import Foundation
import Testing
@testable import SquirrelOpsHome

@Suite("Alert detail presentation")
struct AlertDetailPresentationTests {
    private static func alert(
        type: String,
        detail: AnyCodableValue,
        sourceIp: String? = nil,
        sourceMac: String? = nil,
        deviceId: Int? = nil,
        decoyId: Int? = nil,
        actionedAt: String? = nil,
        actionNote: String? = nil,
        affectedDevices: [AffectedDevice]? = nil,
        riskDescription: String? = nil,
        remediation: String? = nil
    ) -> AlertDetail {
        AlertDetail(
            id: 1, incidentId: nil, alertType: type, severity: "high", title: "Synthetic alert",
            detail: detail, sourceIp: sourceIp, sourceMac: sourceMac, deviceId: deviceId,
            decoyId: decoyId, readAt: nil, actionedAt: actionedAt, actionNote: actionNote,
            createdAt: "2026-11-02T10:00:00Z", affectedDevices: affectedDevices,
            riskDescription: riskDescription, remediation: remediation
        )
    }

    private static let ipConflict: AnyCodableValue = .object([
        "kind": .string("ip_claimed_by_multiple_macs"),
        "ip_addresses": .array([.string("192.0.2.10")]),
        "mac_addresses": .array([.string("02:00:00:00:00:0A"), .string("02:00:00:00:00:0B")]),
        "known_devices": .array([
            .object([
                "device_id": .int(7),
                "display_name": .string("Printer"),
                "vendor": .string("Example Vendor"),
                "ip_address": .string("192.0.2.10"),
                "mac_address": .string("02:00:00:00:00:0A"),
                "matched_on": .array([.string("ip"), .string("mac")]),
            ]),
        ]),
    ])

    private static let macConflict: AnyCodableValue = .object([
        "kind": .string("mac_observed_at_multiple_ips"),
        "ip_addresses": .array([.string("192.0.2.3"), .string("192.0.2.50"), .string("192.0.2.51")]),
        "mac_addresses": .array([.string("02:00:00:00:00:50")]),
    ])

    private static let openARPAlert = alert(
        type: "security.arp_conflict",
        detail: .object([
            "issue_key": .string("arp:identity-conflict"),
            "conflict_count": .int(2),
            "conflicts": .array([ipConflict, macConflict]),
        ]),
        riskDescription: "One IP is claimed by several MAC addresses.",
        remediation: "Inspect switch and ARP tables."
    )

    // MARK: - ARP identity conflicts

    @Test("ARP conflicts render their own section instead of empty decoy cards")
    func arpConflictRouting() {
        let presentation = AlertDetailPresentation(Self.openARPAlert)
        #expect(presentation.sections == [.arpConflicts, .guidance])
        #expect(presentation.rows(.arpConflicts) == [
            AlertDetailRow(label: "Conflicts", value: "2", mono: true),
        ])
        #expect(presentation.rows(.guidance) == [
            AlertDetailRow(label: "Risk", value: "One IP is claimed by several MAC addresses."),
            AlertDetailRow(label: "Fix", value: "Inspect switch and ARP tables."),
        ])
    }

    @Test("Each conflict says what happened in plain language")
    func arpConflictHeadlines() {
        let conflicts = AlertDetailPresentation(Self.openARPAlert).arpConflicts
        #expect(conflicts.map(\.headline) == [
            "192.0.2.10 answered from 2 MAC addresses",
            "One MAC answered at 3 IP addresses",
        ])
        #expect(conflicts.allSatisfy { !$0.explanation.isEmpty })
    }

    @Test("Each address names the known device behind it, or says there is none")
    func arpConflictAddresses() {
        let conflict = AlertDetailPresentation(Self.openARPAlert).arpConflicts[0]
        #expect(conflict.addresses.map(\.value) == [
            "192.0.2.10", "02:00:00:00:00:0A", "02:00:00:00:00:0B",
        ])
        #expect(conflict.addresses.map(\.kind) == [.ip, .mac, .mac])
        #expect(conflict.addresses.map { $0.devices.map(\.deviceId) } == [[7], [7], []])

        let device = conflict.knownDevices[0]
        #expect(device.name == "Printer")
        #expect(device.vendor == "Example Vendor")
        #expect(device.matchDescription == "Matched by IP and MAC")
    }

    @Test("A known device without a name falls back to its vendor")
    func arpConflictDeviceNameFallback() {
        let device = ARPConflictPresentation.KnownDevice(.object([
            "device_id": .int(9),
            "display_name": .null,
            "vendor": .string("Example Vendor"),
            "ip_address": .string("192.0.2.44"),
            "mac_address": .string("02:00:00:00:00:0B"),
            "matched_on": .array([.string("mac")]),
        ]))
        #expect(device?.name == "Example Vendor")
        #expect(device?.matchDescription == "Matched by MAC")
    }

    @Test("A resolved ARP alert says so and keeps the conflicts it resolved")
    func resolvedARPAlert() {
        let resolved = Self.alert(
            type: "security.arp_conflict",
            detail: .object([
                "issue_key": .string("arp:identity-conflict"),
                "conflict_count": .int(0),
                "conflicts": .array([]),
                "resolved_at": .string("2026-11-02T11:00:00Z"),
                "resolved_conflicts": .array([Self.macConflict]),
            ]),
            actionedAt: "2026-11-02T11:00:00Z",
            actionNote: "Automatically resolved by a clean ARP scan",
            riskDescription: "Risk text.",
            remediation: "Fix text."
        )
        let presentation = AlertDetailPresentation(resolved)
        #expect(presentation.sections == [.status, .arpConflicts, .guidance])
        #expect(presentation.rows(.status).map(\.label) == ["Status", "Resolved", "Note"])
        #expect(presentation.rows(.status).first?.value == "Resolved")
        #expect(presentation.arpConflictsAreHistorical)
        #expect(presentation.arpConflicts.map(\.headline) == ["One MAC answered at 3 IP addresses"])
        #expect(presentation.rows(.arpConflicts) == [
            AlertDetailRow(label: "Open Now", value: "0", mono: true),
            AlertDetailRow(label: "Previously", value: "1", mono: true),
        ])
    }

    // MARK: - Other alert types

    @Test("New and unverified devices show the device the sensor recorded",
          arguments: ["device.new", "device.verification_needed"])
    func deviceAlertRouting(type: String) {
        let presentation = AlertDetailPresentation(Self.alert(
            type: type,
            detail: .object([
                "ip_address": .string("192.0.2.20"),
                "mac_address": .string("02:00:00:00:00:20"),
                "hostname": .string("tablet"),
                "vendor": .string("Example Vendor"),
                "device_type": .string("tablet"),
                "trust_status": .string("unknown"),
            ]),
            sourceIp: "192.0.2.20", sourceMac: "02:00:00:00:00:20", deviceId: 4
        ))
        #expect(presentation.sections == [.device])
        let labels = presentation.rows(.device).map(\.label)
        #expect(labels == ["Name", "IP Address", "MAC Address", "Vendor", "Type", "Trust", "Device ID"])
    }

    @Test("A MAC change shows the device and both hardware addresses")
    func macChangedRouting() {
        let presentation = AlertDetailPresentation(Self.alert(
            type: "device.mac_changed",
            detail: .object([
                "device_name": .string("tablet"),
                "ip_address": .string("192.0.2.20"),
                "hostname": .string("tablet"),
                "old_mac": .string("02:00:00:00:00:20"),
                "new_mac": .string("02:00:00:00:00:21"),
                "confidence": .double(0.82),
                "change_count": .int(2),
            ]),
            sourceIp: "192.0.2.20", sourceMac: "02:00:00:00:00:21", deviceId: 4
        ))
        #expect(presentation.sections == [.device, .macChange])
        #expect(!presentation.rows(.device).map(\.label).contains("MAC Address"))
        #expect(presentation.rows(.macChange).map(\.label) == [
            "Previous MAC", "New MAC", "Confidence", "Changes",
        ])
        #expect(presentation.rows(.macChange)[2].value == "82%")
    }

    @Test("Text-only alerts show their recorded description",
          arguments: ["device.review_reminder", "behavioral.anomaly"])
    func textDetailRouting(type: String) {
        let presentation = AlertDetailPresentation(Self.alert(
            type: type,
            detail: .string("Device at 192.0.2.20 contacted something new."),
            sourceIp: "192.0.2.20", deviceId: 4
        ))
        #expect(presentation.sections == [.device, .details])
        #expect(presentation.detailsText == "Device at 192.0.2.20 contacted something new.")
    }

    @Test("Port risk keeps its device list and moves risk and fix into guidance")
    func portRiskRouting() {
        let presentation = AlertDetailPresentation(Self.alert(
            type: "security.port_risk",
            detail: .string("tablet (192.0.2.20)"),
            affectedDevices: [AffectedDevice(
                deviceId: 4, ipAddress: "192.0.2.20", macAddress: nil, displayName: "tablet", port: 23
            )],
            riskDescription: "Telnet is unencrypted.",
            remediation: "Disable Telnet."
        ))
        #expect(presentation.sections == [.portRisk, .guidance])
    }

    @Test("Decoy alerts keep their source and intrusion evidence")
    func decoyRouting() {
        let presentation = AlertDetailPresentation(Self.alert(
            type: "decoy.credential_trip",
            detail: .object([
                "connection_count": .int(3),
                "dest_port": .int(22),
                "credential_used": .string("canary-token"),
                "username": .string("admin"),
                "decoy_name": .string("Build box"),
            ]),
            sourceIp: "192.0.2.30", decoyId: 2
        ))
        #expect(presentation.sections == [.source, .intrusion, .credential, .decoy])
        #expect(presentation.rows(.credential).map(\.label) == ["Credential", "Username"])
    }

    @Test("Alert types with no producer yet still show what they carry",
          arguments: ["security.vendor_advisory", "system.sensor_offline", "system.learning_complete"])
    func fallbackRouting(type: String) {
        let presentation = AlertDetailPresentation(Self.alert(
            type: type,
            detail: .object(["advisory_id": .string("EX-1"), "nested": .object([:])]),
            riskDescription: "Example risk."
        ))
        #expect(presentation.sections == [.details, .guidance])
        #expect(presentation.rows(.details) == [AlertDetailRow(label: "Advisory Id", value: "EX-1")])
    }

    @Test("No alert type produces an empty card", arguments: [
        "decoy.trip", "decoy.credential_trip", "device.new", "device.verification_needed",
        "device.mac_changed", "device.review_reminder", "behavioral.anomaly",
        "security.arp_conflict", "security.port_risk", "security.vendor_advisory",
        "system.sensor_offline", "system.learning_complete", "unrecognized.type",
    ])
    func noEmptySections(type: String) {
        for detail: AnyCodableValue in [.object([:]), .string(""), .null] {
            let presentation = AlertDetailPresentation(Self.alert(type: type, detail: detail))
            for section in presentation.sections {
                #expect(presentation.hasContent(section), "\(type) shows an empty \(section) card")
            }
            #expect(!presentation.sections.contains(.source))
            #expect(!presentation.sections.contains(.intrusion))
        }
    }
}
