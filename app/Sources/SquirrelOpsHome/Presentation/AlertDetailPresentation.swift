import Foundation

/// The cards an alert detail sheet can show, in display order.
enum AlertDetailSection: String, CaseIterable, Sendable {
    case status
    case arpConflicts
    case portRisk
    case device
    case macChange
    case source
    case intrusion
    case connections
    case credential
    case decoy
    case details
    case guidance
}

struct AlertDetailRow: Equatable, Hashable, Sendable {
    let label: String
    let value: String
    var mono: Bool = false
}

/// What the detail sheet shows for one alert.
///
/// Each alert type stores a different detail shape, so the sheet routes by
/// type to the cards that read that shape, then drops any card with nothing
/// to say. A card the sensor has no data for is never drawn empty.
struct AlertDetailPresentation {
    let alert: AlertDetail

    init(_ alert: AlertDetail) {
        self.alert = alert
    }

    /// Cards to draw, in order. Every one has content.
    var sections: [AlertDetailSection] {
        candidateSections.filter(hasContent)
    }

    func hasContent(_ section: AlertDetailSection) -> Bool {
        switch section {
        case .arpConflicts:
            return !rows(.arpConflicts).isEmpty || !arpConflicts.isEmpty
        case .portRisk:
            return !rows(.portRisk).isEmpty || !(alert.affectedDevices ?? []).isEmpty
        case .connections:
            return !recentConnections.isEmpty
        case .details:
            return detailsText != nil || !rows(.details).isEmpty
        default:
            return !rows(section).isEmpty
        }
    }

    private var candidateSections: [AlertDetailSection] {
        switch alert.alertType {
        case "security.arp_conflict":
            return [.status, .arpConflicts, .guidance]
        case "security.port_risk":
            return [.status, .portRisk, .guidance]
        case "device.new", "device.verification_needed", "device.review_reminder",
             "behavioral.anomaly":
            return [.status, .device, .details, .guidance]
        case "device.mac_changed":
            return [.status, .device, .macChange, .guidance]
        case "decoy.trip", "decoy.credential_trip":
            return [.status, .source, .intrusion, .connections, .credential, .decoy, .guidance]
        default:
            return [.status, .source, .details, .guidance]
        }
    }

    // MARK: - Rows

    func rows(_ section: AlertDetailSection) -> [AlertDetailRow] {
        var rows: [AlertDetailRow] = []
        func add(_ label: String, _ value: String?, mono: Bool = false) {
            if let value, !value.isEmpty {
                rows.append(AlertDetailRow(label: label, value: value, mono: mono))
            }
        }
        func addTime(_ label: String, _ value: String?) {
            add(label, value.map { TimestampPresentation.local($0) }, mono: true)
        }

        switch section {
        case .status:
            let resolvedAt = string("resolved_at")
            if resolvedAt != nil {
                add("Status", "Resolved")
                addTime("Resolved", resolvedAt)
            } else if alert.actionedAt != nil {
                add("Status", "Actioned")
                addTime("Actioned", alert.actionedAt)
            }
            if !rows.isEmpty {
                add("Note", alert.actionNote)
            }

        case .arpConflicts:
            if arpConflictsAreHistorical {
                add("Open Now", "0", mono: true)
                add("Previously", String(arpConflicts.count), mono: true)
            } else if let count = int("conflict_count") ?? (arpConflicts.isEmpty ? nil : arpConflicts.count) {
                add("Conflicts", String(count), mono: true)
            }

        case .portRisk:
            add("Service", string("service_name"))
            add("Port", string("port"), mono: true)

        case .device:
            let name = string("custom_name") ?? string("device_name") ?? string("hostname")
            add("Name", name)
            if let hostname = string("hostname"), hostname != name {
                add("Hostname", hostname)
            }
            add("IP Address", string("ip_address") ?? alert.sourceIp, mono: true)
            if alert.alertType != "device.mac_changed" {
                add("MAC Address", string("mac_address") ?? alert.sourceMac, mono: true)
            }
            add("Vendor", string("vendor"))
            if let type = string("device_type"), type != "unknown" {
                add("Type", type.replacingOccurrences(of: "_", with: " ").capitalized)
            }
            add("Model", string("model_name"))
            add("Area", string("area"))
            add("Trust", string("trust_status")?.capitalized)
            addTime("First Seen", string("first_seen"))
            addTime("Last Seen", string("last_seen"))
            add("Device ID", alert.deviceId.map { "#\($0)" })

        case .macChange:
            add("Previous MAC", string("old_mac"), mono: true)
            add("New MAC", string("new_mac"), mono: true)
            if case .double(let confidence)? = value("confidence") {
                add("Confidence", "\(Int((confidence * 100).rounded()))%")
            }
            if let count = int("change_count"), count > 1 {
                add("Changes", String(count), mono: true)
            }
            addTime("First Changed", string("first_changed"))
            if (int("change_count") ?? 1) > 1 {
                addTime("Last Changed", string("last_changed"))
            }

        case .source:
            add("IP Address", alert.sourceIp, mono: true)
            add("MAC Address", alert.sourceMac, mono: true)
            add("Hostname", string("hostname"))
            add("Vendor", string("vendor"))
            add("Device ID", alert.deviceId.map { "#\($0)" })

        case .intrusion:
            add("Connections", string("connection_count"), mono: true)
            add("Services", serviceCountsSummary)
            add("Latest Port", string("dest_port"), mono: true)
            add("Protocol", string("protocol")?.uppercased())
            add("Request Path", string("request_path"), mono: true)
            add("Detection", string("detection_method").map(Self.friendlyDetectionMethod))
            addTime("First Seen", string("first_seen"))
            addTime("Last Seen", string("last_seen"))

        case .credential:
            guard string("credential_used") != nil || string("username") != nil else { break }
            add("Credential", string("credential_used"), mono: true)
            add("Username", string("username"), mono: true)
            add("Auth Method", string("auth_method"))
            if string("credential_used") != nil {
                add("Accessed Via", string("request_path"), mono: true)
            }

        case .decoy:
            add("Name", string("decoy_name"))
            add("Decoy ID", alert.decoyId.map { "#\($0)" })

        case .details:
            // Only for types without a dedicated card: their primitive fields
            // are all the sensor recorded.
            guard !Self.dedicatedTypes.contains(alert.alertType),
                  case .object(let detail) = alert.detail else { break }
            let shownBySource: Set<String> = ["hostname", "vendor"]
            for key in detail.keys.sorted() where !shownBySource.contains(key) {
                add(Self.humanize(key), detail[key].flatMap(Self.primitive))
            }

        case .guidance:
            add("Risk", alert.riskDescription)
            add("Fix", alert.remediation)

        case .connections:
            break
        }
        return rows
    }

    /// The alert's prose detail, for producers that store a sentence.
    var detailsText: String? {
        guard case .string(let text) = alert.detail, !text.isEmpty else { return nil }
        return text
    }

    // MARK: - ARP conflicts

    /// True when the alert has resolved and the conflicts shown are the last
    /// ones seen before it did.
    var arpConflictsAreHistorical: Bool {
        string("resolved_at") != nil
            && conflictList("conflicts").isEmpty
            && !conflictList("resolved_conflicts").isEmpty
    }

    var arpConflicts: [ARPConflictPresentation] {
        let source = arpConflictsAreHistorical
            ? conflictList("resolved_conflicts")
            : conflictList("conflicts")
        return source.enumerated().compactMap { index, raw in
            ARPConflictPresentation(id: index, raw)
        }
    }

    private func conflictList(_ key: String) -> [AnyCodableValue] {
        guard case .array(let list)? = value(key) else { return [] }
        return list
    }

    // MARK: - Decoy evidence

    struct RecentConnection: Equatable, Sendable {
        let port: Int
        let timestamp: String
        let outcome: String?
    }

    var recentConnections: [RecentConnection] {
        guard case .array(let rawConnections)? = value("recent_connections") else {
            return []
        }
        return rawConnections.compactMap { rawConnection in
            guard case .object(let connection) = rawConnection,
                  case .int(let port) = connection["dest_port"],
                  case .string(let timestamp) = connection["timestamp"] else {
                return nil
            }
            let interaction: String?
            if case .string(let value) = connection["interaction_type"] { interaction = value }
            else { interaction = nil }
            return RecentConnection(port: port, timestamp: timestamp,
                                    outcome: AlertSummary.relayOutcomeDescription(interaction))
        }
    }

    private var serviceCountsSummary: String? {
        guard case .object(let rawCounts)? = value("service_counts") else { return nil }
        let parts: [(port: Int, label: String)] = rawCounts.compactMap { key, value in
            guard let port = Int(key), case .int(let count) = value, count > 0 else {
                return nil
            }
            return (port, "\(AlertSummary.decoyServiceName(port)) \(count)")
        }
        let labels = parts.sorted { $0.port < $1.port }.map(\.label)
        return labels.isEmpty ? nil : labels.joined(separator: " · ")
    }

    // MARK: - Detail access

    private static let dedicatedTypes: Set<String> = [
        "security.arp_conflict", "security.port_risk", "device.new",
        "device.verification_needed", "device.review_reminder", "behavioral.anomaly",
        "device.mac_changed", "decoy.trip", "decoy.credential_trip",
    ]

    private func value(_ key: String) -> AnyCodableValue? {
        guard case .object(let detail) = alert.detail else { return nil }
        return detail[key]
    }

    private func string(_ key: String) -> String? {
        value(key).flatMap(Self.primitive).flatMap { $0.isEmpty ? nil : $0 }
    }

    private func int(_ key: String) -> Int? {
        guard case .int(let number)? = value(key) else { return nil }
        return number
    }

    fileprivate static func primitive(_ value: AnyCodableValue) -> String? {
        switch value {
        case .string(let s): return s.isEmpty ? nil : s
        case .int(let i): return String(i)
        case .double(let d): return String(d)
        case .bool(let b): return b ? "Yes" : "No"
        default: return nil
        }
    }

    private static func humanize(_ key: String) -> String {
        key.split(separator: "_").map { $0.capitalized }.joined(separator: " ")
    }

    static func friendlyDetectionMethod(_ method: String) -> String {
        switch method {
        case "decoy_http": return "HTTP Decoy"
        case "mimic_decoy": return "Mimic Decoy"
        case "dns_canary": return "DNS Canary"
        default: return method
        }
    }
}

/// One ambiguous IP/MAC claim from a single ARP scan, with the known devices
/// the sensor matched to its addresses.
struct ARPConflictPresentation: Equatable, Identifiable, Sendable {
    enum AddressKind: Equatable, Sendable {
        case ip
        case mac
    }

    struct Address: Equatable, Identifiable, Sendable {
        let value: String
        let kind: AddressKind
        /// Known devices at this address. Empty means not in inventory.
        let devices: [KnownDevice]

        var id: String { "\(kind)-\(value)" }
    }

    struct KnownDevice: Equatable, Identifiable, Sendable {
        let deviceId: Int
        let name: String
        let vendor: String?
        let ipAddress: String?
        let macAddress: String?
        let matchedOn: [String]

        var id: Int { deviceId }

        init?(_ raw: AnyCodableValue) {
            guard case .object(let fields) = raw,
                  case .int(let deviceId)? = fields["device_id"] else { return nil }
            func text(_ key: String) -> String? {
                fields[key].flatMap(AlertDetailPresentation.primitive)
            }
            self.deviceId = deviceId
            vendor = text("vendor")
            name = text("display_name") ?? vendor ?? "Unnamed device"
            ipAddress = text("ip_address")
            macAddress = text("mac_address")
            if case .array(let matches)? = fields["matched_on"] {
                matchedOn = matches.compactMap { if case .string(let s) = $0 { s } else { nil } }
            } else {
                matchedOn = []
            }
        }

        var matchDescription: String {
            switch (matchedOn.contains("ip"), matchedOn.contains("mac")) {
            case (true, true): return "Matched by IP and MAC"
            case (true, false): return "Matched by IP"
            case (false, true): return "Matched by MAC"
            case (false, false): return "Matched"
            }
        }
    }

    let id: Int
    let kind: String
    let ipAddresses: [String]
    let macAddresses: [String]
    let knownDevices: [KnownDevice]

    init?(id: Int, _ raw: AnyCodableValue) {
        guard case .object(let fields) = raw else { return nil }
        func strings(_ key: String) -> [String] {
            guard case .array(let values)? = fields[key] else { return [] }
            return values.compactMap { if case .string(let s) = $0 { s } else { nil } }
        }
        self.id = id
        if case .string(let kind)? = fields["kind"] { self.kind = kind } else { kind = "" }
        ipAddresses = strings("ip_addresses")
        macAddresses = strings("mac_addresses")
        if case .array(let devices)? = fields["known_devices"] {
            knownDevices = devices.compactMap(KnownDevice.init)
        } else {
            knownDevices = []
        }
        if ipAddresses.isEmpty && macAddresses.isEmpty { return nil }
    }

    var headline: String {
        switch kind {
        case "ip_claimed_by_multiple_macs":
            return "\(ipAddresses.first ?? "One IP") answered from \(macAddresses.count) MAC addresses"
        case "mac_observed_at_multiple_ips":
            return "One MAC answered at \(ipAddresses.count) IP addresses"
        default:
            return "Ambiguous ARP claim"
        }
    }

    var explanation: String {
        switch kind {
        case "ip_claimed_by_multiple_macs":
            return "Several hardware addresses claimed this IP in one scan. A device that "
                + "rotated its private Wi-Fi address, or an address DHCP handed to a new "
                + "device while the old entry was still cached, can cause this. So can ARP "
                + "spoofing, where another host impersonates this address."
        case "mac_observed_at_multiple_ips":
            return "One hardware address answered at several IPs in one scan. Wi-Fi "
                + "extenders and mesh nodes that answer for their clients do this, as does "
                + "a device that just changed address. So can ARP spoofing, where one host "
                + "claims addresses that belong to others."
        default:
            return "The sensor saw an IP and MAC pairing it could not trust."
        }
    }

    /// Every address in the claim, IPs first, with the devices known there.
    var addresses: [Address] {
        let ips = ipAddresses.map { ip in
            Address(value: ip, kind: .ip, devices: knownDevices.filter { $0.ipAddress == ip })
        }
        let macs = macAddresses.map { mac in
            Address(
                value: mac, kind: .mac,
                devices: knownDevices.filter { $0.macAddress?.uppercased() == mac.uppercased() }
            )
        }
        return ips + macs
    }
}
