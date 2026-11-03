import SwiftUI

struct AlertDetailView: View {
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.dismiss) private var dismiss
    let alertId: Int
    let appState: AppState
    @State private var alertDetail: AlertDetail?
    @State private var isLoading = true
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if isLoading {
                ProgressView("Loading alert...")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error = errorMessage {
                VStack(spacing: Spacing.md) {
                    Image(systemName: "exclamationmark.triangle")
                        .font(.system(size: 32))
                        .foregroundStyle(Theme.statusWarning(colorScheme))
                    Text(error)
                        .font(Typography.body)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                }
                .padding(Spacing.lg)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                HStack {
                    Button("Try Again") { Task { await fetchAlert() } }
                    Spacer()
                    Button("Close") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                }
                .padding(Spacing.md)
            } else if let alert = alertDetail {
                alertContent(alert)
            }
        }
        .frame(minWidth: 460, idealWidth: 520, minHeight: 400, idealHeight: 560)
        .background(Theme.background(colorScheme))
        .task { await fetchAlert() }
    }

    // MARK: - Content

    private func alertContent(_ alert: AlertDetail) -> some View {
        let presentation = AlertDetailPresentation(alert)
        return VStack(alignment: .leading, spacing: 0) {
            headerSection(alert)
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.lg) {
                    if presentation.sections.isEmpty {
                        Text("The sensor recorded no further detail for this alert.")
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                    }
                    ForEach(presentation.sections, id: \.self) { section in
                        sectionView(section, presentation)
                    }
                }
                .padding(Spacing.lg)
            }
        }
    }

    @ViewBuilder
    private func sectionView(
        _ section: AlertDetailSection,
        _ presentation: AlertDetailPresentation
    ) -> some View {
        switch section {
        case .arpConflicts:
            arpConflictSection(presentation)
        case .portRisk:
            portRiskSection(presentation)
        case .connections:
            connectionTimelineSection(presentation)
        case .details:
            detailsSection(presentation)
        default:
            rowSection(Self.title(for: section), presentation.rows(section))
        }
    }

    private static func title(for section: AlertDetailSection) -> String {
        switch section {
        case .status: return "STATUS"
        case .arpConflicts: return "CONFLICTS"
        case .portRisk: return "AFFECTED DEVICES"
        case .device: return "DEVICE"
        case .macChange: return "MAC ADDRESS CHANGE"
        case .source: return "SOURCE"
        case .intrusion: return "INTRUSION DETAILS"
        case .connections: return "RECENT CONNECTIONS"
        case .credential: return "CREDENTIAL ACCESS"
        case .decoy: return "DECOY"
        case .details: return "DETAILS"
        case .guidance: return "WHAT TO DO"
        }
    }

    private func rowSection(_ title: String, _ rows: [AlertDetailRow]) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            sectionHeader(title)

            VStack(alignment: .leading, spacing: Spacing.sm) {
                ForEach(rows, id: \.self) { row in
                    detailRow(label: row.label, value: row.value, mono: row.mono)
                }
            }
            .sectionCard(colorScheme: colorScheme)
        }
    }

    private func detailsSection(_ presentation: AlertDetailPresentation) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            sectionHeader(Self.title(for: .details))

            VStack(alignment: .leading, spacing: Spacing.sm) {
                if let text = presentation.detailsText {
                    Text(text)
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
                ForEach(presentation.rows(.details), id: \.self) { row in
                    detailRow(label: row.label, value: row.value, mono: row.mono)
                }
            }
            .sectionCard(colorScheme: colorScheme)
        }
    }

    // MARK: - ARP Conflict Section

    private func arpConflictSection(_ presentation: AlertDetailPresentation) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            sectionHeader(
                presentation.arpConflictsAreHistorical
                    ? "CONFLICTS BEFORE RESOLUTION"
                    : Self.title(for: .arpConflicts)
            )

            VStack(alignment: .leading, spacing: Spacing.md) {
                ForEach(presentation.rows(.arpConflicts), id: \.self) { row in
                    detailRow(label: row.label, value: row.value, mono: row.mono)
                }

                ForEach(presentation.arpConflicts) { conflict in
                    Divider()
                    arpConflictEntry(conflict)
                }
            }
            .sectionCard(colorScheme: colorScheme)
        }
    }

    private func arpConflictEntry(_ conflict: ARPConflictPresentation) -> some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            Text(conflict.headline)
                .font(Typography.body)
                .foregroundStyle(Theme.textPrimary(colorScheme))
                .textSelection(.enabled)
            Text(conflict.explanation)
                .font(Typography.caption)
                .foregroundStyle(Theme.textTertiary(colorScheme))
                .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: Spacing.xs) {
                ForEach(conflict.addresses) { address in
                    arpAddressRow(address)
                }
            }
            .padding(.top, Spacing.xs)
        }
    }

    private func arpAddressRow(_ address: ARPConflictPresentation.Address) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.sm) {
            Text(address.kind == .ip ? "IP" : "MAC")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))
                .frame(width: 32, alignment: .trailing)
            VStack(alignment: .leading, spacing: 2) {
                Text(address.value)
                    .font(Typography.mono)
                    .tracking(Typography.monoTracking)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
                    .textSelection(.enabled)
                if address.devices.isEmpty {
                    Text("Not in device inventory")
                        .font(Typography.caption)
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                } else {
                    ForEach(address.devices) { device in
                        Text("\(knownDeviceLabel(device)) · \(device.matchDescription)")
                            .font(Typography.caption)
                            .foregroundStyle(Theme.textPrimary(colorScheme))
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                    }
                }
            }
        }
    }

    private func knownDeviceLabel(_ device: ARPConflictPresentation.KnownDevice) -> String {
        var parts = [device.name]
        if let vendor = device.vendor, vendor != device.name {
            parts.append(vendor)
        }
        parts.append("#\(device.deviceId)")
        return parts.joined(separator: " · ")
    }

    // MARK: - Header

    private func headerSection(_ alert: AlertDetail) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: Spacing.sm) {
                HStack(spacing: Spacing.sm) {
                    SeverityDot(severity: alert.severity)

                    Text(alert.title)
                        .font(Typography.h3)
                        .tracking(Typography.h3Tracking)
                        .foregroundStyle(Theme.textPrimary(colorScheme))
                }

                HStack(spacing: Spacing.s12) {
                    Text(friendlyAlertType(alert))
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                        .padding(.horizontal, Spacing.sm)
                        .padding(.vertical, 2)
                        .background(Theme.backgroundTertiary(colorScheme))
                        .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusSm))

                    Text(alert.severity.uppercased())
                        .font(Typography.caption)
                        .tracking(Typography.captionTracking)
                        .foregroundStyle(severityColor(alert.severity))
                }

                Text(TimestampPresentation.local(alert.createdAt))
                    .font(Typography.mono)
                    .tracking(Typography.monoTracking)
                    .foregroundStyle(Theme.textTertiary(colorScheme))
            }

            Spacer()

            Button("Done") {
                dismiss()
            }
            .keyboardShortcut(.cancelAction)
        }
        .padding(Spacing.lg)
    }

    // MARK: - Port Risk Section

    private func portRiskSection(_ presentation: AlertDetailPresentation) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            sectionHeader(Self.title(for: .portRisk))

            VStack(alignment: .leading, spacing: Spacing.s12) {
                ForEach(presentation.rows(.portRisk), id: \.self) { row in
                    detailRow(label: row.label, value: row.value, mono: row.mono)
                }

                if let devices = presentation.alert.affectedDevices, !devices.isEmpty {
                    VStack(spacing: Spacing.xs) {
                        ForEach(devices) { device in
                            HStack(spacing: Spacing.sm) {
                                Text(device.displayName)
                                    .font(Typography.bodySmall)
                                    .foregroundStyle(Theme.textPrimary(colorScheme))
                                    .lineLimit(1)
                                Spacer()
                                Text(device.ipAddress)
                                    .font(Typography.mono)
                                    .tracking(Typography.monoTracking)
                                    .foregroundStyle(Theme.textSecondary(colorScheme))
                                    .textSelection(.enabled)
                            }
                        }
                    }
                    .padding(.top, Spacing.xs)
                }
            }
            .sectionCard(colorScheme: colorScheme)
        }
    }

    // MARK: - Connection Timeline Section

    private func connectionTimelineSection(_ presentation: AlertDetailPresentation) -> some View {
        let connections = Array(presentation.recentConnections.reversed())
        return VStack(alignment: .leading, spacing: Spacing.s12) {
            sectionHeader(Self.title(for: .connections))

            VStack(alignment: .leading, spacing: Spacing.sm) {
                ForEach(Array(connections.enumerated()), id: \.offset) { index, item in
                    HStack(alignment: .top, spacing: Spacing.sm) {
                        Text(TimestampPresentation.local(item.timestamp))
                            .font(Typography.mono)
                            .tracking(Typography.monoTracking)
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                        Spacer()
                        VStack(alignment: .trailing, spacing: Spacing.xs) {
                            Text("\(AlertSummary.decoyServiceName(item.port)) :\(item.port)")
                                .font(Typography.mono)
                                .tracking(Typography.monoTracking)
                            if let outcome = item.outcome {
                                Text(outcome)
                                    .font(Typography.caption)
                                    .multilineTextAlignment(.trailing)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                    }
                    if index < connections.count - 1 {
                        Divider()
                    }
                }
            }
            .sectionCard(colorScheme: colorScheme)
        }
    }

    // MARK: - Helpers

    private func sectionHeader(_ title: String) -> some View {
        Text(title)
            .font(Typography.caption)
            .tracking(Typography.captionTracking)
            .foregroundStyle(Theme.textTertiary(colorScheme))
    }

    private func detailRow(label: String, value: String, mono: Bool = false) -> some View {
        HStack(alignment: .top, spacing: Spacing.sm) {
            Text(label)
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))
                .frame(width: 100, alignment: .trailing)

            if mono {
                Text(value)
                    .font(Typography.mono)
                    .tracking(Typography.monoTracking)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
                    .textSelection(.enabled)
            } else {
                Text(value)
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
            }
        }
    }

    private func friendlyAlertType(_ alert: AlertDetail) -> String {
        switch alert.alertType {
        case "decoy.trip":
            guard case .object(let detail) = alert.detail,
                  case .array(let ports) = detail["ports"] else {
                return "Decoy Activity"
            }
            return ports.count >= 2 ? "Port Scan Detected" : "Decoy Activity"
        case "decoy.credential_trip": return "Credential Accessed"
        case "device.new": return "New Device"
        case "device.verification_needed": return "Device Verification"
        case "device.mac_changed": return "MAC Address Changed"
        case "security.arp_conflict": return "ARP Identity Conflict"
        case "security.port_risk": return "Port Risk"
        case "security.vendor_advisory": return "Vendor Advisory"
        case "system.sensor_offline": return "Sensor Offline"
        case "system.learning_complete": return "Learning Complete"
        default: return alert.alertType
        }
    }

    private func severityColor(_ severity: String) -> Color {
        switch severity {
        case "critical", "high": return Theme.statusError(colorScheme)
        case "medium": return Theme.statusWarning(colorScheme)
        case "low": return Theme.statusInfo(colorScheme)
        default: return Theme.textTertiary(colorScheme)
        }
    }

    // MARK: - Network

    private func fetchAlert() async {
        isLoading = true
        errorMessage = nil
        do {
            guard let client = appState.sensorClient else {
                throw SensorClientError.connectionFailed("Sensor is not connected")
            }
            let detail: AlertDetail = try await client.request(.alert(id: alertId))
            await MainActor.run {
                alertDetail = detail
                isLoading = false
            }
        } catch {
            await MainActor.run {
                errorMessage = "Failed to load alert: \(error.localizedDescription)"
                isLoading = false
            }
        }
    }
}

// MARK: - Section Card Modifier

private extension View {
    func sectionCard(colorScheme: ColorScheme) -> some View {
        self
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(Spacing.md)
            .background(Theme.backgroundSecondary(colorScheme))
            .overlay(
                RoundedRectangle(cornerRadius: Spacing.radiusMd)
                    .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
    }
}
