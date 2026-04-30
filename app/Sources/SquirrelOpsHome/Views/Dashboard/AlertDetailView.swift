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
                .frame(maxWidth: .infinity, maxHeight: .infinity)
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
        VStack(alignment: .leading, spacing: 0) {
            headerSection(alert)
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.lg) {
                    if alert.alertType == "security.port_risk" {
                        portRiskSection(alert)
                    } else {
                        sourceSection(alert)
                        intrusionSection(alert)
                    }
                    if hasCredentialInfo(alert) {
                        credentialSection(alert)
                    }
                    if alert.decoyId != nil || detailValue(alert, "decoy_name") != nil {
                        decoySection(alert)
                    }
                }
                .padding(Spacing.lg)
            }
        }
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
                    Text(friendlyAlertType(alert.alertType))
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

                Text(alert.createdAt)
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

    private func portRiskSection(_ alert: AlertDetail) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            sectionHeader("AFFECTED DEVICES")

            VStack(alignment: .leading, spacing: Spacing.s12) {
                if let service = detailValue(alert, "service_name") {
                    detailRow(label: "Service", value: service)
                }
                if let port = detailValue(alert, "port") {
                    detailRow(label: "Port", value: port, mono: true)
                }

                if let devices = alert.affectedDevices, !devices.isEmpty {
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

                if let risk = alert.riskDescription {
                    detailRow(label: "Risk", value: risk)
                }
                if let remediation = alert.remediation {
                    detailRow(label: "Fix", value: remediation)
                }
            }
            .sectionCard(colorScheme: colorScheme)
        }
    }

    // MARK: - Source Section


    private func sourceSection(_ alert: AlertDetail) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            sectionHeader("SOURCE")

            VStack(alignment: .leading, spacing: Spacing.sm) {
                if let ip = alert.sourceIp {
                    detailRow(label: "IP Address", value: ip, mono: true)
                }
                if let mac = alert.sourceMac {
                    detailRow(label: "MAC Address", value: mac, mono: true)
                }
                if let hostname = detailValue(alert, "hostname") {
                    detailRow(label: "Hostname", value: hostname)
                }
                if let vendor = detailValue(alert, "vendor") {
                    detailRow(label: "Vendor", value: vendor)
                }
                if let deviceId = alert.deviceId {
                    detailRow(label: "Device ID", value: "#\(deviceId)")
                }
            }
            .sectionCard(colorScheme: colorScheme)
        }
    }

    // MARK: - Intrusion Section

    private func intrusionSection(_ alert: AlertDetail) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            sectionHeader("INTRUSION DETAILS")

            VStack(alignment: .leading, spacing: Spacing.sm) {
                if let port = detailValue(alert, "dest_port") {
                    detailRow(label: "Port", value: port, mono: true)
                }
                if let proto = detailValue(alert, "protocol") {
                    detailRow(label: "Protocol", value: proto.uppercased())
                }
                if let path = detailValue(alert, "request_path") {
                    detailRow(label: "Request Path", value: path, mono: true)
                }
                if let method = detailValue(alert, "detection_method") {
                    detailRow(label: "Detection", value: friendlyDetectionMethod(method))
                }
            }
            .sectionCard(colorScheme: colorScheme)
        }
    }

    // MARK: - Credential Section

    private func credentialSection(_ alert: AlertDetail) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            sectionHeader("CREDENTIAL ACCESS")

            VStack(alignment: .leading, spacing: Spacing.sm) {
                if let cred = detailValue(alert, "credential_used") {
                    detailRow(label: "Credential", value: cred, mono: true)
                }
                if let path = detailValue(alert, "request_path") {
                    detailRow(label: "Accessed Via", value: path, mono: true)
                }
            }
            .sectionCard(colorScheme: colorScheme)
        }
    }

    // MARK: - Decoy Section

    private func decoySection(_ alert: AlertDetail) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            sectionHeader("DECOY")

            VStack(alignment: .leading, spacing: Spacing.sm) {
                if let name = detailValue(alert, "decoy_name") {
                    detailRow(label: "Name", value: name)
                }
                if let decoyId = alert.decoyId {
                    detailRow(label: "Decoy ID", value: "#\(decoyId)")
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

    private func detailValue(_ alert: AlertDetail, _ key: String) -> String? {
        guard case .object(let dict) = alert.detail,
              let val = dict[key] else { return nil }
        switch val {
        case .string(let s): return s
        case .int(let i): return String(i)
        case .double(let d): return String(d)
        case .bool(let b): return b ? "true" : "false"
        default: return nil
        }
    }

    private func hasCredentialInfo(_ alert: AlertDetail) -> Bool {
        detailValue(alert, "credential_used") != nil
    }

    private func friendlyAlertType(_ type: String) -> String {
        switch type {
        case "decoy.trip": return "Port Scan Detected"
        case "decoy.credential_trip": return "Credential Accessed"
        case "device.new": return "New Device"
        case "device.verification_needed": return "Device Verification"
        case "device.mac_changed": return "MAC Address Changed"
        case "security.port_risk": return "Port Risk"
        case "security.vendor_advisory": return "Vendor Advisory"
        case "system.sensor_offline": return "Sensor Offline"
        case "system.learning_complete": return "Learning Complete"
        default: return type
        }
    }

    private func friendlyDetectionMethod(_ method: String) -> String {
        switch method {
        case "decoy_http": return "HTTP Decoy"
        case "mimic_decoy": return "Mimic Decoy"
        case "dns_canary": return "DNS Canary"
        default: return method
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
            let detail: AlertDetail = try await appState.sensorClient!.request(.alert(id: alertId))
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
