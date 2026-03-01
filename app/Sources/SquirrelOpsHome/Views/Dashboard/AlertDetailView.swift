import SwiftUI

/// Detail view for grouped security alerts.
///
/// Shown when the user clicks a grouped alert (one with an `issueKey`).
/// Displays the risk description, remediation steps, and a table of all
/// affected devices with their IPs, ports, and MACs.
struct AlertDetailView: View {
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.dismiss) private var dismiss
    let alertDetail: AlertDetail
    let appState: AppState
    @State private var isAcknowledging = false

    private var isRead: Bool {
        alertDetail.readAt != nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerSection
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.lg) {
                    if let description = alertDetail.riskDescription, !description.isEmpty {
                        infoCard(label: "WHY THIS MATTERS", content: description)
                    }

                    if let remediation = alertDetail.remediation, !remediation.isEmpty {
                        infoCard(label: "RECOMMENDED ACTION", content: remediation)
                    }

                    if let devices = alertDetail.affectedDevices, !devices.isEmpty {
                        affectedDevicesSection(devices)
                    }

                    metadataSection
                }
                .padding(Spacing.lg)
            }
        }
        .frame(minWidth: 480, idealWidth: 560, minHeight: 400, idealHeight: 600)
        .background(Theme.background(colorScheme))
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: Spacing.sm) {
                HStack(spacing: Spacing.sm) {
                    SeverityDot(severity: alertDetail.severity)

                    Text(alertDetail.title)
                        .font(Typography.h3)
                        .tracking(Typography.h3Tracking)
                        .foregroundStyle(Theme.textPrimary(colorScheme))
                }

                HStack(spacing: Spacing.s12) {
                    StatusBadge(
                        label: alertDetail.severity,
                        style: severityBadgeStyle
                    )

                    if let count = alertDetail.deviceCount, count > 0 {
                        Text("\(count) device\(count == 1 ? "" : "s") affected")
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textSecondary(colorScheme))
                    }

                    if isRead {
                        Text("Dismissed")
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                    }
                }
            }

            Spacer()

            HStack(spacing: Spacing.sm) {
                if !isRead {
                    Button {
                        dismissAlert()
                    } label: {
                        HStack(spacing: Spacing.xs) {
                            Image(systemName: "xmark.circle")
                            Text("Dismiss")
                                .font(Typography.bodySmall)
                        }
                        .foregroundStyle(.white)
                        .padding(.horizontal, Spacing.s12)
                        .padding(.vertical, Spacing.xs)
                        .background(Theme.accentDefault(colorScheme))
                        .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusFull))
                    }
                    .buttonStyle(.plain)
                    .disabled(isAcknowledging)
                }

                Button("Done") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
            }
        }
        .padding(Spacing.lg)
    }

    // MARK: - Info Cards

    private func infoCard(label: String, content: String) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text(label)
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            Text(content)
                .font(Typography.body)
                .foregroundStyle(Theme.textSecondary(colorScheme))
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

    // MARK: - Affected Devices

    private func affectedDevicesSection(_ devices: [AffectedDevice]) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("AFFECTED DEVICES")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            VStack(spacing: 0) {
                // Header row
                HStack(spacing: 0) {
                    Text("Device")
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Text("IP Address")
                        .frame(width: 140, alignment: .leading)
                    Text("Port")
                        .frame(width: 60, alignment: .trailing)
                }
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))
                .padding(.vertical, Spacing.sm)
                .padding(.horizontal, Spacing.md)
                .background(Theme.backgroundTertiary(colorScheme))

                Divider()

                // Device rows
                ForEach(devices) { device in
                    HStack(spacing: 0) {
                        Text(device.displayName)
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textPrimary(colorScheme))
                            .lineLimit(1)
                            .frame(maxWidth: .infinity, alignment: .leading)

                        Text(device.ipAddress)
                            .font(Typography.mono)
                            .tracking(Typography.monoTracking)
                            .foregroundStyle(Theme.textSecondary(colorScheme))
                            .frame(width: 140, alignment: .leading)

                        Text(String(device.port))
                            .font(Typography.mono)
                            .tracking(Typography.monoTracking)
                            .foregroundStyle(Theme.textSecondary(colorScheme))
                            .frame(width: 60, alignment: .trailing)
                    }
                    .padding(.vertical, Spacing.sm)
                    .padding(.horizontal, Spacing.md)

                    if device.id != devices.last?.id {
                        Divider()
                            .foregroundStyle(Theme.borderSubtle(colorScheme))
                    }
                }
            }
            .background(Theme.backgroundSecondary(colorScheme))
            .overlay(
                RoundedRectangle(cornerRadius: Spacing.radiusMd)
                    .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
        }
    }

    // MARK: - Metadata

    private var metadataSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("DETAILS")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            VStack(alignment: .leading, spacing: Spacing.sm) {
                metadataRow(label: "Created", value: alertDetail.createdAt, mono: true)
                metadataRow(label: "Type", value: alertDetail.alertType)

                if let issueKey = alertDetail.issueKey {
                    metadataRow(label: "Issue", value: issueKey, mono: true)
                }

                if let readAt = alertDetail.readAt {
                    metadataRow(label: "Dismissed", value: readAt, mono: true)
                }
            }
            .padding(Spacing.md)
            .background(Theme.backgroundSecondary(colorScheme))
            .overlay(
                RoundedRectangle(cornerRadius: Spacing.radiusMd)
                    .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
        }
    }

    private func metadataRow(label: String, value: String, mono: Bool = false) -> some View {
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
            } else {
                Text(value)
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
            }
        }
    }

    // MARK: - Actions

    private func dismissAlert() {
        isAcknowledging = true
        appState.markAlertRead(alertDetail.id)
        Task {
            try? await appState.sensorClient?.request(.readAlert(id: alertDetail.id))
            isAcknowledging = false
            dismiss()
        }
    }

    // MARK: - Helpers

    private var severityBadgeStyle: StatusBadge.Style {
        switch alertDetail.severity {
        case "critical": return .critical
        case "high": return .critical
        case "medium": return .degraded
        case "low": return .active
        default: return .degraded
        }
    }
}
