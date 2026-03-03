import SwiftUI

struct AlertRow: View {
    @Environment(\.colorScheme) private var colorScheme
    let alert: AlertSummary
    var onDismiss: (() -> Void)?
    @State private var isHovering = false

    private var isUnread: Bool {
        alert.readAt == nil
    }

    private var isGrouped: Bool {
        alert.alertCount != nil && (alert.alertCount ?? 0) > 1
    }

    private var friendlyType: String {
        switch alert.alertType {
        case "decoy.trip": return "Port scan detected"
        case "decoy.credential_trip": return "Credential accessed"
        case "device.new": return "New device"
        case "device.verification_needed": return "Device verification"
        case "device.mac_changed": return "MAC changed"
        case "security.port_risk": return "Port risk"
        case "security.vendor_advisory": return "Vendor advisory"
        case "system.sensor_offline": return "Sensor offline"
        case "system.learning_complete": return "Learning complete"
        default: return alert.alertType
        }
    }

    var body: some View {
        HStack(spacing: Spacing.s12) {
            // Severity indicator
            SeverityDot(severity: alert.severity)

            // Title and subtitle
            VStack(alignment: .leading, spacing: 2) {
                Text(alert.title)
                    .font(Typography.body)
                    .foregroundStyle(
                        isUnread
                            ? Theme.textPrimary(colorScheme)
                            : Theme.textSecondary(colorScheme)
                    )
                    .lineLimit(1)

                HStack(spacing: Spacing.sm) {
                    if isGrouped, let count = alert.deviceCount, count > 0 {
                        // Grouped alert: show device count badge
                        Text("\(count) device\(count == 1 ? "" : "s")")
                            .font(Typography.mono)
                            .tracking(Typography.monoTracking)
                            .foregroundStyle(Theme.textSecondary(colorScheme))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 1)
                            .background(Theme.backgroundTertiary(colorScheme))
                            .clipShape(RoundedRectangle(cornerRadius: 3))
                    } else if let sourceIp = alert.sourceIp {
                        Text(sourceIp)
                            .font(Typography.mono)
                            .tracking(Typography.monoTracking)
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                            .lineLimit(1)
                    }

                    Text(friendlyType)
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                        .lineLimit(1)
                }
            }

            Spacer()

            // Timestamp
            Text(alert.createdAt)
                .font(Typography.mono)
                .tracking(Typography.monoTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))
                .lineLimit(1)

            // Dismiss button (visible on hover for unread alerts)
            if let onDismiss = onDismiss, isHovering {
                Button {
                    onDismiss()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 14))
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                }
                .buttonStyle(.plain)
                .help("Dismiss alert")
            } else if isGrouped {
                // Detail chevron for grouped alerts
                Image(systemName: "chevron.right")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(Theme.textTertiary(colorScheme))
            }

            // Unread indicator dot
            if isUnread {
                Circle()
                    .fill(Theme.accentDefault(colorScheme))
                    .frame(width: 6, height: 6)
            } else {
                // Reserve space so rows align
                Color.clear
                    .frame(width: 6, height: 6)
            }
        }
        .padding(.vertical, Spacing.sm)
        .padding(.horizontal, Spacing.md)
        .background(
            isUnread
                ? Theme.backgroundSecondary(colorScheme).opacity(0.5)
                : Color.clear
        )
        .contentShape(Rectangle())
        .onHover { hovering in
            isHovering = hovering
        }
    }
}
