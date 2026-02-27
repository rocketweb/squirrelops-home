import SwiftUI

struct AlertRow: View {
    @Environment(\.colorScheme) private var colorScheme
    let alert: AlertSummary

    private var isUnread: Bool {
        alert.readAt == nil
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
                    if let sourceIp = alert.sourceIp {
                        Text(sourceIp)
                            .font(Typography.mono)
                            .tracking(Typography.monoTracking)
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                            .lineLimit(1)
                    }

                    Text(alert.alertType)
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
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
    }
}
