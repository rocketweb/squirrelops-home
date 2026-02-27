import SwiftUI

struct DeviceTile: View {
    @Environment(\.colorScheme) private var colorScheme
    let device: DeviceSummary

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            HStack(spacing: Spacing.sm) {
                Image(systemName: device.deviceIcon)
                    .font(.system(size: 20))
                    .foregroundStyle(Theme.textSecondary(colorScheme))

                Spacer()

                Circle()
                    .fill(device.isOnline
                        ? Theme.statusSuccess(colorScheme)
                        : Theme.textTertiary(colorScheme))
                    .frame(width: 8, height: 8)
            }

            Text(device.displayName)
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textPrimary(colorScheme))
                .lineLimit(1)

            Text(device.ipAddress)
                .font(Typography.mono)
                .tracking(Typography.monoTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))
                .lineLimit(1)

            StatusBadge(
                label: device.trustStatusLabel,
                style: device.trustBadgeStyle
            )
        }
        .frame(minWidth: 140, maxWidth: .infinity, alignment: .leading)
        .padding(Spacing.md)
        .background(Theme.backgroundSecondary(colorScheme))
        .overlay(
            RoundedRectangle(cornerRadius: Spacing.radiusLg)
                .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusLg))
    }
}
