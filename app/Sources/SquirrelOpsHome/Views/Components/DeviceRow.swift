import SwiftUI

struct DeviceRow: View {
    @Environment(\.colorScheme) private var colorScheme
    let device: DeviceSummary

    private var hostnameSubtitle: String? {
        guard device.customName != nil else { return nil }
        return device.hostname
    }

    var body: some View {
        HStack(spacing: Spacing.s12) {
            // Online indicator dot
            Circle()
                .fill(device.isOnline
                    ? Theme.statusSuccess(colorScheme)
                    : Theme.textTertiary(colorScheme))
                .frame(width: 8, height: 8)

            // Device type icon
            Image(systemName: device.deviceIcon)
                .font(.system(size: 16))
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .frame(width: 20, alignment: .center)

            // Name column
            VStack(alignment: .leading, spacing: 2) {
                Text(device.displayName)
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textPrimary(colorScheme))
                    .lineLimit(1)

                if let subtitle = hostnameSubtitle {
                    Text(subtitle)
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                        .lineLimit(1)
                }
            }
            .frame(minWidth: 120, alignment: .leading)

            Spacer()

            // IP address
            Text(device.ipAddress)
                .font(Typography.mono)
                .tracking(Typography.monoTracking)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .lineLimit(1)

            // MAC address
            if let mac = device.macAddress {
                Text(mac)
                    .font(Typography.mono)
                    .tracking(Typography.monoTracking)
                    .foregroundStyle(Theme.textTertiary(colorScheme))
                    .lineLimit(1)
                    .frame(width: 130, alignment: .leading)
            } else {
                Text("--")
                    .font(Typography.mono)
                    .tracking(Typography.monoTracking)
                    .foregroundStyle(Theme.textTertiary(colorScheme))
                    .frame(width: 130, alignment: .leading)
            }

            // Review status badge
            StatusBadge(
                label: device.trustStatusLabel,
                style: device.trustBadgeStyle
            )
        }
        .padding(.vertical, Spacing.sm)
        .padding(.horizontal, Spacing.md)
        .contentShape(Rectangle())
    }
}
