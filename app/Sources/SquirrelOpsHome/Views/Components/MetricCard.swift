import SwiftUI

struct MetricCard: View {
    @Environment(\.colorScheme) private var colorScheme
    let title: String
    let value: String
    let icon: String

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            HStack(spacing: Spacing.sm) {
                Image(systemName: icon)
                    .font(.system(size: 14))
                    .foregroundStyle(Theme.textTertiary(colorScheme))
                Text(title.uppercased())
                    .font(Typography.caption)
                    .tracking(Typography.captionTracking)
                    .foregroundStyle(Theme.textTertiary(colorScheme))
            }
            Text(value)
                .font(Typography.h3)
                .foregroundStyle(Theme.textPrimary(colorScheme))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(Spacing.md)
        .background(Theme.backgroundSecondary(colorScheme))
        .cornerRadius(Spacing.radiusLg)
    }
}
