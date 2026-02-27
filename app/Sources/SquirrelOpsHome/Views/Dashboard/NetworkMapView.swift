import SwiftUI

struct NetworkMapView: View {
    @Environment(\.colorScheme) private var colorScheme
    let devices: [DeviceSummary]

    private static let categoryOrder: [String] = [
        "infrastructure", "computer", "server", "phone", "media", "iot", "unknown",
    ]

    private var groupedDevices: [(category: String, devices: [DeviceSummary])] {
        let grouped = Dictionary(grouping: devices) { $0.deviceType }
        return Self.categoryOrder.compactMap { category in
            guard let items = grouped[category], !items.isEmpty else { return nil }
            return (category: category, devices: items)
        }
    }

    private let columns = [
        GridItem(.adaptive(minimum: 160), spacing: Spacing.md),
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            ForEach(groupedDevices, id: \.category) { group in
                VStack(alignment: .leading, spacing: Spacing.sm) {
                    Text(group.category.uppercased())
                        .font(Typography.caption)
                        .tracking(Typography.captionTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))

                    LazyVGrid(columns: columns, spacing: Spacing.md) {
                        ForEach(group.devices) { device in
                            DeviceTile(device: device)
                        }
                    }
                }
            }
        }
    }
}
