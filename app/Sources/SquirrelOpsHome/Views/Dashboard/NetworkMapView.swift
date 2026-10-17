import SwiftUI

struct NetworkMapView: View {
    @Environment(\.colorScheme) private var colorScheme
    let devices: [DeviceSummary]

    private static let categoryOrder: [String] = [
        "infrastructure", "computer", "server", "phone", "media", "iot", "unknown",
    ]

    var groupedDevices: [(category: String, devices: [DeviceSummary])] {
        let grouped = Dictionary(grouping: devices) { Self.displayCategory(for: $0.deviceType) }
        return Self.categoryOrder.compactMap { category in
            guard let items = grouped[category], !items.isEmpty else { return nil }
            return (category: category, devices: items)
        }
    }

    // These are display groups, not the sensor's device taxonomy. Preserve
    // legacy values and keep future/unrecognized types visible in Unknown.
    private static func displayCategory(for deviceType: String) -> String {
        switch deviceType {
        case "infrastructure", "network_equipment": return "infrastructure"
        case "computer", "sbc": return "computer"
        case "server", "nas": return "server"
        case "phone", "smartphone": return "phone"
        case "media", "smart_tv", "speaker", "smart_speaker", "streaming",
             "gaming_console", "game_console": return "media"
        case "iot", "camera", "thermostat", "smart_home", "smart_lighting", "iot_device": return "iot"
        default: return "unknown"
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
