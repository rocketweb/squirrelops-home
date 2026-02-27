import SwiftUI

extension DeviceSummary {
    var deviceIcon: String {
        switch deviceType {
        case "computer": return "desktopcomputer"
        case "smartphone": return "iphone"
        case "smart_tv": return "tv"
        case "speaker": return "hifispeaker"
        case "smart_speaker": return "homepod"
        case "network_equipment": return "wifi.router"
        case "nas": return "externaldrive.connected.to.line.below"
        case "sbc": return "cpu"
        case "camera": return "web.camera"
        case "streaming": return "appletv"
        case "thermostat": return "thermometer"
        case "smart_home", "smart_lighting": return "lightbulb"
        case "iot_device": return "sensor"
        case "gaming_console", "game_console": return "gamecontroller"
        default: return "questionmark.circle"
        }
    }

    var trustStatusLabel: String {
        switch trustStatus {
        case "approved": return "Approved"
        case "rejected": return "Rejected"
        default: return "Unreviewed"
        }
    }

    var trustBadgeStyle: StatusBadge.Style {
        switch trustStatus {
        case "approved": return .active
        case "rejected": return .critical
        default: return .degraded
        }
    }

    var displayName: String {
        if let customName { return customName }
        if let hostname { return hostname }
        if let modelName { return modelName }
        return vendorDisplayName ?? "Unknown Device"
    }

    /// Builds a display name from vendor + device type (e.g., "Sonos Speaker").
    private var vendorDisplayName: String? {
        guard let vendor, vendor != "Unknown" else { return nil }
        let typeName = Self.deviceTypeDisplayNames[deviceType]
        if let typeName {
            return "\(vendor) \(typeName)"
        }
        return vendor
    }

    private static let deviceTypeDisplayNames: [String: String] = [
        "computer": "Computer",
        "smartphone": "Phone",
        "smart_tv": "TV",
        "speaker": "Speaker",
        "smart_speaker": "Speaker",
        "network_equipment": "Router",
        "nas": "NAS",
        "sbc": "SBC",
        "camera": "Camera",
        "streaming": "Streaming",
        "thermostat": "Thermostat",
        "smart_home": "Smart Home",
        "smart_lighting": "Light",
        "iot_device": "IoT Device",
        "gaming_console": "Console",
        "game_console": "Console",
    ]
}
