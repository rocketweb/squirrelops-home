import Foundation

/// The two intentional first-launch outcomes supported by the desktop app.
enum SetupPath: String, CaseIterable, Identifiable, Sendable {
    case protectThisMac
    case connectToAnotherSensor

    var id: Self { self }

    var title: String {
        switch self {
        case .protectThisMac:
            "Build Local Sensor"
        case .connectToAnotherSensor:
            "Connect to Another Sensor"
        }
    }

    var detail: String {
        switch self {
        case .protectThisMac:
            "Build and run a sensor on this Mac to protect your home network."
        case .connectToAnotherSensor:
            "Connect to a SquirrelOps sensor already running on your network."
        }
    }

    var systemImage: String {
        switch self {
        case .protectThisMac:
            "desktopcomputer.and.macbook"
        case .connectToAnotherSensor:
            "network"
        }
    }

    var requiresLocalServices: Bool {
        self == .protectThisMac
    }

    var installationNote: String {
        switch self {
        case .protectThisMac:
            "Included with the SquirrelOps Home package"
        case .connectToAnotherSensor:
            "No local services installed"
        }
    }
}
