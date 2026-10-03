import AppKit
import SwiftUI

/// Standalone screenshot entry point. No production app startup, pairing,
/// notification service, Keychain reads, WebSocket, sensor or network client.
private enum SyntheticScreens {
    static let timestamp = "2026-10-02T14:15:00Z"

    static func remap<T: Codable>(_ value: T) throws -> T {
        let bytes = try JSONEncoder().encode(value)
        let text = String(decoding: bytes, as: UTF8.self)
            .replacingOccurrences(of: "192.168.1.", with: "192.168.50.")
            .replacingOccurrences(of: "matts-macbook-pro", with: "office-macbook")
            .replacingOccurrences(of: "Matt's MacBook Pro", with: "Office MacBook Pro")
            .replacingOccurrences(of: "2026-02-23", with: "2026-10-02")
            .replacingOccurrences(of: "2026-02-22", with: "2026-10-01")
        return try JSONDecoder().decode(T.self, from: Data(text.utf8))
    }

    static var decoys: [DecoySummary] {
        PreviewData.decoys.filter { $0.id != 3 }.map { d in
            DecoySummary(id: d.id, name: d.name, decoyType: d.decoyType,
                bindAddress: d.bindAddress.replacingOccurrences(of: "192.168.1.", with: "192.168.50."),
                port: d.port, status: "active", connectionCount: d.connectionCount,
                credentialTripCount: d.port == 22 || d.port == 445 ? 0 : d.credentialTripCount,
                createdAt: timestamp, updatedAt: timestamp, hostId: d.hostId,
                hostname: d.hostname, serviceProtocol: d.serviceProtocol, serviceName: d.serviceName)
        } + [DecoySummary(id: 9, name: "Archive NAS", decoyType: "mimic",
            bindAddress: "192.168.50.250", port: 80, status: "active", connectionCount: 0,
            credentialTripCount: 0, createdAt: timestamp, updatedAt: timestamp,
            hostId: 41, hostname: "archive-nas.local", serviceProtocol: "http", serviceName: "NAS Admin")]
    }

    static let profile = ResourceProfileResponse(profile: "standard", scanIntervalSeconds: 300,
        maxDecoys: 3, llmClassification: "cloud_llm", scoutIntervalMinutes: 60,
        maxMimicDecoys: 5, maxVirtualIPs: 5, totalDecoyCapacity: 8)

    static func devices() throws -> [DeviceSummary] {
        // PreviewData predates the current sensor taxonomy. Exercise today's
        // types in the real UI instead of concealing grouping/icon regressions.
        let currentTypes = ["phone": "smartphone", "iot": "smart_lighting",
                            "infrastructure": "network_equipment", "server": "nas", "media": "streaming"]
        let devices: [DeviceSummary] = try remap(PreviewData.devices)
        return devices.map { d in
            DeviceSummary(id: d.id, ipAddress: d.ipAddress, macAddress: d.macAddress,
                hostname: d.hostname, vendor: d.vendor, deviceType: currentTypes[d.deviceType] ?? d.deviceType,
                modelName: d.modelName, area: d.area, customName: d.customName,
                trustStatus: d.trustStatus, isOnline: d.isOnline, firstSeen: d.firstSeen, lastSeen: d.lastSeen)
        }
    }

    @MainActor static func state() throws -> AppState {
        let state = AppState()
        state.connectionState = .live
        state.sensorInfo = PreviewData.health
        state.devices = try devices()
        state.alerts = try remap(PreviewData.alerts)
        state.incidents = try remap(PreviewData.incidents)
        state.decoys = decoys
        state.systemStatus = StatusResponse(profile: "standard", learningMode: false,
            deviceCount: state.devices.count, decoyCount: decoys.count, alertCount: state.alerts.count)
        state.learningStatus = PreviewData.learningStatus
        state.applyResourceProfile(profile)
        state.sensorClient = ScreenshotClient()
        return state
    }
}

private final class ScreenshotClient: SensorClientProtocol, Sendable {
    func request<T: Decodable>(_ endpoint: Endpoint) async throws -> T {
        let value: any Encodable
        switch endpoint {
        case .health: value = PreviewData.health
        case .status:
            value = StatusResponse(profile: "standard", learningMode: false,
                deviceCount: 8, decoyCount: SyntheticScreens.decoys.count, alertCount: 5)
        case .profile: value = SyntheticScreens.profile
        case .learning: value = PreviewData.learningStatus
        case .decoys: value = DecoyListResponse(items: SyntheticScreens.decoys)
        case .scoutStatus:
            value = ScoutStatusResponse(enabled: true, isRunning: false, lifecycleBusy: false,
                lastScoutAt: SyntheticScreens.timestamp, lastScoutDurationMs: 3400,
                totalProfiles: 3, intervalMinutes: 60, activeMimics: 1, maxMimics: 5,
                fakeHostCount: 1, serviceDecoyCount: 1)
        case .scoutProfiles:
            value = [
                ServiceProfileSummary(id: 1, deviceId: 1, ipAddress: "192.168.50.10", port: 22,
                    protocol_: "tcp", serviceName: "SSH", httpStatus: nil, httpServerHeader: nil,
                    tlsCn: nil, protocolVersion: "OpenSSH", scoutedAt: SyntheticScreens.timestamp),
                ServiceProfileSummary(id: 2, deviceId: 5, ipAddress: "192.168.50.50", port: 80,
                    protocol_: "tcp", serviceName: "NAS Admin", httpStatus: 200, httpServerHeader: "nginx",
                    tlsCn: nil, protocolVersion: "HTTP/1.1", scoutedAt: SyntheticScreens.timestamp),
                ServiceProfileSummary(id: 3, deviceId: 5, ipAddress: "192.168.50.50", port: 445,
                    protocol_: "tcp", serviceName: "SMB", httpStatus: nil, httpServerHeader: nil,
                    tlsCn: nil, protocolVersion: "SMB3", scoutedAt: SyntheticScreens.timestamp),
            ]
        case .mimicDecoys:
            value = [MimicDecoySummary(id: 9, name: "Archive NAS", bindAddress: "192.168.50.250",
                port: 80, status: "active", sourceDeviceId: 5, deviceCategory: "server",
                connectionCount: 0, createdAt: SyntheticScreens.timestamp, hostId: 41,
                hostname: "archive-nas.local", serviceProtocol: "http", serviceName: "NAS Admin")]
        case .config:
            value = ["profile": AnyCodableValue.string("standard"),
                "classifier": .object(["llm_provider": .string("ollama"),
                    "llm_endpoint": .string("http://127.0.0.1:11434"), "llm_model": .string("local-model")]),
                "credential_filename": .string("team-passwords.txt")]
        default:
            // Fail visibly instead of falling back to a real sensor.
            throw SensorClientError.connectionFailed("Synthetic screenshot fixture: unsupported \(endpoint.path)")
        }
        return try JSONDecoder().decode(T.self, from: JSONEncoder().encode(value))
    }

    func request(_ endpoint: Endpoint) async throws {
        throw SensorClientError.connectionFailed("Synthetic screenshots do not allow writes")
    }
}

@MainActor
private final class CaptureDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        Task { @MainActor in
            do {
                try await capture()
                NSApp.terminate(nil)
            } catch {
                print("Screenshot capture failed: \(error)")
                exit(1)
            }
        }
    }

    private func capture() async throws {
        guard CommandLine.arguments.count == 2 else {
            throw CocoaError(.fileNoSuchFile)
        }
        let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        FontRegistration.registerAllFonts()
        guard NSFont(name: "SpaceGrotesk-Medium", size: 16) != nil,
              NSFont(name: "SpaceMono-Regular", size: 12) != nil else {
            throw CocoaError(.fileReadNoSuchFile)
        }
        let screens: [(String, DashboardSection, Bool)] = [
            ("dashboard", .dashboard, false), ("devices", .devices, false),
            ("alerts", .alerts, false), ("decoys", .decoys, false),
            ("scouts", .scouts, false), ("settings", .settings, false),
            ("alert", .dashboard, true),
        ]
        for (name, section, modal) in screens {
            let state = try SyntheticScreens.state()
            state.selectedDashboardSection = section
            let root = ZStack {
                DashboardView(appState: state)
                if modal { CriticalAlertModal(appState: state) }
            }
            .environment(\.colorScheme, .light)
            .frame(width: 1280, height: 800)
            let controller = NSHostingController(rootView: root)
            let window = NSWindow(contentViewController: controller)
            window.styleMask = [.titled, .closable, .miniaturizable, .resizable]
            window.isReleasedWhenClosed = false
            window.title = "SquirrelOps Home"
            window.appearance = NSAppearance(named: .aqua)
            window.setContentSize(NSSize(width: 1280, height: 800))
            window.center()
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            try await Task.sleep(for: .seconds(1))
            controller.view.layoutSubtreeIfNeeded()
            let path = output.appendingPathComponent("squirrelops-\(name)-2.1-synthetic.png")
            guard !FileManager.default.fileExists(atPath: path.path) else {
                throw CocoaError(.fileWriteFileExists)
            }
            let capture = Process()
            capture.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
            capture.arguments = ["-x", "-o", "-l", String(window.windowNumber), path.path]
            try capture.run()
            capture.waitUntilExit()
            guard capture.terminationStatus == 0,
                  let image = NSImage(contentsOf: path), image.size.width > 1000 else {
                throw CocoaError(.fileReadCorruptFile)
            }
            print("Captured synthetic \(name): \(path.lastPathComponent)")
            window.close()
        }
    }
}

@main
enum ScreenshotApp {
    @MainActor static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        let delegate = CaptureDelegate()
        app.delegate = delegate
        withExtendedLifetime(delegate) { app.run() }
    }
}
