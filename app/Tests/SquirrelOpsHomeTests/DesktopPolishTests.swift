import AppKit
import SwiftUI
import Testing

@testable import SquirrelOpsHome

/// An offline rendering fixture. No pairing, Keychain access or live sensor requests.
private final class DesktopPreviewClient: SensorClientProtocol, Sendable {
    func request<T: Decodable>(_ endpoint: Endpoint) async throws -> T {
        let value: any Encodable
        switch endpoint.path {
        case "/system/health": value = PreviewData.health
        case "/system/status": value = PreviewData.status
        case "/decoys": value = DecoyListResponse(items: PreviewData.decoys)
        case "/system/profile":
            value = ResourceProfileResponse(profile: "standard", scanIntervalSeconds: 300,
                maxDecoys: 8, llmClassification: "cloud_llm", scoutIntervalMinutes: 60,
                maxMimicDecoys: 10, maxVirtualIPs: 10, totalDecoyCapacity: 18)
        case "/scouts/status":
            value = ScoutStatusResponse(enabled: true, isRunning: false, lifecycleBusy: false,
                lastScoutAt: "2026-09-26T07:00:00Z", lastScoutDurationMs: 3400,
                totalProfiles: 12, intervalMinutes: 60, activeMimics: 10, maxMimics: 10,
                fakeHostCount: 10, serviceDecoyCount: 35)
        case "/scouts/mimics":
            value = [MimicDecoySummary(id: 99, name: "Build archives", bindAddress: "192.168.1.203",
                port: 445, status: "active", connectionCount: 12, createdAt: "2026-09-25T07:00:00Z",
                hostname: "engineering-build-archive-workstation.local", serviceProtocol: "smb",
                serviceName: "SMB")]
        case "/scouts/profiles":
            value = [ServiceProfileSummary(id: 1, deviceId: 1, ipAddress: "192.168.1.10", port: 22,
                protocol_: "tcp", serviceName: "SSH", httpStatus: nil, httpServerHeader: nil,
                tlsCn: nil, protocolVersion: "OpenSSH", scoutedAt: "2026-09-26T07:00:00Z")]
        case "/config":
            value = ["profile": AnyCodableValue.string("standard")]
        case "/alerts/1":
            value = AlertDetail(id: 1, incidentId: nil, alertType: "decoy.trip", severity: "high",
                title: "SMB file access on engineering-build-archive-workstation.local",
                detail: .object(["path": .string("Engineering/Release archives/2.1/Test credentials.txt")]),
                sourceIp: "192.168.1.7", sourceMac: nil, deviceId: nil, decoyId: nil,
                readAt: nil, actionedAt: nil, actionNote: nil, createdAt: "2026-09-26T07:00:00Z")
        default: throw SensorClientError.connectionFailed("Offline UI fixture: unsupported \(endpoint.path)")
        }
        return try JSONDecoder().decode(T.self, from: JSONEncoder().encode(value))
    }

    func request(_ endpoint: Endpoint) async throws {
        throw SensorClientError.connectionFailed("Offline UI fixture does not allow writes")
    }
}

@Suite("Desktop polish", .serialized)
struct DesktopPolishTests {
    @Test("Foreground fixture uses the same decoy list envelope as the sensor")
    func fixtureDecoyResponse() async throws {
        let response: DecoyListResponse = try await DesktopPreviewClient().request(.decoys)
        #expect(response.items == PreviewData.decoys)
    }

    @Test("Secondary and status text remains readable on grouped surfaces")
    func textContrast() throws {
        for scheme in [ColorScheme.light, .dark] {
            for background in [Theme.background(scheme), Theme.backgroundSecondary(scheme), Theme.backgroundTertiary(scheme)] {
                for foreground in [Theme.textTertiary(scheme), Theme.accentText(scheme), Theme.statusSuccess(scheme), Theme.statusWarning(scheme), Theme.statusInfo(scheme), Theme.statusError(scheme)] {
                    let ratio = try contrast(foreground, background)
                    #expect(ratio >= 4.5, "\(scheme) text contrast: \(ratio)")
                }
            }
        }
    }

    private func contrast(_ a: Color, _ b: Color) throws -> Double {
        func luminance(_ color: Color) throws -> Double {
            let c = try #require(NSColor(color).usingColorSpace(.sRGB))
            func linear(_ x: Double) -> Double { x <= 0.04045 ? x / 12.92 : pow((x + 0.055) / 1.055, 2.4) }
            return 0.2126 * linear(c.redComponent) + 0.7152 * linear(c.greenComponent) + 0.0722 * linear(c.blueComponent)
        }
        let x = try luminance(a), y = try luminance(b)
        return (max(x, y) + 0.05) / (min(x, y) + 0.05)
    }

    @MainActor
    @Test("Empty, disconnected, long-content and detail views render without live services")
    func edgeStates() async throws {
        FontRegistration.registerAllFonts()
        let output = ProcessInfo.processInfo.environment["SQUIRRELOPS_DESKTOP_UI_OUTPUT"]
        if let output { try FileManager.default.createDirectory(atPath: output, withIntermediateDirectories: true) }
        let populated = PreviewData.populatedAppState()
        populated.sensorClient = DesktopPreviewClient()
        let empty = AppState()
        let longState = AppState()
        longState.devices = [DeviceSummary(id: 1, ipAddress: "192.168.100.200",
            macAddress: "AA:BB:CC:DD:EE:FF", hostname: "engineering-build-archive-workstation.local",
            vendor: "Apple", deviceType: "computer", modelName: nil,
            customName: "Engineering release validation and archive workstation",
            trustStatus: "unknown", isOnline: false,
            firstSeen: "2026-09-26T07:00:00Z", lastSeen: "2026-09-26T07:00:00Z")]
        longState.alerts = [AlertSummary(id: 1, incidentId: nil, alertType: "decoy.trip", severity: "high",
            title: "Repeated SMB file access on engineering-build-archive-workstation.local from an unreviewed device",
            sourceIp: "192.168.100.200", readAt: nil, actionedAt: nil,
            createdAt: "2026-09-26T07:00:00Z", alertCount: 1)]
        let cases: [(String, AnyView)] = [
            ("empty-devices", AnyView(DeviceInventoryView(appState: empty))),
            ("empty-alerts", AnyView(AlertFeedView(appState: empty))),
            ("empty-decoys", AnyView(DecoyStatusView(appState: empty))),
            ("offline-settings", AnyView(SettingsView(appState: empty))),
            ("offline-scouts", AnyView(SquirrelScoutsView(appState: empty))),
            ("offline-alert-detail", AnyView(AlertDetailView(alertId: 1, appState: empty))),
            ("long-devices", AnyView(DeviceInventoryView(appState: longState))),
            ("long-alerts", AnyView(AlertFeedView(appState: longState))),
            ("device-detail", AnyView(DeviceDetailView(deviceId: 1, appState: populated))),
            ("alert-detail", AnyView(AlertDetailView(alertId: 1, appState: populated))),
            ("decoy-detail", AnyView(DecoyDetailSheet(decoy: PreviewData.decoys[0], appState: populated))),
        ]
        for (name, view) in cases {
            let host = NSHostingView(rootView: view.environment(\.colorScheme, .light).frame(width: 560, height: 560))
            host.frame = NSRect(x: 0, y: 0, width: 560, height: 560)
            let window = NSWindow(contentRect: host.frame, styleMask: [.titled, .resizable], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false
            window.contentView = host
            host.layoutSubtreeIfNeeded()
            try await Task.sleep(for: .milliseconds(180))
            host.layoutSubtreeIfNeeded()
            let bitmap = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
            host.cacheDisplay(in: host.bounds, to: bitmap)
            let data = try #require(bitmap.representation(using: .png, properties: [:]))
            #expect(data.count > 10_000)
            if let output { try data.write(to: URL(fileURLWithPath: output).appendingPathComponent("edge-\(name).png")) }
            window.close()
        }
    }

    @MainActor
    @Test("All six screens render at minimum, default and wide window sizes")
    func screenMatrix() async throws {
        let output = ProcessInfo.processInfo.environment["SQUIRRELOPS_DESKTOP_UI_OUTPUT"]
        FontRegistration.registerAllFonts()
        #expect(NSFont(name: "SpaceGrotesk-Medium", size: 16) != nil)
        if let output { try FileManager.default.createDirectory(atPath: output, withIntermediateDirectories: true) }
        for size in [NSSize(width: 800, height: 560), NSSize(width: 1080, height: 720), NSSize(width: 1600, height: 1000)] {
            for section in DashboardSection.allCases {
                for scheme in [ColorScheme.light, .dark] {
                    let state = PreviewData.populatedAppState()
                    state.sensorClient = DesktopPreviewClient()
                    state.selectedDashboardSection = section
                    let root = DashboardView(appState: state)
                        .environment(\.colorScheme, scheme)
                        .frame(width: size.width, height: size.height)
                    let host = NSHostingView(rootView: root)
                    host.frame = NSRect(origin: .zero, size: size)
                    let window = NSWindow(contentRect: host.frame, styleMask: [.titled, .resizable], backing: .buffered, defer: false)
                    window.isReleasedWhenClosed = false
                    window.appearance = NSAppearance(named: scheme == .dark ? .darkAqua : .aqua)
                    window.contentView = host
                    host.layoutSubtreeIfNeeded()
                    try await Task.sleep(for: .milliseconds(180))
                    host.layoutSubtreeIfNeeded()
                    var searchFieldCount = 0
                    func checkSearchFields(_ view: NSView) {
                        if let field = view as? NSTextField,
                           field.placeholderString?.hasPrefix("Search") == true {
                            searchFieldCount += 1
                            let rect = field.convert(field.bounds, to: host)
                            #expect(rect.width >= 160, "\(section): search field is only \(rect.width) points wide")
                            #expect(rect.minX >= 0 && rect.maxX <= size.width, "\(section): search field escapes the window")
                        }
                        view.subviews.forEach(checkSearchFields)
                    }
                    checkSearchFields(host)
                    if section == .devices || section == .alerts { #expect(searchFieldCount > 0) }
                    let bitmap = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
                    host.cacheDisplay(in: host.bounds, to: bitmap)
                    let data = try #require(bitmap.representation(using: .png, properties: [:]))
                    #expect(data.count > 10_000)
                    let filename = "\(section.rawValue.lowercased())-\(Int(size.width))-\(scheme).png"
                    if let output { try data.write(to: URL(fileURLWithPath: output).appendingPathComponent(filename)) }
                    window.close()
                }
            }
        }
    }
}
