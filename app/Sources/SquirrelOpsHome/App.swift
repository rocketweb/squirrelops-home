import AppKit
import SwiftUI

@main
struct SquirrelOpsHomeApp: App {
    @State private var appState = AppState()
    @State private var connectionService: SensorConnectionService?
    @State private var pairingManager = PairingManager(
        client: SensorClient(baseURL: URL(string: "https://localhost")!, certFingerprint: "", caCertData: nil)
    )
    @AppStorage("appearanceMode") private var appearanceMode: String = "system"

    init() {
        FontRegistration.registerAllFonts()
        HelperManager.installIfNeeded()
    }

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(appState: appState)
        } label: {
            MenuBarIcon(status: appState.menuBarStatus)
        }
        .menuBarExtraStyle(.window)

        Window("SquirrelOps Home", id: "main") {
            RootView(
                appState: appState,
                pairingManager: pairingManager,
                onPaired: { sensor in
                    connectToSensor(sensor)
                }
            )
            .preferredColorScheme(AppearanceMode.resolvedColorScheme(for: appearanceMode))
            .onAppear {
                NSApp.setActivationPolicy(.regular)
                NSApp.activate(ignoringOtherApps: true)
            }
            .task {
                // Wire up repair action for auth-failed banner
                appState.onRepairRequested = { [weak appState] in
                    guard let appState else { return }
                    connectionService?.disconnect()
                    connectionService = nil
                    // Clear persisted pairing from Keychain
                    try? PairingManager.deletePairedSensor()
                    appState.pairedSensor = nil
                    appState.connectionState = .disconnected
                    appState.sensorClient = nil
                }

                // Load persisted pairing from Keychain if not already set
                if appState.pairedSensor == nil {
                    appState.pairedSensor = PairingManager.loadPairedSensor()
                }
                if let sensor = appState.pairedSensor {
                    connectToSensor(sensor)
                }
            }
        }
        .defaultSize(width: 1080, height: 720)
    }

    private func connectToSensor(_ sensor: PairingManager.PairedSensor) {
        appState.pairedSensor = sensor

        // Use TOFU mode for TLS (sensor's server cert is self-signed, not
        // signed by the pairing CA). Safe for local-network communication.
        let client = SensorClient(
            baseURL: sensor.baseURL,
            certFingerprint: sensor.certFingerprint,
            caCertData: nil
        )
        appState.sensorClient = client
        // WebSocket requires wss:// scheme instead of https://
        var wsComponents = URLComponents(url: sensor.baseURL.appendingPathComponent("ws/events"), resolvingAgainstBaseURL: false)!
        wsComponents.scheme = "wss"
        let wsURL = wsComponents.url!
        let wsDelegate = TLSPinningDelegate(caCertData: nil)
        let wsSession = URLSession(configuration: .default, delegate: wsDelegate, delegateQueue: nil)
        let wsManager = WebSocketManager(url: wsURL, session: wsSession)

        let service = SensorConnectionService(
            sensorClient: client,
            webSocketManager: wsManager,
            appState: appState,
            onEvent: { [appState] frame in
                Task { @MainActor in
                    WSEventProcessor.process(frame, into: appState)
                }
            }
        )
        connectionService = service

        Task {
            await service.connect(
                baseURL: sensor.baseURL,
                certFingerprint: sensor.certFingerprint
            )
        }
    }
}
