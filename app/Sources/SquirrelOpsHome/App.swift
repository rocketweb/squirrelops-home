import AppKit
import Security
import SwiftUI

@main
struct SquirrelOpsHomeApp: App {
    @State private var appState = AppState()
    @State private var connectionService: SensorConnectionService?
    @State private var pairingManager = PairingManager(
        client: SensorClient(
            pairingBaseURL: URL(string: "https://localhost")!
        )
    )
    @AppStorage("appearanceMode") private var appearanceMode: String = "system"
    private let notificationService = MacNotificationService.shared

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
                notificationService.onOpenAlerts = { [appState] in
                    appState.selectedDashboardSection = .alerts
                    WindowActivationController.present(.dashboard) {}
                }
                appState.onAlertNotificationsRequested = {
                    [notificationService, appState] alerts in
                    Task { @MainActor in
                        await notificationService.deliver(
                            alerts,
                            isSilenced: appState.isSilenced
                        )
                    }
                }
                await notificationService.start()

                // Wire up repair action for auth-failed banner
                appState.onRepairRequested = { [weak appState] in
                    guard let appState else { return }
                    connectionService?.disconnect()
                    connectionService = nil
                    let pairedSensor = appState.pairedSensor
                    // Clear persisted pairing from Keychain
                    if let pairedSensor {
                        try? PairingManager.deleteStoredCredentials(for: pairedSensor)
                    } else {
                        try? PairingManager.deletePairedSensor()
                    }
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
        .commands {
            SquirrelOpsHelpCommands()
        }

        Window("SquirrelOps Home Help", id: AppWindow.help.rawValue) {
            HelpGuideView()
                .onAppear {
                    NSApp.setActivationPolicy(.regular)
                    NSApp.activate(ignoringOtherApps: true)
                }
        }
        .defaultSize(width: 980, height: 720)
    }

    private func connectToSensor(_ sensor: PairingManager.PairedSensor) {
        appState.pairedSensor = sensor

        let caCertData: Data
        let clientIdentity: SecIdentity
        do {
            caCertData = try PairingManager.loadCACertificateData(for: sensor)
            clientIdentity = try PairingManager.loadClientIdentity(for: sensor)
        } catch {
            // Missing or unreadable paired credentials are an authentication
            // failure. Never reinterpret them as pairing-time TOFU.
            appState.sensorClient = nil
            appState.connectionState = .authFailed
            return
        }

        let client = SensorClient(
            baseURL: sensor.baseURL,
            certFingerprint: sensor.certFingerprint,
            caCertData: caCertData,
            clientIdentity: clientIdentity
        )
        appState.sensorClient = client
        // WebSocket requires wss:// scheme instead of https://
        var wsComponents = URLComponents(url: sensor.baseURL.appendingPathComponent("ws/events"), resolvingAgainstBaseURL: false)!
        wsComponents.scheme = "wss"
        let wsURL = wsComponents.url!
        let wsDelegate = TLSPinningDelegate(
            serverTrustMode: .pinnedCA(caCertData),
            clientIdentity: clientIdentity
        )
        let wsSession = URLSession(configuration: .default, delegate: wsDelegate, delegateQueue: nil)
        let wsManager = WebSocketManager(url: wsURL, session: wsSession)

        let service = SensorConnectionService(
            sensorClient: client,
            webSocketManager: wsManager,
            appState: appState,
            localSensorProbe: { [pairingManager] in
                await pairingManager.detectLocalSensor() != nil
            },
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
