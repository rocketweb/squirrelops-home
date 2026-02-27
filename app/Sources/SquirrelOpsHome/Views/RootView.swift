import SwiftUI

/// Root content view that switches between setup flow and main dashboard.
struct RootView: View {
    let appState: AppState
    let pairingManager: PairingManager
    var onPaired: ((PairingManager.PairedSensor) -> Void)?

    var body: some View {
        if appState.isPaired {
            ZStack {
                DashboardView(appState: appState)
                if appState.hasCriticalAlert {
                    CriticalAlertModal(appState: appState)
                }
            }
        } else {
            SetupFlow(pairingManager: pairingManager) { sensor in
                onPaired?(sensor)
            }
        }
    }
}
