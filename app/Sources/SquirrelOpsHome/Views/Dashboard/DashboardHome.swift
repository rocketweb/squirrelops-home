import SwiftUI

struct DashboardHome: View {
    let appState: AppState
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                SystemHealthView(appState: appState)

                VStack(alignment: .leading, spacing: Spacing.sm) {
                    Text("NETWORK MAP")
                        .font(Typography.caption)
                        .tracking(Typography.captionTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))

                    NetworkMapView(devices: appState.devices)
                }
            }
            .padding(Spacing.lg)
        }
        .background(Theme.background(colorScheme))
    }
}
