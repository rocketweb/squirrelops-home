import SwiftUI

extension DashboardSection {
    var icon: String {
        switch self {
        case .dashboard: return "square.grid.2x2"
        case .devices: return "desktopcomputer"
        case .alerts: return "bell"
        case .decoys: return "ant"
        case .scouts: return "binoculars"
        case .settings: return "gearshape"
        }
    }
}

struct DashboardView: View {
    @Environment(\.colorScheme) private var colorScheme
    @Bindable var appState: AppState

    var body: some View {
        VStack(spacing: 0) {
            if appState.connectionState == .authFailed {
                repairBanner
            }
            NavigationSplitView {
                sidebar
            } detail: {
                detailView
            }
        }
    }

    private var repairBanner: some View {
        HStack(spacing: Spacing.md) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.black)
            Text("Connection to \(appState.pairedSensor?.name ?? "sensor") lost. Sensor was reset or pairing expired.")
                .font(Typography.body)
                .foregroundStyle(.black)
            Spacer()
            Button("Re-pair") {
                appState.onRepairRequested?()
            }
            .buttonStyle(.borderedProminent)
            .tint(.black.opacity(0.2))
            .foregroundStyle(.black)
        }
        .padding(.horizontal, Spacing.lg)
        .padding(.vertical, Spacing.sm)
        .background(Color.orange)
    }

    private var sidebar: some View {
        List(
            DashboardSection.allCases,
            id: \.self,
            selection: $appState.selectedDashboardSection
        ) { item in
            Label {
                Text(item.rawValue)
                    .font(Typography.body)
            } icon: {
                Image(systemName: item.icon)
            }
            .badge(badgeCount(for: item))
        }
        .listStyle(.sidebar)
        .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 240)
    }

    @ViewBuilder
    private var detailView: some View {
        switch appState.selectedDashboardSection {
        case .dashboard:
            DashboardHome(appState: appState)
        case .devices:
            DeviceInventoryView(appState: appState)
        case .alerts:
            AlertFeedView(appState: appState)
        case .decoys:
            DecoyStatusView(appState: appState)
        case .scouts:
            SquirrelScoutsView(appState: appState)
        case .settings:
            SettingsView(appState: appState)
        case nil:
            DashboardHome(appState: appState)
        }
    }

    private func badgeCount(for item: DashboardSection) -> Int {
        switch item {
        case .alerts:
            return appState.alerts.filter { $0.readAt == nil }.count
        default:
            return 0
        }
    }
}
