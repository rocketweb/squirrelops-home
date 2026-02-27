import SwiftUI

/// Content view displayed in the menu bar popover window.
public struct MenuBarView: View {
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.openWindow) private var openWindow

    let appState: AppState

    public init(appState: AppState) {
        self.appState = appState
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            statusLine
            Divider()
            alertCountsSection
            Spacer()
            actionButtons
        }
        .padding(Spacing.md)
        .frame(width: 320)
        .background(Theme.background(colorScheme))
    }

    // MARK: - Status Line

    @ViewBuilder
    private var statusLine: some View {
        HStack(spacing: Spacing.sm) {
            statusDot
            Text(statusText)
                .font(Typography.body)
                .foregroundStyle(Theme.textPrimary(colorScheme))
        }
    }

    private var statusDot: some View {
        Circle()
            .fill(statusDotColor)
            .frame(width: 8, height: 8)
    }

    private var statusDotColor: Color {
        switch appState.menuBarStatus {
        case .connected:
            return Theme.statusSuccess(colorScheme)
        case .alertsPresent:
            return Theme.statusWarning(colorScheme)
        case .criticalAlert:
            return Theme.statusError(colorScheme)
        case .disconnected:
            return Theme.textTertiary(colorScheme)
        }
    }

    private var statusText: String {
        switch appState.menuBarStatus {
        case .connected:
            return "Monitoring Active"
        case .alertsPresent:
            let count = appState.alerts.filter { $0.readAt == nil }.count
            return "\(count) Unread Alert\(count == 1 ? "" : "s")"
        case .criticalAlert:
            return "Critical Alert Active"
        case .disconnected:
            return "Sensor Disconnected"
        }
    }

    // MARK: - Alert Counts

    @ViewBuilder
    private var alertCountsSection: some View {
        let counts = appState.unreadAlertCounts
        if !counts.isEmpty {
            VStack(alignment: .leading, spacing: Spacing.xs) {
                Text("UNREAD ALERTS")
                    .font(Typography.caption)
                    .foregroundStyle(Theme.textTertiary(colorScheme))
                    .textCase(.uppercase)

                ForEach(sortedSeverities(counts), id: \.key) { severity, count in
                    HStack {
                        Circle()
                            .fill(severityColor(severity))
                            .frame(width: 6, height: 6)
                        Text(severity.capitalized)
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textSecondary(colorScheme))
                        Spacer()
                        Text("\(count)")
                            .font(Typography.mono)
                            .foregroundStyle(Theme.textPrimary(colorScheme))
                    }
                }
            }
        }
    }

    private func sortedSeverities(_ counts: [String: Int]) -> [(key: String, value: Int)] {
        let order = ["critical", "high", "medium", "low"]
        return counts.sorted { a, b in
            let aIndex = order.firstIndex(of: a.key) ?? order.count
            let bIndex = order.firstIndex(of: b.key) ?? order.count
            return aIndex < bIndex
        }
    }

    private func severityColor(_ severity: String) -> Color {
        switch severity {
        case "critical":
            return Theme.statusError(colorScheme)
        case "high":
            return Color(red: 249.0 / 255.0, green: 115.0 / 255.0, blue: 22.0 / 255.0)
        case "medium":
            return Theme.statusWarning(colorScheme)
        case "low":
            return Theme.statusInfo(colorScheme)
        default:
            return Theme.textTertiary(colorScheme)
        }
    }

    // MARK: - Action Buttons

    private var actionButtons: some View {
        VStack(spacing: Spacing.xs) {
            Divider()

            Button {
                if appState.isSilenced {
                    appState.silenceUntil = nil
                } else {
                    appState.silenceUntil = Date().addingTimeInterval(3600)
                }
            } label: {
                HStack {
                    Image(systemName: appState.isSilenced ? "bell" : "bell.slash")
                    Text(appState.isSilenced ? "Resume Alerts" : "Silence for 1 Hour")
                        .font(Typography.bodySmall)
                    Spacer()
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(Theme.textPrimary(colorScheme))
            .padding(.vertical, Spacing.xs)

            Divider()

            Button {
                openWindow(id: "main")
            } label: {
                HStack {
                    Image(systemName: "macwindow")
                    Text("Open Dashboard")
                        .font(Typography.bodySmall)
                    Spacer()
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(Theme.textPrimary(colorScheme))
            .padding(.vertical, Spacing.xs)

            Divider()

            Button {
                NSApp.terminate(nil)
            } label: {
                HStack {
                    Image(systemName: "power")
                    Text("Quit SquirrelOps")
                        .font(Typography.bodySmall)
                    Spacer()
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(Theme.textSecondary(colorScheme))
            .padding(.vertical, Spacing.xs)
        }
    }
}
