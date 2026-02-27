import SwiftUI

struct SystemHealthView: View {
    @Environment(\.colorScheme) private var colorScheme
    let appState: AppState

    private var connectionDotColor: Color {
        switch appState.connectionState {
        case .live:
            return Theme.statusSuccess(colorScheme)
        case .connected, .syncing:
            return Theme.statusWarning(colorScheme)
        case .connecting:
            return Theme.statusInfo(colorScheme)
        case .disconnected:
            return Theme.textTertiary(colorScheme)
        case .authFailed:
            return Theme.statusWarning(colorScheme)
        }
    }

    private var connectionLabel: String {
        switch appState.connectionState {
        case .live: return "Live"
        case .connected: return "Connected"
        case .syncing: return "Syncing"
        case .connecting: return "Connecting"
        case .disconnected: return "Disconnected"
        case .authFailed: return "Auth Failed"
        }
    }

    private var profileLabel: String {
        appState.systemStatus?.profile.capitalized ?? "Unknown"
    }

    private var unreadAlertCount: Int {
        appState.alerts.filter { $0.readAt == nil }.count
    }

    private var formattedUptime: String {
        guard let uptime = appState.sensorInfo?.uptimeSeconds else { return "--" }
        let totalSeconds = Int(uptime)
        let days = totalSeconds / 86400
        let hours = (totalSeconds % 86400) / 3600
        let minutes = (totalSeconds % 3600) / 60

        if days > 0 {
            return "\(days)d \(hours)h"
        } else {
            return "\(hours)h \(minutes)m"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            // MARK: - Connection Status Row
            HStack(spacing: Spacing.sm) {
                Circle()
                    .fill(connectionDotColor)
                    .frame(width: 10, height: 10)

                Text(connectionLabel)
                    .font(Typography.body)
                    .foregroundStyle(Theme.textPrimary(colorScheme))

                Spacer()

                StatusBadge(label: profileLabel, style: .active)
            }

            // MARK: - Metrics Row
            HStack(spacing: Spacing.md) {
                MetricCard(
                    title: "Devices",
                    value: "\(appState.devices.count)",
                    icon: "desktopcomputer"
                )
                MetricCard(
                    title: "Decoys",
                    value: "\(appState.decoys.count)",
                    icon: "ant"
                )
                MetricCard(
                    title: "Unread Alerts",
                    value: "\(unreadAlertCount)",
                    icon: "bell.badge"
                )
            }

            // MARK: - Learning Progress
            if appState.systemStatus?.learningMode == true {
                VStack(alignment: .leading, spacing: Spacing.sm) {
                    Text("LEARNING MODE")
                        .font(Typography.caption)
                        .tracking(Typography.captionTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))

                    ProgressView(value: learningProgress, total: 1.0)
                        .tint(Theme.statusInfo(colorScheme))

                    Text(learningEstimateText)
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                }
                .padding(Spacing.md)
                .background(Theme.backgroundSecondary(colorScheme))
                .cornerRadius(Spacing.radiusLg)
            }

            // MARK: - Sensor Info
            if appState.sensorInfo != nil {
                VStack(alignment: .leading, spacing: Spacing.sm) {
                    Text("SENSOR")
                        .font(Typography.caption)
                        .tracking(Typography.captionTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))

                    HStack(spacing: Spacing.lg) {
                        VStack(alignment: .leading, spacing: Spacing.xs) {
                            Text("Version")
                                .font(Typography.bodySmall)
                                .foregroundStyle(Theme.textSecondary(colorScheme))
                            Text(appState.sensorInfo?.version ?? "--")
                                .font(Typography.mono)
                                .tracking(Typography.monoTracking)
                                .foregroundStyle(Theme.textPrimary(colorScheme))
                        }

                        VStack(alignment: .leading, spacing: Spacing.xs) {
                            Text("Uptime")
                                .font(Typography.bodySmall)
                                .foregroundStyle(Theme.textSecondary(colorScheme))
                            Text(formattedUptime)
                                .font(Typography.mono)
                                .tracking(Typography.monoTracking)
                                .foregroundStyle(Theme.textPrimary(colorScheme))
                        }
                    }
                }
                .padding(Spacing.md)
                .background(Theme.backgroundSecondary(colorScheme))
                .cornerRadius(Spacing.radiusLg)
            }
        }
    }

    // MARK: - Learning Helpers

    private var learningProgress: Double {
        guard let learning = appState.learningStatus, learning.hoursTotal > 0 else {
            return 0.0
        }
        return min(learning.hoursElapsed / Double(learning.hoursTotal), 1.0)
    }

    private var learningEstimateText: String {
        guard let learning = appState.learningStatus else {
            return "Establishing network baseline..."
        }
        let remaining = max(Double(learning.hoursTotal) - learning.hoursElapsed, 0)
        if remaining < 1 {
            let minutes = Int(remaining * 60)
            return "\(minutes)m remaining"
        }
        return "\(Int(remaining))h remaining"
    }
}
