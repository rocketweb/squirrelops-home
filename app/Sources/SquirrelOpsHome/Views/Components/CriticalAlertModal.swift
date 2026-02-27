import SwiftUI

/// Full-screen modal overlay for critical/high-severity alerts.
///
/// Shown when `appState.hasCriticalAlert` is true. Displays the first unread
/// critical/high alert and requires user acknowledgment before dismissing.
/// If multiple are queued, shows a count and offers "Dismiss All".
struct CriticalAlertModal: View {
    let appState: AppState
    @Environment(\.colorScheme) private var colorScheme

    private var alert: AlertSummary? {
        appState.firstCriticalAlert
    }

    private var unreadCriticalAlerts: [AlertSummary] {
        appState.alerts.filter { $0.readAt == nil && ($0.severity == "critical" || $0.severity == "high") }
    }

    var body: some View {
        if let alert {
            ZStack {
                // Backdrop
                Theme.accentMuted(colorScheme)
                    .opacity(0.85)
                    .ignoresSafeArea()

                // Card
                VStack(spacing: Spacing.lg) {
                    // Severity icon
                    Image(systemName: alertIcon(for: alert.alertType))
                        .font(.system(size: 40))
                        .foregroundStyle(Theme.statusError(colorScheme))

                    // Severity label
                    Text(alert.severity.uppercased())
                        .font(Typography.caption)
                        .tracking(Typography.captionTracking)
                        .foregroundStyle(Theme.statusError(colorScheme))

                    // Title
                    Text(alert.title)
                        .font(Typography.h3)
                        .tracking(Typography.h3Tracking)
                        .foregroundStyle(Theme.textPrimary(colorScheme))
                        .multilineTextAlignment(.center)

                    // Source IP
                    if let sourceIp = alert.sourceIp {
                        Text(sourceIp)
                            .font(Typography.mono)
                            .tracking(Typography.monoTracking)
                            .foregroundStyle(Theme.textSecondary(colorScheme))
                    }

                    // Timestamp
                    Text(alert.createdAt)
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))

                    // Remaining count
                    let remaining = unreadCriticalAlerts.count
                    if remaining > 1 {
                        Text("\(remaining) unread alerts")
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textSecondary(colorScheme))
                    }

                    Spacer().frame(height: Spacing.sm)

                    // Buttons
                    VStack(spacing: Spacing.s12) {
                        Button {
                            acknowledgeAll()
                        } label: {
                            Text(remaining > 1 ? "Dismiss All (\(remaining))" : "Acknowledge")
                                .font(Typography.body)
                                .foregroundStyle(.white)
                                .frame(minWidth: 200)
                                .padding(.vertical, Spacing.s12)
                                .padding(.horizontal, Spacing.xl)
                                .background(Theme.accentDefault(colorScheme))
                                .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
                        }
                        .buttonStyle(.plain)

                        Button {
                            appState.silenceUntil = Calendar.current.date(byAdding: .hour, value: 1, to: Date())
                        } label: {
                            Text("Later")
                                .font(Typography.bodySmall)
                                .foregroundStyle(Theme.textSecondary(colorScheme))
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(Spacing.xl)
                .frame(maxWidth: 420)
                .background(Theme.backgroundElevated(colorScheme))
                .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusLg))
                .overlay(
                    RoundedRectangle(cornerRadius: Spacing.radiusLg)
                        .stroke(Theme.statusError(colorScheme).opacity(0.3), lineWidth: 1)
                )
                .shadow(color: Theme.statusError(colorScheme).opacity(0.2), radius: 20)
            }
        }
    }

    // MARK: - Actions

    private func acknowledge(_ alert: AlertSummary) {
        appState.markAlertRead(alert.id)
        Task {
            try? await appState.sensorClient?.request(.readAlert(id: alert.id))
        }
    }

    private func acknowledgeAll() {
        let alerts = unreadCriticalAlerts
        for alert in alerts {
            appState.markAlertRead(alert.id)
        }
        Task {
            for alert in alerts {
                try? await appState.sensorClient?.request(.readAlert(id: alert.id))
            }
        }
    }

    // MARK: - Helpers

    private func alertIcon(for alertType: String) -> String {
        switch alertType {
        case "decoy.trip", "decoy.credential_trip":
            return "exclamationmark.shield.fill"
        case "device.new", "device.verification_needed":
            return "desktopcomputer.trianglebadge.exclamationmark"
        case "device.mac_changed":
            return "exclamationmark.triangle.fill"
        case "system.sensor_offline":
            return "wifi.exclamationmark"
        default:
            return "exclamationmark.octagon.fill"
        }
    }
}
