import SwiftUI

/// Full-screen modal overlay for critical/high-severity alerts.
///
/// Displays the first unsuppressed critical/high alert. Review preserves the
/// complete unread batch and navigates to Alerts; Clear acknowledges only the
/// batch represented by this modal.
struct CriticalAlertModal: View {
    let appState: AppState
    @Environment(\.colorScheme) private var colorScheme

    private var alert: AlertSummary? {
        appState.firstCriticalAlert
    }

    private var presentedAlerts: [AlertSummary] {
        appState.presentedCriticalAlerts
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

                    // Source info: device count for grouped, IP for single
                    if alert.issueKey != nil, let count = alert.deviceCount, count > 0 {
                        Text("Affecting \(count) device\(count == 1 ? "" : "s")")
                            .font(Typography.body)
                            .foregroundStyle(Theme.textSecondary(colorScheme))
                    } else if let sourceIp = alert.sourceIp {
                        Text(sourceIp)
                            .font(Typography.mono)
                            .tracking(Typography.monoTracking)
                            .foregroundStyle(Theme.textSecondary(colorScheme))
                    }

                    // Timestamp
                    Text(TimestampPresentation.local(alert.createdAt))
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))

                    // Remaining count
                    let remaining = presentedAlerts.count
                    if remaining > 1 {
                        Text("\(remaining) unread alerts")
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textSecondary(colorScheme))
                    }

                    Spacer().frame(height: Spacing.sm)

                    // Buttons
                    VStack(spacing: Spacing.s12) {
                        Button {
                            appState.reviewPresentedCriticalAlerts()
                        } label: {
                            Text("Review")
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
                            clearPresentedAlerts()
                        } label: {
                            Text("Clear")
                                .font(Typography.bodySmall)
                                .foregroundStyle(Theme.statusError(colorScheme))
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

    private func clearPresentedAlerts() {
        let alertIds = appState.clearPresentedCriticalAlerts()
        Task {
            for alertId in alertIds {
                try? await appState.sensorClient?.request(.readAlert(id: alertId))
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
