import AppKit
import Foundation
@preconcurrency import UserNotifications

enum MacNotificationPreferences {
    static let enabledKey = "macNotificationsEnabled"
    static let minimumSeverityKey = "macNotificationsMinimumSeverity"
}

enum MacNotificationPolicy {
    static func shouldNotify(
        _ alert: AlertSummary,
        enabled: Bool,
        minimumSeverity: String,
        isSilenced: Bool
    ) -> Bool {
        guard enabled, !isSilenced, alert.readAt == nil else { return false }
        return severityRank(alert.severity) >= severityRank(minimumSeverity)
    }

    private static func severityRank(_ severity: String) -> Int {
        switch severity.lowercased() {
        case "critical": return 3
        case "high": return 2
        case "medium": return 1
        default: return 0
        }
    }
}

final class MacNotificationDelegate: NSObject, UNUserNotificationCenterDelegate,
    @unchecked Sendable
{
    var onOpenAlerts: (@MainActor @Sendable () -> Void)?

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler:
            @escaping @Sendable (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping @Sendable () -> Void
    ) {
        Task { @MainActor [weak self] in
            self?.onOpenAlerts?()
            completionHandler()
        }
    }
}

@MainActor
final class MacNotificationService {
    static let shared = MacNotificationService()

    private let center: UNUserNotificationCenter
    private let defaults: UserDefaults
    private let delegate = MacNotificationDelegate()

    var onOpenAlerts: (@MainActor @Sendable () -> Void)? {
        didSet { delegate.onOpenAlerts = onOpenAlerts }
    }

    init(
        center: UNUserNotificationCenter = .current(),
        defaults: UserDefaults = .standard
    ) {
        self.center = center
        self.defaults = defaults
        center.delegate = delegate
        defaults.register(defaults: [
            MacNotificationPreferences.enabledKey: true,
            MacNotificationPreferences.minimumSeverityKey: "low",
        ])
    }

    var isEnabled: Bool {
        defaults.bool(forKey: MacNotificationPreferences.enabledKey)
    }

    var minimumSeverity: String {
        defaults.string(forKey: MacNotificationPreferences.minimumSeverityKey) ?? "low"
    }

    func start() async {
        center.delegate = delegate
        guard isEnabled else { return }
        _ = try? await center.requestAuthorization(options: [.alert, .sound])
    }

    func updatePreferences(enabled: Bool, minimumSeverity: String) async {
        defaults.set(enabled, forKey: MacNotificationPreferences.enabledKey)
        defaults.set(
            minimumSeverity,
            forKey: MacNotificationPreferences.minimumSeverityKey
        )
        guard enabled else { return }
        _ = try? await center.requestAuthorization(options: [.alert, .sound])
    }

    func deliver(_ alerts: [AlertSummary], isSilenced: Bool) async {
        for alert in alerts where MacNotificationPolicy.shouldNotify(
            alert,
            enabled: isEnabled,
            minimumSeverity: minimumSeverity,
            isSilenced: isSilenced
        ) {
            let content = UNMutableNotificationContent()
            content.title = notificationTitle(for: alert)
            content.body = notificationBody(for: alert)
            content.sound = .default
            content.userInfo = ["alert_id": alert.id]

            let request = UNNotificationRequest(
                identifier: "squirrelops.alert.\(alert.id).\(alert.alertCount ?? 1)",
                content: content,
                trigger: nil
            )
            try? await center.add(request)
        }
    }

    private func notificationTitle(for alert: AlertSummary) -> String {
        "SquirrelOps \(alert.severity.capitalized) Alert"
    }

    private func notificationBody(for alert: AlertSummary) -> String {
        guard let sourceIp = alert.sourceIp, !sourceIp.isEmpty else {
            return alert.title
        }
        return "\(alert.title) • \(sourceIp)"
    }
}
