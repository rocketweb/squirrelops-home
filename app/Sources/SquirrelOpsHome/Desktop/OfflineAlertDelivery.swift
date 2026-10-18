import Foundation
import os

// The sensor is the normal alert dispatcher. The one alert it can never send
// is "the sensor is gone", so the app delivers that one itself through the
// same Slack webhook the operator configured, formatted the way the sensor
// formats everything else.
//
// The sensor redacts the webhook URL on every configuration response, so the
// only moment the app ever sees it is when the operator types it in Settings.
// `SlackDeliveryCache` keeps that value in the app's Keychain at that moment;
// the non-secret parts (enabled, minimum severity) ride along in defaults and
// are refreshed from every configuration load.

// MARK: - Severity ranking

enum AlertSeverityRank {
    static func rank(_ severity: String) -> Int {
        switch severity.lowercased() {
        case "critical": return 3
        case "high": return 2
        case "medium": return 1
        default: return 0
        }
    }
}

// MARK: - Formatter

/// Mirrors `format_slack_payload` in the sensor so an app-sent message is
/// indistinguishable from a sensor-sent one in the channel.
enum SlackAlertFormatter {
    static func emoji(for severity: String) -> String {
        switch severity.lowercased() {
        case "critical": return "\u{1F534}"
        case "high": return "\u{1F7E0}"
        case "medium": return "\u{1F7E1}"
        default: return "\u{1F535}"
        }
    }

    static func payload(for alert: AlertSummary, detail: String?) -> [String: Any] {
        let severity = alert.severity.lowercased()
        let emoji = emoji(for: severity)
        let upper = severity.uppercased()

        var blocks: [[String: Any]] = [
            [
                "type": "header",
                "text": ["type": "plain_text", "text": "\(emoji) \(alert.title)"],
            ],
            [
                "type": "section",
                "fields": [
                    ["type": "mrkdwn", "text": "*Severity:* \(emoji) \(upper)"],
                    ["type": "mrkdwn", "text": "*Type:* `\(alert.alertType)`"],
                ],
            ],
        ]

        if let sourceIp = alert.sourceIp, !sourceIp.isEmpty {
            blocks.append([
                "type": "section",
                "fields": [
                    ["type": "mrkdwn", "text": "*Source IP:* `\(sourceIp)`"],
                    ["type": "mrkdwn", "text": "*Time:* \(alert.createdAt)"],
                ],
            ])
        } else {
            blocks.append([
                "type": "section",
                "fields": [["type": "mrkdwn", "text": "*Time:* \(alert.createdAt)"]],
            ])
        }

        if let detail, !detail.isEmpty {
            blocks.append([
                "type": "section",
                "text": ["type": "mrkdwn", "text": "_\(detail)_"],
            ])
        }

        return ["text": "\(emoji) [\(upper)] \(alert.title)", "blocks": blocks]
    }
}

// MARK: - Secret storage

protocol SlackSecretStore: Sendable {
    func save(_ value: String, account: String) throws
    func load(account: String) throws -> String?
    func delete(account: String) throws
}

struct KeychainSlackSecretStore: SlackSecretStore {
    func save(_ value: String, account: String) throws {
        try KeychainStore.storePassword(value, account: account)
    }

    func load(account: String) throws -> String? {
        do {
            return try KeychainStore.loadPassword(account: account)
        } catch KeychainError.itemNotFound {
            return nil
        }
    }

    func delete(account: String) throws {
        try KeychainStore.deletePassword(account: account)
    }
}

// MARK: - Cache

struct SlackDeliveryTarget: Equatable, Sendable {
    let enabled: Bool
    let webhookURL: URL
    let minimumSeverity: String
}

final class SlackDeliveryCache: @unchecked Sendable {
    /// The sensor's `config_secrets.REDACTED`. Echoed back on every load, it
    /// means "unchanged" and must never overwrite a real cached URL.
    static let redactedSentinel = "__squirrelops_redacted__"

    static let shared = SlackDeliveryCache(
        defaults: .standard,
        secrets: KeychainSlackSecretStore()
    )

    private static let webhookAccount = "alert_methods.slack.webhook_url"
    private static let enabledKey = "slackDeliveryEnabled"
    private static let minimumSeverityKey = "slackDeliveryMinimumSeverity"

    private let defaults: UserDefaults
    private let secrets: any SlackSecretStore
    private let lock = NSLock()
    private let logger = Logger(subsystem: "io.squirrelops.home", category: "SlackDeliveryCache")

    init(defaults: UserDefaults, secrets: any SlackSecretStore) {
        self.defaults = defaults
        self.secrets = secrets
    }

    /// Record what the operator saved or what the sensor reported. `webhookURL`
    /// is written only when it is a real URL; the redaction sentinel leaves the
    /// stored secret alone and an empty string removes it.
    func record(enabled: Bool, webhookURL: String?, minimumSeverity: String?) {
        lock.withLock {
            defaults.set(enabled, forKey: Self.enabledKey)
            if let minimumSeverity, !minimumSeverity.isEmpty {
                defaults.set(minimumSeverity, forKey: Self.minimumSeverityKey)
            }

            guard let webhookURL else { return }
            let trimmed = webhookURL.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed == Self.redactedSentinel { return }
            do {
                if trimmed.isEmpty {
                    try secrets.delete(account: Self.webhookAccount)
                } else if Self.validWebhook(trimmed) != nil {
                    try secrets.save(trimmed, account: Self.webhookAccount)
                } else {
                    // Not something we would ever post to; drop any stale value
                    // rather than keep delivering to an address the operator
                    // has since changed.
                    try secrets.delete(account: Self.webhookAccount)
                }
            } catch {
                logger.error("Slack webhook cache update failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    func target() -> SlackDeliveryTarget? {
        lock.withLock {
            let stored: String?
            do {
                stored = try secrets.load(account: Self.webhookAccount)
            } catch {
                logger.error("Slack webhook cache read failed: \(error.localizedDescription, privacy: .public)")
                return nil
            }
            guard let stored, let url = Self.validWebhook(stored) else { return nil }
            return SlackDeliveryTarget(
                enabled: defaults.bool(forKey: Self.enabledKey),
                webhookURL: url,
                minimumSeverity: defaults.string(forKey: Self.minimumSeverityKey) ?? "low"
            )
        }
    }

    func clear() {
        lock.withLock {
            defaults.removeObject(forKey: Self.enabledKey)
            defaults.removeObject(forKey: Self.minimumSeverityKey)
            try? secrets.delete(account: Self.webhookAccount)
        }
    }

    private static func validWebhook(_ raw: String) -> URL? {
        guard let url = URL(string: raw),
              url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty else { return nil }
        return url
    }
}

// MARK: - Dispatcher

enum OfflineDeliveryOutcome: Equatable, Sendable {
    enum SkipReason: Equatable, Sendable {
        case notConfigured
        case disabled
        case belowMinimumSeverity
    }

    case delivered
    case skipped(SkipReason)
    case failed(String)
}

final class OfflineAlertDispatcher: Sendable {
    typealias Post = @Sendable (URLRequest) async throws -> (Data, URLResponse)

    static let shared = OfflineAlertDispatcher(cache: .shared)

    private let cache: SlackDeliveryCache
    private let post: Post
    private let logger = Logger(subsystem: "io.squirrelops.home", category: "OfflineAlertDispatcher")

    init(cache: SlackDeliveryCache, post: Post? = nil) {
        self.cache = cache
        self.post = post ?? { request in
            // Ephemeral: nothing about the webhook or the message touches disk.
            let session = URLSession(configuration: .ephemeral)
            defer { session.finishTasksAndInvalidate() }
            return try await session.data(for: request)
        }
    }

    /// Deliver one alert through the cached Slack target. Never throws; the
    /// caller is a connection-loss path that must not fail on a webhook error.
    @discardableResult
    func deliver(_ alert: AlertSummary, detail: String?) async -> OfflineDeliveryOutcome {
        guard let target = cache.target() else { return .skipped(.notConfigured) }
        guard target.enabled else { return .skipped(.disabled) }
        guard AlertSeverityRank.rank(alert.severity) >= AlertSeverityRank.rank(target.minimumSeverity) else {
            return .skipped(.belowMinimumSeverity)
        }

        var request = URLRequest(url: target.webhookURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 10
        do {
            request.httpBody = try JSONSerialization.data(
                withJSONObject: SlackAlertFormatter.payload(for: alert, detail: detail)
            )
            let (_, response) = try await post(request)
            guard let http = response as? HTTPURLResponse else {
                return failure("Slack webhook returned a non-HTTP response")
            }
            guard (200..<300).contains(http.statusCode) else {
                return failure("Slack webhook returned HTTP \(http.statusCode)")
            }
            logger.info("Delivered \(alert.alertType, privacy: .public) to Slack from the app")
            return .delivered
        } catch {
            return failure("Slack webhook request failed (\(type(of: error)))")
        }
    }

    private func failure(_ message: String) -> OfflineDeliveryOutcome {
        logger.error("\(message, privacy: .public)")
        return .failed(message)
    }
}
