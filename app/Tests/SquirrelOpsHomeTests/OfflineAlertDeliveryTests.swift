import Foundation
import Testing

@testable import SquirrelOpsHome

// MARK: - Test doubles

final class InMemorySlackSecretStore: SlackSecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: String] = [:]

    func save(_ value: String, account: String) throws {
        lock.withLock { values[account] = value }
    }

    func load(account: String) throws -> String? {
        lock.withLock { values[account] }
    }

    func delete(account: String) throws {
        _ = lock.withLock { values.removeValue(forKey: account) }
    }
}

private func makeCache() -> SlackDeliveryCache {
    let defaults = UserDefaults(suiteName: "OfflineAlertDeliveryTests.\(UUID().uuidString)")!
    return SlackDeliveryCache(defaults: defaults, secrets: InMemorySlackSecretStore())
}

private func offlineAlert(severity: String = "high") -> AlertSummary {
    AlertSummary(
        id: -1,
        alertType: "system.sensor_offline",
        severity: severity,
        title: "Sensor Disconnected",
        createdAt: "2026-10-18T12:00:00Z"
    )
}

// MARK: - Formatter

@Suite("Slack alert formatter")
struct SlackAlertFormatterTests {

    @Test("Offline alert renders the same Block Kit shape the sensor sends")
    func matchesSensorShape() throws {
        let payload = SlackAlertFormatter.payload(
            for: offlineAlert(severity: "high"),
            detail: "The app has not reached the sensor for 5 minutes."
        )

        #expect(payload["text"] as? String == "\u{1F7E0} [HIGH] Sensor Disconnected")

        let blocks = try #require(payload["blocks"] as? [[String: Any]])
        #expect(blocks.count == 4)

        let header = try #require(blocks[0]["text"] as? [String: String])
        #expect(blocks[0]["type"] as? String == "header")
        #expect(header["type"] == "plain_text")
        #expect(header["text"] == "\u{1F7E0} Sensor Disconnected")

        let fields = try #require(blocks[1]["fields"] as? [[String: String]])
        #expect(fields.map { $0["text"] } == ["*Severity:* \u{1F7E0} HIGH", "*Type:* `system.sensor_offline`"])

        // No source IP on an offline alert, so the time stands alone.
        let timeFields = try #require(blocks[2]["fields"] as? [[String: String]])
        #expect(timeFields.map { $0["text"] } == ["*Time:* 2026-10-18T12:00:00Z"])

        let detail = try #require(blocks[3]["text"] as? [String: String])
        #expect(detail["text"] == "_The app has not reached the sensor for 5 minutes._")
    }

    @Test("Severity emoji follow the sensor's map")
    func severityEmoji() {
        #expect(SlackAlertFormatter.emoji(for: "critical") == "\u{1F534}")
        #expect(SlackAlertFormatter.emoji(for: "high") == "\u{1F7E0}")
        #expect(SlackAlertFormatter.emoji(for: "medium") == "\u{1F7E1}")
        #expect(SlackAlertFormatter.emoji(for: "low") == "\u{1F535}")
    }

    @Test("Source IP, when present, shares a section with the time")
    func sourceIPSection() throws {
        let alert = AlertSummary(
            id: 5, alertType: "decoy.trip", severity: "medium", title: "Decoy connection",
            sourceIp: "192.168.1.9", createdAt: "2026-10-18T12:00:00Z"
        )
        let payload = SlackAlertFormatter.payload(for: alert, detail: nil)
        let blocks = try #require(payload["blocks"] as? [[String: Any]])
        #expect(blocks.count == 3)
        let fields = try #require(blocks[2]["fields"] as? [[String: String]])
        #expect(fields.map { $0["text"] } == ["*Source IP:* `192.168.1.9`", "*Time:* 2026-10-18T12:00:00Z"])
    }
}

// MARK: - Cache

@Suite("Slack delivery cache")
struct SlackDeliveryCacheTests {

    @Test("Records a real webhook URL typed by the operator")
    func recordsRealURL() throws {
        let cache = makeCache()
        cache.record(enabled: true, webhookURL: "https://hooks.slack.com/services/T0/B0/x", minimumSeverity: "high")

        let target = try #require(cache.target())
        #expect(target.enabled)
        #expect(target.webhookURL.absoluteString == "https://hooks.slack.com/services/T0/B0/x")
        #expect(target.minimumSeverity == "high")
    }

    @Test("The sensor's redaction sentinel never replaces a cached URL")
    func ignoresRedactedSentinel() throws {
        let cache = makeCache()
        cache.record(enabled: true, webhookURL: "https://hooks.slack.com/services/T0/B0/x", minimumSeverity: "low")
        cache.record(enabled: true, webhookURL: SlackDeliveryCache.redactedSentinel, minimumSeverity: "critical")

        let target = try #require(cache.target())
        #expect(target.webhookURL.absoluteString == "https://hooks.slack.com/services/T0/B0/x")
        #expect(target.minimumSeverity == "critical")
    }

    @Test("Disabling keeps the URL but yields a disabled target")
    func disableKeepsURL() throws {
        let cache = makeCache()
        cache.record(enabled: true, webhookURL: "https://hooks.slack.com/services/T0/B0/x", minimumSeverity: "low")
        cache.record(enabled: false, webhookURL: SlackDeliveryCache.redactedSentinel, minimumSeverity: "low")

        let target = try #require(cache.target())
        #expect(target.enabled == false)
        #expect(target.webhookURL.absoluteString == "https://hooks.slack.com/services/T0/B0/x")
    }

    @Test("An emptied URL removes the cached secret")
    func emptyURLClears() {
        let cache = makeCache()
        cache.record(enabled: true, webhookURL: "https://hooks.slack.com/services/T0/B0/x", minimumSeverity: "low")
        cache.record(enabled: true, webhookURL: "", minimumSeverity: "low")
        #expect(cache.target() == nil)
    }

    @Test("Only https Slack-shaped URLs are cached")
    func rejectsNonHTTPS() {
        let cache = makeCache()
        cache.record(enabled: true, webhookURL: "http://hooks.slack.com/services/T0/B0/x", minimumSeverity: "low")
        #expect(cache.target() == nil)
        cache.record(enabled: true, webhookURL: "not a url", minimumSeverity: "low")
        #expect(cache.target() == nil)
    }

    @Test("Nothing cached means no target")
    func emptyCache() {
        #expect(makeCache().target() == nil)
    }
}

// MARK: - Dispatcher

@Suite("Offline alert dispatcher")
struct OfflineAlertDispatcherTests {

    private final class Recorder: @unchecked Sendable {
        private let lock = NSLock()
        private var _requests: [URLRequest] = []
        var requests: [URLRequest] { lock.withLock { _requests } }
        func append(_ r: URLRequest) { lock.withLock { _requests.append(r) } }
    }

    private func dispatcher(
        cache: SlackDeliveryCache,
        status: Int = 200,
        recorder: Recorder
    ) -> OfflineAlertDispatcher {
        OfflineAlertDispatcher(cache: cache) { request in
            recorder.append(request)
            let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
            return (Data("ok".utf8), response)
        }
    }

    @Test("Posts the formatted payload to the cached webhook")
    func postsToWebhook() async throws {
        let cache = makeCache()
        cache.record(enabled: true, webhookURL: "https://hooks.slack.com/services/T0/B0/x", minimumSeverity: "medium")
        let recorder = Recorder()

        let delivered = await dispatcher(cache: cache, recorder: recorder)
            .deliver(offlineAlert(severity: "high"), detail: "detail")

        #expect(delivered == .delivered)
        let request = try #require(recorder.requests.first)
        #expect(request.url?.absoluteString == "https://hooks.slack.com/services/T0/B0/x")
        #expect(request.httpMethod == "POST")
        #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
        let body = try JSONSerialization.jsonObject(with: try #require(request.httpBody)) as! [String: Any]
        #expect(body["text"] as? String == "\u{1F7E0} [HIGH] Sensor Disconnected")
    }

    @Test("Honors the operator's minimum severity")
    func belowMinimumSkips() async {
        let cache = makeCache()
        cache.record(enabled: true, webhookURL: "https://hooks.slack.com/services/T0/B0/x", minimumSeverity: "high")
        let recorder = Recorder()

        let outcome = await dispatcher(cache: cache, recorder: recorder)
            .deliver(offlineAlert(severity: "medium"), detail: nil)

        #expect(outcome == .skipped(.belowMinimumSeverity))
        #expect(recorder.requests.isEmpty)
    }

    @Test("Disabled or unconfigured Slack sends nothing")
    func disabledSkips() async {
        let disabled = makeCache()
        disabled.record(enabled: false, webhookURL: "https://hooks.slack.com/services/T0/B0/x", minimumSeverity: "low")
        let recorder = Recorder()

        #expect(await dispatcher(cache: disabled, recorder: recorder).deliver(offlineAlert(), detail: nil) == .skipped(.disabled))
        #expect(await dispatcher(cache: makeCache(), recorder: recorder).deliver(offlineAlert(), detail: nil) == .skipped(.notConfigured))
        #expect(recorder.requests.isEmpty)
    }

    @Test("A webhook failure is reported, not thrown")
    func failureIsReported() async {
        let cache = makeCache()
        cache.record(enabled: true, webhookURL: "https://hooks.slack.com/services/T0/B0/x", minimumSeverity: "low")
        let recorder = Recorder()

        let outcome = await dispatcher(cache: cache, status: 500, recorder: recorder)
            .deliver(offlineAlert(), detail: nil)

        #expect(outcome == .failed("Slack webhook returned HTTP 500"))
    }
}
