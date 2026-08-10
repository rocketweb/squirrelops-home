import Foundation
import Testing
@testable import SquirrelOpsHome

@Suite("UpdateChecker")
struct UpdateCheckerTests {

    // MARK: - Helpers

    @MainActor
    private final class CallCounter {
        var count = 0
    }

    private static func releaseJSON(
        tag: String,
        htmlURL: String = "https://github.com/rocketweb/squirrelops-home/releases/tag/x"
    ) -> Data {
        let object: [String: Any] = ["tag_name": tag, "html_url": htmlURL]
        return try! JSONSerialization.data(withJSONObject: object)
    }

    private static func httpResponse(_ status: Int) -> URLResponse {
        HTTPURLResponse(
            url: UpdateChecker.releasesURL,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: nil
        )!
    }

    private static func volatileDefaults() -> UserDefaults {
        let suite = "UpdateCheckerTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        return defaults
    }

    @MainActor
    private static func makeChecker(
        currentVersion: String = "2.0.1",
        tag: String = "home-v2.0.1",
        htmlURL: String = "https://github.com/rocketweb/squirrelops-home/releases/tag/x",
        status: Int = 200,
        body: Data? = nil,
        error: Error? = nil,
        now: @escaping @MainActor () -> Date = { Date() },
        defaults: UserDefaults? = nil,
        counter: CallCounter? = nil
    ) -> UpdateChecker {
        UpdateChecker(
            currentVersion: currentVersion,
            defaults: defaults ?? volatileDefaults(),
            now: now,
            fetch: { _ in
                counter?.count += 1
                if let error { throw error }
                return (
                    body ?? releaseJSON(tag: tag, htmlURL: htmlURL),
                    httpResponse(status)
                )
            }
        )
    }

    // MARK: - Comparison

    @Test("Reports an available update when the release is newer")
    @MainActor
    func reportsAvailableUpdate() async {
        let checker = Self.makeChecker(currentVersion: "2.0.1", tag: "home-v2.1.0")
        let result = await checker.check(force: true)
        #expect(result == .available(AvailableUpdate(
            version: "2.1.0",
            url: URL(string: "https://github.com/rocketweb/squirrelops-home/releases/tag/x")!
        )))
        #expect(checker.availableUpdate?.version == "2.1.0")
    }

    @Test("Reports up to date when versions match")
    @MainActor
    func reportsUpToDate() async {
        let checker = Self.makeChecker(currentVersion: "2.0.1", tag: "home-v2.0.1")
        #expect(await checker.check(force: true) == .upToDate(current: "2.0.1"))
        #expect(checker.availableUpdate == nil)
    }

    @Test("Reports up to date when the release is older")
    @MainActor
    func reportsUpToDateWhenRemoteIsOlder() async {
        let checker = Self.makeChecker(currentVersion: "2.0.1", tag: "home-v1.9.9")
        #expect(await checker.check(force: true) == .upToDate(current: "2.0.1"))
    }

    @Test("Strips both known tag prefixes", arguments: [
        ("home-v2.1.0", "2.1.0"),
        ("v2.1.0", "2.1.0"),
        ("2.1.0", "2.1.0"),
    ])
    @MainActor
    func stripsTagPrefixes(tag: String, expected: String) async {
        let checker = Self.makeChecker(currentVersion: "2.0.1", tag: tag)
        _ = await checker.check(force: true)
        #expect(checker.availableUpdate?.version == expected)
    }

    // MARK: - Failures

    @Test("A non-200 response is a failure, not an up-to-date answer")
    @MainActor
    func nonOKStatusFails() async {
        let checker = Self.makeChecker(status: 503)
        guard case .failed = await checker.check(force: true) else {
            Issue.record("expected .failed")
            return
        }
        #expect(checker.availableUpdate == nil)
    }

    @Test("Malformed JSON is a failure, not an up-to-date answer")
    @MainActor
    func malformedBodyFails() async {
        let checker = Self.makeChecker(body: Data("not json".utf8))
        guard case .failed = await checker.check(force: true) else {
            Issue.record("expected .failed")
            return
        }
    }

    @Test("A transport error is reported as a failure")
    @MainActor
    func transportErrorFails() async {
        let checker = Self.makeChecker(error: URLError(.notConnectedToInternet))
        guard case .failed = await checker.check(force: true) else {
            Issue.record("expected .failed")
            return
        }
    }

    // MARK: - Throttling

    @Test("An automatic check is skipped inside the throttle window")
    @MainActor
    func automaticCheckIsThrottled() async {
        let defaults = Self.volatileDefaults()
        let counter = CallCounter()
        let checker = Self.makeChecker(defaults: defaults, counter: counter)

        _ = await checker.check()
        let second = await checker.check()

        #expect(second == .skipped)
        #expect(counter.count == 1)
    }

    @Test("A forced check ignores the throttle window")
    @MainActor
    func forcedCheckBypassesThrottle() async {
        let defaults = Self.volatileDefaults()
        let counter = CallCounter()
        let checker = Self.makeChecker(defaults: defaults, counter: counter)

        _ = await checker.check()
        _ = await checker.check(force: true)

        #expect(counter.count == 2)
    }

    @Test("An automatic check runs again once the window has elapsed")
    @MainActor
    func automaticCheckResumesAfterInterval() async {
        let defaults = Self.volatileDefaults()
        let counter = CallCounter()
        let start = Date(timeIntervalSince1970: 1_000_000)
        var clock = start
        let checker = Self.makeChecker(
            now: { clock },
            defaults: defaults,
            counter: counter
        )

        _ = await checker.check()
        clock = start.addingTimeInterval(UpdateChecker.automaticInterval + 1)
        _ = await checker.check()

        #expect(counter.count == 2)
    }

    @Test("A failed check does not start the throttle window")
    @MainActor
    func failureDoesNotThrottleTheRetry() async {
        let defaults = Self.volatileDefaults()
        let counter = CallCounter()
        let checker = Self.makeChecker(
            status: 500,
            defaults: defaults,
            counter: counter
        )

        _ = await checker.check()
        _ = await checker.check()

        // A transient outage must not suppress checks for a full day.
        #expect(counter.count == 2)
    }

    @Test("A successful check records the time it ran")
    @MainActor
    func successRecordsTimestamp() async {
        let defaults = Self.volatileDefaults()
        let stamp = Date(timeIntervalSince1970: 1_700_000_000)
        let checker = Self.makeChecker(now: { stamp }, defaults: defaults)

        _ = await checker.check()

        #expect(defaults.object(forKey: UpdateChecker.lastCheckDefaultsKey) as? Date == stamp)
    }

    // MARK: - Pending update persistence

    @Test("A pending update survives a relaunch inside the throttle window")
    @MainActor
    func pendingUpdateIsRestored() async {
        let defaults = Self.volatileDefaults()
        let first = Self.makeChecker(
            currentVersion: "2.0.1", tag: "home-v2.1.0", defaults: defaults
        )
        _ = await first.check()
        #expect(first.availableUpdate?.version == "2.1.0")

        // Same defaults, fresh instance: the app was relaunched.
        let counter = CallCounter()
        let second = Self.makeChecker(
            currentVersion: "2.0.1", tag: "home-v2.1.0",
            defaults: defaults, counter: counter
        )
        #expect(second.availableUpdate?.version == "2.1.0")

        // The throttle still applies, so the indicator comes from storage.
        #expect(await second.check() == .skipped)
        #expect(counter.count == 0)
        #expect(second.availableUpdate?.version == "2.1.0")
    }

    @Test("Installing the update clears the indicator but keeps the known release")
    @MainActor
    func upToDateClearsTheIndicator() async {
        let defaults = Self.volatileDefaults()
        let stale = Self.makeChecker(
            currentVersion: "2.0.1", tag: "home-v2.1.0", defaults: defaults
        )
        _ = await stale.check(force: true)
        #expect(stale.availableUpdate != nil)

        // The user installed it, so the running version now matches.
        let updated = Self.makeChecker(
            currentVersion: "2.1.0", tag: "home-v2.1.0", defaults: defaults
        )
        _ = await updated.check(force: true)

        #expect(updated.availableUpdate == nil)
        // Still the newest release; we are simply no longer behind it. The
        // snapshot has to survive so other components can be compared to it.
        #expect(updated.latestRelease?.version.description == "2.1.0")
    }

    @Test("A failed check keeps a previously found update visible")
    @MainActor
    func failureKeepsKnownUpdate() async {
        let defaults = Self.volatileDefaults()
        let found = Self.makeChecker(
            currentVersion: "2.0.1", tag: "home-v2.1.0", defaults: defaults
        )
        _ = await found.check(force: true)

        let offline = Self.makeChecker(
            currentVersion: "2.0.1",
            error: URLError(.notConnectedToInternet),
            defaults: defaults
        )
        _ = await offline.check(force: true)

        // Losing the network is not evidence the release was withdrawn.
        #expect(offline.availableUpdate?.version == "2.1.0")
    }

    // MARK: - Version parsing

    @Test("An unrecognized tag scheme fails instead of reporting up to date")
    @MainActor
    func unreadableTagFails() async {
        let checker = Self.makeChecker(currentVersion: "2.0.1", tag: "nightly-build")
        guard case .failed = await checker.check(force: true) else {
            Issue.record("an unreadable tag must not resolve to up-to-date")
            return
        }
        #expect(checker.availableUpdate == nil)
    }

    @Test("A newer release under an unfamiliar prefix is still detected")
    @MainActor
    func unfamiliarPrefixStillCompares() async {
        // The old parser dropped "sensor-v3" entirely, compared as 0.0, and
        // told the user they were up to date.
        let checker = Self.makeChecker(currentVersion: "2.0.1", tag: "sensor-v3.0.0")
        #expect(await checker.check(force: true) == .available(AvailableUpdate(
            version: "3.0.0",
            url: URL(string: "https://github.com/rocketweb/squirrelops-home/releases/tag/x")!
        )))
    }

    @Test("An unreadable installed version fails rather than comparing")
    @MainActor
    func unreadableCurrentVersionFails() async {
        let checker = Self.makeChecker(currentVersion: "unknown", tag: "home-v2.1.0")
        guard case .failed = await checker.check(force: true) else {
            Issue.record("expected .failed")
            return
        }
    }

    @Test("Multi-digit patch versions compare numerically")
    @MainActor
    func multiDigitPatchComparesNumerically() async {
        let checker = Self.makeChecker(currentVersion: "1.1.9", tag: "v1.1.14")
        _ = await checker.check(force: true)
        #expect(checker.availableUpdate?.version == "1.1.14")
    }
}
