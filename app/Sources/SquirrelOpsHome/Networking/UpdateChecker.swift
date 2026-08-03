import Foundation
import Observation

// MARK: - Result types

/// A release newer than the one currently running.
public struct AvailableUpdate: Sendable, Equatable {
    public let version: String
    public let url: URL

    public init(version: String, url: URL) {
        self.version = version
        self.url = url
    }
}

/// Outcome of one update check.
///
/// ``failed`` is deliberately distinct from ``upToDate``. Treating an
/// unreachable or unparseable source as "up to date" would tell someone running
/// an old build that they are current, which is the one wrong answer that
/// matters here.
public enum UpdateCheckResult: Sendable, Equatable {
    case available(AvailableUpdate)
    case upToDate(current: String)
    case failed(String)
    case skipped
}

// MARK: - Checker

/// Checks the public release feed for a newer distribution.
///
/// Lives outside any view so the launch check and the Settings button share one
/// piece of state: the launch check populates it, and Settings renders whatever
/// the last check found instead of starting from blank.
///
/// The network call, the clock, and the defaults store are injected so the
/// throttle and the failure paths are testable without a live network.
@MainActor
@Observable
public final class UpdateChecker {

    public typealias ReleaseFetcher = @MainActor (URLRequest) async throws -> (Data, URLResponse)

    public nonisolated static let releasesURL = URL(
        string: "https://api.github.com/repos/rocketweb/squirrelops-home/releases/latest"
    )!

    /// Automatic checks run at most once a day. The release feed is
    /// unauthenticated and rate limited per IP, and a new build is not
    /// something a user needs to hear about more often than that.
    public nonisolated static let automaticInterval: TimeInterval = 24 * 60 * 60

    public nonisolated static let lastCheckDefaultsKey = "lastUpdateCheckAt"

    // A known-pending update outlives the process. Without this, relaunching
    // inside the throttle window would skip the check, leave `result` nil, and
    // silently drop the update indicator while the update was still pending.
    public nonisolated static let pendingVersionDefaultsKey = "pendingUpdateVersion"
    public nonisolated static let pendingURLDefaultsKey = "pendingUpdateURL"

    public private(set) var isChecking = false
    public private(set) var result: UpdateCheckResult?

    public var availableUpdate: AvailableUpdate? {
        if case .available(let update) = result { return update }
        return nil
    }

    private let currentVersion: String
    private let defaults: UserDefaults
    private let interval: TimeInterval
    private let now: @MainActor () -> Date
    private let fetch: ReleaseFetcher

    public init(
        currentVersion: String = UpdateChecker.bundleVersion,
        defaults: UserDefaults = .standard,
        interval: TimeInterval = UpdateChecker.automaticInterval,
        now: @escaping @MainActor () -> Date = { Date() },
        fetch: @escaping ReleaseFetcher = { try await URLSession.shared.data(for: $0) }
    ) {
        self.currentVersion = currentVersion
        self.defaults = defaults
        self.interval = interval
        self.now = now
        self.fetch = fetch
        self.result = Self.restorePendingUpdate(from: defaults)
    }

    /// Rehydrate an update found by an earlier run of the app.
    private nonisolated static func restorePendingUpdate(
        from defaults: UserDefaults
    ) -> UpdateCheckResult? {
        guard
            let version = defaults.string(forKey: pendingVersionDefaultsKey),
            let raw = defaults.string(forKey: pendingURLDefaultsKey),
            let url = URL(string: raw)
        else { return nil }
        return .available(AvailableUpdate(version: version, url: url))
    }

    /// The running distribution version, falling back to the app version.
    public static var bundleVersion: String {
        Bundle.main.infoDictionary?["SquirrelOpsDistributionVersion"] as? String
            ?? Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String
            ?? "unknown"
    }

    /// Check the release feed.
    ///
    /// - Parameter force: bypass the throttle. The Settings button passes
    ///   `true` so an explicit request always does something visible.
    @discardableResult
    public func check(force: Bool = false) async -> UpdateCheckResult {
        guard !isChecking else { return .skipped }
        if !force, let last = defaults.object(forKey: Self.lastCheckDefaultsKey) as? Date,
           now().timeIntervalSince(last) < interval {
            return .skipped
        }

        isChecking = true
        defer { isChecking = false }

        var request = URLRequest(url: Self.releasesURL)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 15

        let outcome: UpdateCheckResult
        do {
            let (data, response) = try await fetch(request)
            outcome = Self.interpret(
                data: data,
                response: response,
                currentVersion: currentVersion
            )
        } catch {
            outcome = .failed("Check failed: \(error.localizedDescription)")
        }

        // Only a completed check opens the throttle window. Stamping on failure
        // would let one transient outage suppress checks for a full day.
        switch outcome {
        case .available(let update):
            defaults.set(now(), forKey: Self.lastCheckDefaultsKey)
            defaults.set(update.version, forKey: Self.pendingVersionDefaultsKey)
            defaults.set(update.url.absoluteString, forKey: Self.pendingURLDefaultsKey)
        case .upToDate:
            defaults.set(now(), forKey: Self.lastCheckDefaultsKey)
            defaults.removeObject(forKey: Self.pendingVersionDefaultsKey)
            defaults.removeObject(forKey: Self.pendingURLDefaultsKey)
        case .failed:
            // Keep whatever we last knew; a failed check is not evidence that a
            // previously found update went away.
            result = result ?? outcome
            return outcome
        case .skipped:
            break
        }

        result = outcome
        return outcome
    }

    // MARK: - Parsing

    private static func interpret(
        data: Data,
        response: URLResponse,
        currentVersion: String
    ) -> UpdateCheckResult {
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            return .failed("Could not reach GitHub. Try again later.")
        }
        guard
            let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let tagName = json["tag_name"] as? String,
            let htmlURL = json["html_url"] as? String,
            let url = URL(string: htmlURL)
        else {
            return .failed("Unexpected response from GitHub.")
        }

        // An unreadable version is reported, never assumed. Guessing here would
        // tell someone on an old build that they are current.
        guard let latest = SemanticVersion(parsing: tagName) else {
            return .failed("Could not read a version from release tag \"\(tagName)\".")
        }
        guard let current = SemanticVersion(parsing: currentVersion) else {
            return .failed("Could not read the installed version \"\(currentVersion)\".")
        }

        guard latest > current else {
            return .upToDate(current: current.description)
        }
        return .available(AvailableUpdate(version: latest.description, url: url))
    }
}
