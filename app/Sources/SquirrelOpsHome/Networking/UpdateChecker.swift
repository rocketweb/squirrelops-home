import Foundation
import Observation

// MARK: - Result types

/// The newest release the update source knows about.
///
/// This is specifically a ``home-v*`` distribution release. App and sensor
/// component tags have independent versions and are not interchangeable with
/// the version of the installed Home package.
public struct ReleaseSnapshot: Sendable, Equatable {
    public let version: SemanticVersion
    public let url: URL

    public init(version: SemanticVersion, url: URL) {
        self.version = version
        self.url = url
    }
}

/// A release newer than some component that is installed.
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
/// Lives outside any view so Settings and the menu bar share one piece of state.
///
/// Only the app reaches the network. The sensor's version arrives over the
/// existing authenticated status call, so a privileged daemon whose job is
/// watching a home network never has to phone a third party to learn it is out
/// of date.
///
/// The network call, the clock, and the defaults store are injected so the
/// throttle and the failure paths are testable without a live network.
@MainActor
@Observable
public final class UpdateChecker {

    public typealias ReleaseFetcher = @MainActor (URLRequest) async throws -> (Data, URLResponse)

    public nonisolated static let releasesURL = URL(
        string: "https://api.github.com/repos/rocketweb/squirrelops-home/releases?per_page=100"
    )!

    /// Non-forced callers are throttled. The shipped UI only checks after an
    /// explicit click and passes ``force: true``.
    public nonisolated static let automaticInterval: TimeInterval = 24 * 60 * 60

    public nonisolated static let lastCheckDefaultsKey = "lastUpdateCheckAt"

    // The newest known release outlives the process so an update found by an
    // explicit check remains visible after relaunch.
    public nonisolated static let latestVersionDefaultsKey = "latestReleaseVersion"
    public nonisolated static let latestURLDefaultsKey = "latestReleaseURL"

    public private(set) var isChecking = false
    public private(set) var result: UpdateCheckResult?

    /// The newest release seen, whether or not anything is behind it.
    public private(set) var latestRelease: ReleaseSnapshot?

    /// A release newer than the running app.
    public var availableUpdate: AvailableUpdate? {
        update(forDistributionVersion: currentVersion)
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
        self.latestRelease = Self.restoreLatestRelease(from: defaults)
        self.result = Self.describe(
            latestRelease: latestRelease,
            componentVersion: currentVersion
        )
    }

    /// The running distribution version, falling back to the app version.
    public static var bundleVersion: String {
        Bundle.main.infoDictionary?["SquirrelOpsDistributionVersion"] as? String
            ?? Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String
            ?? "unknown"
    }

    // MARK: - Comparison

    /// A Home release newer than the installed distribution version.
    private func update(forDistributionVersion raw: String) -> AvailableUpdate? {
        guard
            let component = SemanticVersion(parsing: raw),
            let release = latestRelease,
            release.version > component
        else { return nil }
        return AvailableUpdate(version: release.version.description, url: release.url)
    }

    // MARK: - Checking

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

        let lookup: ReleaseLookup
        do {
            let (data, response) = try await fetch(request)
            lookup = Self.parseRelease(data: data, response: response)
        } catch {
            lookup = .problem("Check failed: \(error.localizedDescription)")
        }

        switch lookup {
        case .problem(let message):
            // Keep whatever we last knew. Losing the network is not evidence
            // that a previously found release was withdrawn, and stamping the
            // clock would let one outage suppress checks for a full day.
            result = .failed(message)
            return .failed(message)

        case .found(let release):
            latestRelease = release
            defaults.set(now(), forKey: Self.lastCheckDefaultsKey)
            defaults.set(release.version.description, forKey: Self.latestVersionDefaultsKey)
            defaults.set(release.url.absoluteString, forKey: Self.latestURLDefaultsKey)
            let outcome = Self.describe(
                latestRelease: release,
                componentVersion: currentVersion
            ) ?? .failed("Could not read the installed version \"\(currentVersion)\".")
            result = outcome
            return outcome
        }
    }

    // MARK: - Parsing

    /// Either a usable release or the reason one could not be read.
    private enum ReleaseLookup {
        case found(ReleaseSnapshot)
        case problem(String)
    }

    private static func parseRelease(
        data: Data,
        response: URLResponse
    ) -> ReleaseLookup {
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            return .problem("Could not reach GitHub. Try again later.")
        }
        guard let releases = try? JSONSerialization.jsonObject(with: data)
            as? [[String: Any]] else {
            return .problem("Unexpected response from GitHub.")
        }

        var newest: ReleaseSnapshot?
        for release in releases {
            if release["draft"] as? Bool == true || release["prerelease"] as? Bool == true {
                continue
            }
            guard let tagName = release["tag_name"] as? String,
                  tagName.hasPrefix("home-v") else {
                continue
            }
            guard let version = SemanticVersion(parsing: tagName),
                  tagName == "home-v\(version.description)" else {
                // One malformed historical release must not suppress every
                // valid Home release in the feed. The aggregate still fails
                // closed below if no usable release remains.
                continue
            }
            guard let htmlURL = release["html_url"] as? String,
                  let url = validatedReleaseURL(htmlURL, tag: tagName) else {
                continue
            }
            let candidate = ReleaseSnapshot(version: version, url: url)
            if newest == nil || version > newest!.version {
                newest = candidate
            }
        }
        guard let newest else {
            return .problem("GitHub did not return a published Home release.")
        }
        return .found(newest)
    }

    /// Render the display outcome for one component against a known release.
    private static func describe(
        latestRelease: ReleaseSnapshot?,
        componentVersion raw: String
    ) -> UpdateCheckResult? {
        guard let release = latestRelease else { return nil }
        guard let component = SemanticVersion(parsing: raw) else { return nil }
        guard release.version > component else {
            return .upToDate(current: component.description)
        }
        return .available(
            AvailableUpdate(version: release.version.description, url: release.url)
        )
    }

    /// Rehydrate the release found by an earlier run of the app.
    private nonisolated static func restoreLatestRelease(
        from defaults: UserDefaults
    ) -> ReleaseSnapshot? {
        guard
            let raw = defaults.string(forKey: latestVersionDefaultsKey),
            let version = SemanticVersion(parsing: raw),
            let rawURL = defaults.string(forKey: latestURLDefaultsKey),
            let url = validatedReleaseURL(
                rawURL,
                tag: "home-v\(version.description)"
            )
        else { return nil }
        return ReleaseSnapshot(version: version, url: url)
    }

    /// Only links to the expected repository's exact release-tag page can be
    /// restored or shown. UserDefaults is writable by the local user and must
    /// not be treated as authority for a clickable destination.
    private nonisolated static func validatedReleaseURL(
        _ raw: String,
        tag: String
    ) -> URL? {
        guard let components = URLComponents(string: raw),
              components.scheme?.lowercased() == "https",
              components.host?.lowercased() == "github.com",
              components.port == nil,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              components.path == "/rocketweb/squirrelops-home/releases/tag/\(tag)",
              let url = components.url else {
            return nil
        }
        return url
    }
}
