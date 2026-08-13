import Foundation

/// Removes sensor responses that earlier versions cached to disk.
///
/// Every release before 2.0.2 returned `GET /config` verbatim, including the
/// Home Assistant token, the Slack webhook URL, and the classifier API key,
/// and the app fetched it through a `URLSessionConfiguration.default` session.
/// That configuration shares an on-disk `URLCache`, so those bodies were
/// written unencrypted under the app's Caches directory, readable by any
/// process running as the paired user.
///
/// Redaction and `Cache-Control: no-store` stop the sensor producing new
/// copies. Neither reaches a file that is already on disk. An upgrade has to
/// clear what the old build left behind, or the vulnerability survives the fix
/// on every existing install.
///
/// Rotating the exposed credentials is still the correct response to a machine
/// that may have been read. This removes the copy; it cannot un-disclose it.
public enum ResponseCacheHygiene {

    /// Records the version whose purge already ran, so the sweep happens once
    /// per upgrade rather than on every launch.
    public static let purgeMarkerKey = "httpResponseCachePurgedForVersion"

    /// Bumped only when a new release needs to force another sweep.
    public static let purgeVersion = "2.0.2"

    /// Clear the legacy on-disk cache, then keep the shared cache unusable.
    ///
    /// - Returns: whether this call performed the one-time purge.
    @discardableResult
    public static func purgeLegacyResponseCacheIfNeeded(
        defaults: UserDefaults = .standard,
        cache: URLCache = .shared
    ) -> Bool {
        // Unconditional, and deliberately outside the once-per-version gate.
        // Sensor traffic now uses ephemeral sessions, but a future session
        // built from `.default` would silently reopen this hole. A shared
        // cache with no capacity cannot store a response in the first place.
        cache.memoryCapacity = 0
        cache.diskCapacity = 0

        let alreadyPurged = defaults.string(forKey: purgeMarkerKey) == purgeVersion
        guard !alreadyPurged else { return false }

        cache.removeAllCachedResponses()
        defaults.set(purgeVersion, forKey: purgeMarkerKey)
        return true
    }
}
