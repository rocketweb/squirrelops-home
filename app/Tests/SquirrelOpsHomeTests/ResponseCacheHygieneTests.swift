import Foundation
import Testing
@testable import SquirrelOpsHome

/// The sensor's redaction fix does not reach a response an older build already
/// wrote to disk. These pin the client half of that fix.
@Suite("ResponseCacheHygiene")
struct ResponseCacheHygieneTests {

    private func freshDefaults(_ name: String) -> UserDefaults {
        let defaults = UserDefaults(suiteName: "ResponseCacheHygieneTests.\(name)")!
        defaults.removePersistentDomain(
            forName: "ResponseCacheHygieneTests.\(name)"
        )
        return defaults
    }

    private func countingCache() -> URLCache {
        URLCache(memoryCapacity: 1024, diskCapacity: 1024, diskPath: nil)
    }

    @Test("A first run purges the legacy cache")
    func purgesOnFirstRun() {
        let defaults = freshDefaults(#function)
        let cache = countingCache()

        let purged = ResponseCacheHygiene.purgeLegacyResponseCacheIfNeeded(
            defaults: defaults,
            cache: cache
        )

        #expect(purged)
    }

    @Test("The purge runs once per version, not on every launch")
    func purgesOnlyOncePerVersion() {
        let defaults = freshDefaults(#function)
        let cache = countingCache()

        let first = ResponseCacheHygiene.purgeLegacyResponseCacheIfNeeded(
            defaults: defaults,
            cache: cache
        )
        let second = ResponseCacheHygiene.purgeLegacyResponseCacheIfNeeded(
            defaults: defaults,
            cache: cache
        )

        #expect(first)
        #expect(!second)
    }

    @Test("Capacity is zeroed even when the purge is skipped")
    func alwaysDisablesTheSharedCache() {
        let defaults = freshDefaults(#function)
        defaults.set(
            ResponseCacheHygiene.purgeVersion,
            forKey: ResponseCacheHygiene.purgeMarkerKey
        )
        let cache = countingCache()

        let purged = ResponseCacheHygiene.purgeLegacyResponseCacheIfNeeded(
            defaults: defaults,
            cache: cache
        )

        // The one-time sweep is done, but a cache that can still store a
        // response would let a future `.default` session reopen the hole.
        #expect(!purged)
        #expect(cache.memoryCapacity == 0)
        #expect(cache.diskCapacity == 0)
    }

    @Test("A stale marker from an earlier version forces another purge")
    func rePurgesWhenTheVersionMovesOn() {
        let defaults = freshDefaults(#function)
        defaults.set("2.0.1", forKey: ResponseCacheHygiene.purgeMarkerKey)
        let cache = countingCache()

        let purged = ResponseCacheHygiene.purgeLegacyResponseCacheIfNeeded(
            defaults: defaults,
            cache: cache
        )

        #expect(purged)
        #expect(
            defaults.string(forKey: ResponseCacheHygiene.purgeMarkerKey)
                == ResponseCacheHygiene.purgeVersion
        )
    }

    @Test("Sensor sessions never persist a response to disk")
    func sensorSessionsAreNonPersistent() {
        let configuration = SensorClient.nonPersistentConfiguration()

        #expect(configuration.urlCache == nil)
        #expect(configuration.requestCachePolicy == .reloadIgnoringLocalCacheData)
        // Ephemeral keeps cookies and credentials in memory too. A disk-backed
        // store here is what wrote plaintext /config bodies before 2.0.2.
        #expect(configuration.httpCookieStorage !== HTTPCookieStorage.shared)
        #expect(configuration.urlCredentialStorage !== URLCredentialStorage.shared)
    }
}
