import Foundation
import Testing
@testable import SquirrelOpsHome

/// Home distribution releases must not be compared with independent component
/// versions.
@Suite("ComponentUpdates")
struct ComponentUpdateTests {

    private static func releaseJSON(tag: String) -> Data {
        let object: [[String: Any]] = [[
            "tag_name": tag,
            "html_url": "https://github.com/rocketweb/squirrelops-home/releases/tag/\(tag)",
            "draft": false,
            "prerelease": false,
        ]]
        return try! JSONSerialization.data(withJSONObject: object)
    }

    /// An AppState whose checker has already seen `releaseTag`.
    @MainActor
    private static func makeState(
        appVersion: String,
        sensorVersion: String?,
        releaseTag: String = "home-v2.1.0"
    ) async -> AppState {
        let suite = "ComponentUpdateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)

        let checker = UpdateChecker(
            currentVersion: appVersion,
            defaults: defaults,
            fetch: { _ in
                (
                    releaseJSON(tag: releaseTag),
                    HTTPURLResponse(
                        url: UpdateChecker.releasesURL,
                        statusCode: 200,
                        httpVersion: "HTTP/1.1",
                        headerFields: nil
                    )!
                )
            }
        )
        await checker.check(force: true)

        let state = AppState(updateChecker: checker)
        if let sensorVersion {
            state.sensorInfo = HealthResponse(version: sensorVersion, uptimeSeconds: 1)
        }
        return state
    }

    @Test("An older Home distribution reports one Home update")
    @MainActor
    func homeBehind() async {
        let state = await Self.makeState(appVersion: "2.0.1", sensorVersion: "2.0.1")
        #expect(state.outdatedComponents == [.home])
        #expect(state.pendingUpdateSummary == "Update SquirrelOps Home to v2.1.0")
    }

    @Test("An older sensor does not create a nonexistent Home update")
    @MainActor
    func sensorVersionIsIndependent() async {
        let state = await Self.makeState(appVersion: "2.1.0", sensorVersion: "2.0.1")
        #expect(state.outdatedComponents.isEmpty)
        #expect(state.pendingUpdateSummary == nil)
        #expect(state.pendingUpdate == nil)
    }

    @Test("The Home distribution is reported even when the sensor is newer")
    @MainActor
    func homeVersionIsAuthoritative() async {
        let state = await Self.makeState(appVersion: "2.0.1", sensorVersion: "2.1.0")
        #expect(state.outdatedComponents == [.home])
        #expect(state.pendingUpdateSummary == "Update SquirrelOps Home to v2.1.0")
    }

    @Test("Nothing behind reports nothing")
    @MainActor
    func nothingBehind() async {
        let state = await Self.makeState(appVersion: "2.1.0", sensorVersion: "2.1.0")
        #expect(state.outdatedComponents.isEmpty)
        #expect(state.pendingUpdate == nil)
        #expect(state.pendingUpdateSummary == nil)
    }

    @Test("An unknown sensor version does not affect a current Home distribution")
    @MainActor
    func unknownSensorVersionIsNotFlagged() async {
        // /system/health omits the version before authentication, so it is
        // genuinely absent until the status call lands. Absent is not stale.
        let state = await Self.makeState(appVersion: "2.1.0", sensorVersion: nil)
        #expect(state.outdatedComponents.isEmpty)
        #expect(state.pendingUpdate == nil)
    }

    @Test("An unreadable sensor version does not affect a current Home distribution")
    @MainActor
    func unreadableSensorVersionIsNotFlagged() async {
        let state = await Self.makeState(appVersion: "2.1.0", sensorVersion: "unknown")
        #expect(state.outdatedComponents.isEmpty)
    }

    @Test("Nothing is reported before any release has been seen")
    @MainActor
    func noReleaseYetReportsNothing() async {
        let suite = "ComponentUpdateTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        let state = AppState(
            updateChecker: UpdateChecker(currentVersion: "2.0.1", defaults: defaults)
        )
        state.sensorInfo = HealthResponse(version: "1.0.0", uptimeSeconds: 1)

        #expect(state.outdatedComponents.isEmpty)
        #expect(state.pendingUpdate == nil)
    }
}
