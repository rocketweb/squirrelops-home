import Testing

@testable import SquirrelOpsHome

@Suite("Squirrel Scouts refresh policy")
struct SquirrelScoutsRefreshTests {
    @Test("Idle progress keeps polling until the deployment state is stable")
    func idleProgressPollsUntilStable() {
        var state = ScoutRefreshPollState(
            maximumPolls: 20,
            requiredStableIdleSamples: 2
        )
        let first = ScoutRefreshSnapshot(
            isRunning: false,
            activeMimics: 18,
            maxMimics: 30,
            mimicRevision: []
        )
        let progressed = ScoutRefreshSnapshot(
            isRunning: false,
            activeMimics: 19,
            maxMimics: 30,
            mimicRevision: []
        )

        let afterFirst = state.shouldPoll(after: first)
        let afterProgress = state.shouldPoll(after: progressed)
        let firstStableSample = state.shouldPoll(after: progressed)
        let secondStableSample = state.shouldPoll(after: progressed)

        #expect(afterFirst)
        #expect(afterProgress)
        #expect(firstStableSample)
        #expect(!secondStableSample)
    }

    @Test("A continuously running scout is bounded")
    func runningScoutPollingIsBounded() {
        var state = ScoutRefreshPollState(
            maximumPolls: 3,
            requiredStableIdleSamples: 1
        )
        let running = ScoutRefreshSnapshot(
            isRunning: true,
            activeMimics: 3,
            maxMimics: 30,
            mimicRevision: []
        )

        let first = state.shouldPoll(after: running)
        let second = state.shouldPoll(after: running)
        let third = state.shouldPoll(after: running)
        let bounded = state.shouldPoll(after: running)

        #expect(first)
        #expect(second)
        #expect(third)
        #expect(!bounded)
    }

    @Test("An idle scout at mimic capacity does not poll")
    func fullCapacityDoesNotPoll() {
        var state = ScoutRefreshPollState(
            maximumPolls: 20,
            requiredStableIdleSamples: 2
        )
        let full = ScoutRefreshSnapshot(
            isRunning: false,
            activeMimics: 30,
            maxMimics: 30,
            mimicRevision: makeMimicRevisions(count: 30)
        )

        let shouldPoll = state.shouldPoll(after: full)
        #expect(!shouldPoll)
    }

    @Test("Lifecycle work keeps status polling even at full capacity")
    func lifecycleBusyKeepsPolling() {
        var state = ScoutRefreshPollState(
            maximumPolls: 20,
            requiredStableIdleSamples: 2
        )
        let updating = ScoutRefreshSnapshot(
            isRunning: false,
            lifecycleBusy: true,
            activeMimics: 30,
            maxMimics: 30,
            mimicRevision: makeMimicRevisions(count: 30)
        )

        let shouldPoll = state.shouldPoll(after: updating)
        #expect(shouldPoll)
    }

    @Test("A full status count still polls when the mimic list is stale")
    func fullStatusWithStaleRowsPolls() {
        var state = ScoutRefreshPollState(
            maximumPolls: 20,
            requiredStableIdleSamples: 2
        )
        let stale = ScoutRefreshSnapshot(
            isRunning: false,
            activeMimics: 30,
            maxMimics: 30,
            mimicRevision: makeMimicRevisions(count: 18)
        )

        let shouldPoll = state.shouldPoll(after: stale)
        #expect(shouldPoll)
    }

    @Test("WebSocket mimic revisions include lifecycle changes but ignore classic decoys")
    func appStateMimicRevisionTracksLifecycleChanges() {
        let classic = makeDecoy(id: 1, type: "dev_server", status: "active")
        let active = makeDecoy(id: 2, type: "mimic", status: "active")
        let stopped = makeDecoy(id: 2, type: "mimic", status: "stopped")

        #expect(ScoutRefreshPolicy.mimicRevision(in: [classic]).isEmpty)
        #expect(
            ScoutRefreshPolicy.mimicRevision(in: [classic, active])
                != ScoutRefreshPolicy.mimicRevision(in: [classic, stopped])
        )
    }

    @Test("WebSocket revisions immediately replace local service hit counts")
    func appStateMimicRevisionUpdatesLocalHitCount() {
        let mimic = MimicDecoySummary(
            id: 20,
            name: "Printer",
            bindAddress: "192.168.1.203",
            port: 9100,
            status: "active",
            connectionCount: 2,
            createdAt: "2026-07-24T00:00:00Z",
            hostId: 4,
            hostname: "printer.local"
        )
        let revision = ScoutMimicRevision(
            id: 20,
            bindAddress: "192.168.1.203",
            port: 9100,
            status: "active",
            connectionCount: 7
        )

        let updated = ScoutRefreshPolicy.applying([revision], to: [mimic])

        #expect(updated[0].connectionCount == 7)
    }

    @Test("An in-flight fake-host action presents and disables lifecycle work")
    func localLifecycleActionIsImmediatelyVisible() {
        #expect(
            ScoutLifecyclePresentation.activityLabel(
                serverLabel: "Idle",
                actionInFlight: true
            ) == "Updating"
        )
        #expect(
            ScoutLifecyclePresentation.controlsDisabled(
                serverBusy: false,
                actionInFlight: true
            )
        )
        #expect(
            ScoutLifecyclePresentation.controlsDisabled(
                serverBusy: true,
                actionInFlight: false
            )
        )
        #expect(
            !ScoutLifecyclePresentation.controlsDisabled(
                serverBusy: false,
                actionInFlight: false
            )
        )
    }

    private func makeDecoy(id: Int, type: String, status: String) -> DecoySummary {
        DecoySummary(
            id: id,
            name: "Decoy \(id)",
            decoyType: type,
            bindAddress: type == "mimic" ? "192.168.1.\(200 + id)" : "0.0.0.0",
            port: 80,
            status: status,
            connectionCount: 0,
            credentialTripCount: 0,
            createdAt: "2026-07-23T00:00:00Z",
            updatedAt: "2026-07-23T00:00:00Z"
        )
    }

    private func makeMimicRevisions(count: Int) -> [ScoutMimicRevision] {
        (0..<count).map {
            ScoutMimicRevision(
                id: $0,
                bindAddress: "192.168.1.\(200 + $0)",
                port: 80,
                status: "active",
                connectionCount: 0
            )
        }
    }
}
