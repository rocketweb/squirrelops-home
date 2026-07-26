import Testing

@testable import SquirrelOpsHome

private actor TestLatch {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if isOpen {
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func open() {
        isOpen = true
        let pending = waiters
        waiters.removeAll()
        for continuation in pending {
            continuation.resume()
        }
    }
}

@Suite("LLM config save coordinator")
struct LLMConfigSaveCoordinatorTests {
    @Test("Latest save waits for an older non-cooperative request")
    @MainActor
    func latestSaveCannotBeOverwrittenByOlderRequest() async {
        let coordinator = LLMConfigSaveCoordinator()
        let firstStarted = TestLatch()
        let releaseFirst = TestLatch()
        var events: [String] = []

        coordinator.submit(delay: .zero) {
            events.append("old-start")
            await firstStarted.open()
            await releaseFirst.wait()
            events.append("old-finish")
        }
        await firstStarted.wait()

        coordinator.submit(delay: .zero) {
            events.append("new")
        }
        await Task.yield()
        #expect(events == ["old-start"])

        await releaseFirst.open()
        await coordinator.waitForIdle()
        #expect(events == ["old-start", "old-finish", "new"])
    }
}
