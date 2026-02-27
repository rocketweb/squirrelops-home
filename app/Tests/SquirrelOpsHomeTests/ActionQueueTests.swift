import Foundation
import Testing

@testable import SquirrelOpsHome

@Suite("Action Queue")
struct ActionQueueTests {

    @Test("Enqueue increments count")
    func enqueueIncrementsCount() {
        var queue = ActionQueue()

        #expect(queue.count == 0)

        queue.enqueue(.health)
        #expect(queue.count == 1)

        queue.enqueue(.status)
        #expect(queue.count == 2)
    }

    @Test("DequeueAll returns in FIFO order and clears the queue")
    func dequeueAllReturnsFIFO() {
        var queue = ActionQueue()

        queue.enqueue(.health)
        queue.enqueue(.status)
        queue.enqueue(.profile)

        let endpoints = queue.dequeueAll()

        #expect(endpoints.count == 3)
        #expect(endpoints[0].path == "/system/health")
        #expect(endpoints[1].path == "/system/status")
        #expect(endpoints[2].path == "/system/profile")
        #expect(queue.count == 0)
        #expect(queue.isEmpty == true)
    }

    @Test("Overflow drops oldest entries when exceeding 100")
    func overflowDropsOldest() {
        var queue = ActionQueue()

        for i in 0..<100 {
            queue.enqueue(.device(id: i))
        }
        #expect(queue.count == 100)
        #expect(queue.isFull == true)

        queue.enqueue(.device(id: 999))
        #expect(queue.count == 100)

        let endpoints = queue.dequeueAll()
        #expect(endpoints[0].path == "/devices/1")
        #expect(endpoints[99].path == "/devices/999")
    }

    @Test("Clear empties the queue")
    func clearEmptiesQueue() {
        var queue = ActionQueue()

        queue.enqueue(.health)
        queue.enqueue(.status)
        queue.enqueue(.profile)
        #expect(queue.count == 3)

        queue.clear()
        #expect(queue.count == 0)
        #expect(queue.isEmpty == true)
    }

    @Test("isEmpty returns true for empty queue")
    func isEmptyWhenEmpty() {
        let queue = ActionQueue()
        #expect(queue.isEmpty == true)
        #expect(queue.isFull == false)
    }

    @Test("isFull returns true at 100 entries")
    func isFullAt100() {
        var queue = ActionQueue()

        for i in 0..<99 {
            queue.enqueue(.device(id: i))
        }
        #expect(queue.isFull == false)

        queue.enqueue(.device(id: 99))
        #expect(queue.isFull == true)
    }
}
