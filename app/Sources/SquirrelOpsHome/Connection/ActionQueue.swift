import Foundation

/// A FIFO buffer for Endpoint values that should be replayed on reconnect.
/// When the queue exceeds its maximum capacity (100), the oldest entries are dropped.
public struct ActionQueue: Sendable {

    private static let maxCapacity = 100

    private var buffer: [Endpoint] = []

    public init() {}

    public var count: Int { buffer.count }
    public var isFull: Bool { buffer.count >= ActionQueue.maxCapacity }
    public var isEmpty: Bool { buffer.isEmpty }

    public mutating func enqueue(_ endpoint: Endpoint) {
        buffer.append(endpoint)
        if buffer.count > ActionQueue.maxCapacity {
            buffer.removeFirst()
        }
    }

    public mutating func dequeueAll() -> [Endpoint] {
        let result = buffer
        buffer.removeAll()
        return result
    }

    public mutating func clear() {
        buffer.removeAll()
    }
}
