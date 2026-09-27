import Darwin
import Foundation

/// Owns one accepted descriptor and its existing guest connection allowance.
final class RelayConnection: @unchecked Sendable {
    let descriptor: Int32
    private let limiter: ConnectionLimiter
    private let lock = NSLock()
    private var closed = false

    init?(descriptor: Int32, limiter: ConnectionLimiter) {
        guard limiter.acquire() else {
            Darwin.close(descriptor)
            return nil
        }
        self.descriptor = descriptor
        self.limiter = limiter
    }

    func close() {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return }
        closed = true
        shutdown(descriptor, SHUT_RDWR)
        Darwin.close(descriptor)
        limiter.release()
    }

    deinit { close() }
}

enum RelayOutcome: String, Sendable {
    case guestConnected = "guest_connected"
    case capacityRejected = "capacity_rejected"
    case guestConnectFailed = "guest_connect_failed"
    case guestConnectTimeout = "guest_connect_timeout"
}

func guestConnectionHandler(
    limiter: ConnectionLimiter,
    onConnection: @escaping @Sendable (PeerEndpoint, RelayOutcome) -> Void,
    onAccepted: @escaping @MainActor @Sendable (RelayConnection, PeerEndpoint) async -> RelayOutcome
) -> TCPListener.Handler {
    { descriptor, peer in
        // Reserve on the listener queue, before another MainActor task or fd can
        // accumulate. The existing ceiling includes queued and connected peers.
        let connection = RelayConnection(descriptor: descriptor, limiter: limiter)
        guard let connection else {
            onConnection(peer, .capacityRejected)
            return
        }
        Task { @MainActor in
            let outcome = await onAccepted(connection, peer)
            onConnection(peer, outcome)
        }
    }
}
