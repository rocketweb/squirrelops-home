import Foundation

struct GuestSocketTransfer: @unchecked Sendable {
    let value: any RelayGuestConnection
}

enum GuestConnectFailure: Error { case timedOut, unavailable }

/// VZ connect has no cancellation API. A missed deadline poisons this VM's
/// connector, resumes all waiters, and refuses new work until the VM is replaced.
/// Late callbacks can only close their connection, never revive a timed-out relay.
@MainActor
final class GuestSocketConnector {
    private struct Pending {
        let continuation: CheckedContinuation<GuestSocketTransfer, any Error>
        let deadline: Task<Void, Never>
    }
    private var pending: [UUID: Pending] = [:]
    private let timeout: Duration
    private(set) var isUnavailable = false
    var pendingCount: Int { pending.count }

    init(timeout: Duration = .seconds(10)) { self.timeout = timeout }

    func connect(
        start: (@escaping @Sendable (Result<GuestSocketTransfer, any Error>) -> Void) -> Void
    ) async throws -> any RelayGuestConnection {
        guard !isUnavailable else { throw GuestConnectFailure.unavailable }
        let id = UUID()
        let result: GuestSocketTransfer = try await withCheckedThrowingContinuation { continuation in
            let deadline = Task { @MainActor [weak self, timeout] in
                do { try await Task.sleep(for: timeout) } catch { return }
                self?.expire(id)
            }
            pending[id] = Pending(continuation: continuation, deadline: deadline)
            start { [weak self] result in
                Task { @MainActor in
                    guard let self else {
                        if case let .success(connection) = result { connection.value.close() }
                        return
                    }
                    guard let attempt = self.pending.removeValue(forKey: id) else {
                        if case let .success(connection) = result { connection.value.close() }
                        return
                    }
                    attempt.deadline.cancel()
                    attempt.continuation.resume(with: result)
                }
            }
        }
        return result.value
    }

    private func expire(_ id: UUID) {
        guard pending[id] != nil else { return }
        invalidate(error: .timedOut)
    }

    func invalidate(error: GuestConnectFailure = .unavailable) {
        isUnavailable = true
        let attempts = Array(pending.values)
        pending.removeAll()
        for attempt in attempts {
            attempt.deadline.cancel()
            attempt.continuation.resume(throwing: error)
        }
    }
}
