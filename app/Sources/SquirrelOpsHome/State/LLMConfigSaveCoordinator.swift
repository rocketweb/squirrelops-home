import Foundation

/// Serializes debounced LLM configuration writes so an older request can
/// never finish after and overwrite a newer provider or credential choice.
@MainActor
final class LLMConfigSaveCoordinator {
    private var pending: Task<Void, Never>?

    func submit(
        delay: Duration = .seconds(1),
        operation: @escaping @MainActor @Sendable () async -> Void
    ) {
        let previous = pending
        previous?.cancel()
        pending = Task { @MainActor in
            // A cancelled URL request may already be executing on the sensor.
            // Wait for it to finish before dispatching the newest snapshot.
            if let previous {
                await previous.value
            }
            guard !Task.isCancelled else { return }
            do {
                try await Task.sleep(for: delay)
            } catch {
                return
            }
            guard !Task.isCancelled else { return }
            await operation()
        }
    }

    func waitForIdle() async {
        await pending?.value
    }
}
