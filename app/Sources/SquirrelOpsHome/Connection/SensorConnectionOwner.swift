import Foundation

/// App-scoped ownership, independent of the main window's appearance cycle.
@MainActor
final class SensorConnectionOwner {
    private var service: SensorConnectionService?
    private var connectionTask: Task<Void, Never>?
    private struct Identity: Equatable {
        let id: Int
        let baseURL: URL
        let fingerprint: String
        let credentialIdentifier: String
    }
    private var identity: Identity?

    func connect(
        to sensor: PairingManager.PairedSensor,
        makeService: () throws -> SensorConnectionService
    ) rethrows {
        let identity = Identity(id: sensor.id, baseURL: sensor.baseURL,
            fingerprint: sensor.certFingerprint, credentialIdentifier: sensor.credentialIdentifier)
        guard self.identity != identity || service == nil else { return }
        disconnect()
        let service = try makeService()
        self.service = service
        self.identity = identity
        connectionTask = Task {
            guard !Task.isCancelled else { return }
            await service.connect(baseURL: sensor.baseURL, certFingerprint: sensor.certFingerprint)
        }
    }

    func disconnect() {
        connectionTask?.cancel()
        connectionTask = nil
        service?.disconnect()
        service = nil
        identity = nil
    }
}
