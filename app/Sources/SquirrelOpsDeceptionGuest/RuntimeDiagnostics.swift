import Dispatch
import Foundation

// Internal checkpoints only. No peer addresses, payloads, names, paths or
// exception descriptions. Neither the budget nor sink affects admission.
enum RelayCheckpoint: String, Sendable, CaseIterable {
    case listenerActivated = "listener_activated"
    case listenerReadable = "listener_readable"
    case acceptFailed = "accept_failed"
    case clientSetupFailed = "client_setup_failed"
    case accepted = "accepted"
    case mainActorEntered = "main_actor_entered"
    case capacityRejected = "capacity_rejected"
    case guestConnectStarted = "guest_connect_started"
    case guestConnected = "guest_connected"
    case guestConnectFailed = "guest_connect_failed"
    case guestConnectTimeout = "guest_connect_timeout"
    case relayStarted = "relay_started"
    case firstRead = "first_read"
    case readEOF = "read_eof"
    case readFailed = "read_failed"
    case writeFailed = "write_failed"
    case pollFailed = "poll_failed"
    case nonblockingFailed = "nonblocking_failed"
    case relayTimedOut = "relay_timed_out"
    case relayClosed = "relay_closed"
    case diagnosticsTruncated = "diagnostics_truncated"
}

enum RelayDirection: String, Sendable { case none, clientToGuest = "client_to_guest", guestToClient = "guest_to_client" }

struct RelayDiagnostic: Sendable {
    let stage: RelayCheckpoint
    let servicePort: UInt16
    let connectionID: Int
    let sequence: Int
    let errorNumber: Int32
    let direction: RelayDirection

    var payload: [String: Any] {
        ["event": "runtime_diagnostic", "stage": stage.rawValue,
         "service_port": Int(servicePort), "connection_id": connectionID,
         "sequence": sequence, "errno": Int(errorNumber), "direction": direction.rawValue]
    }
}

final class RuntimeDiagnostics: @unchecked Sendable {
    static let maximumRecords = 512
    private let lock = NSLock()
    private let queue = DispatchQueue(label: "com.squirrelops.deception.diagnostics")
    private let sink: @Sendable (RelayDiagnostic) -> Void
    private var records = 0
    private var connections = 0

    init(sink: @escaping @Sendable (RelayDiagnostic) -> Void) { self.sink = sink }

    func service(_ port: UInt16) -> RelayDiagnosticContext {
        RelayDiagnosticContext(owner: self, port: port, connectionID: 0)
    }

    fileprivate func connection(port: UInt16) -> RelayDiagnosticContext {
        lock.lock()
        defer { lock.unlock() }
        // Stop growing identifiers once diagnostics are exhausted, not sockets.
        if records < Self.maximumRecords { connections += 1 }
        return RelayDiagnosticContext(owner: self, port: port, connectionID: connections)
    }

    fileprivate func record(_ stage: RelayCheckpoint, port: UInt16, connectionID: Int,
                            errorNumber: Int32, direction: RelayDirection) {
        lock.lock()
        defer { lock.unlock() }
        guard records <= Self.maximumRecords else { return }
        let effectiveStage: RelayCheckpoint = records == Self.maximumRecords ? .diagnosticsTruncated : stage
        records += 1
        let record = RelayDiagnostic(stage: effectiveStage, servicePort: port,
                                     connectionID: connectionID, sequence: records,
                                     errorNumber: errorNumber, direction: direction)
        // Bounded to 512 records plus one truncation marker per VM. A stalled
        // output consumer never blocks a listener/relay on a pipe write.
        queue.async { [sink] in sink(record) }
    }

    // Test synchronization only. Runtime network paths never wait on this queue.
    func flushForTesting() { queue.sync {} }
}

struct RelayDiagnosticContext: Sendable {
    fileprivate let owner: RuntimeDiagnostics
    fileprivate let port: UInt16
    fileprivate let connectionID: Int

    func connection() -> Self { owner.connection(port: port) }
    func record(_ stage: RelayCheckpoint, errno: Int32 = 0, direction: RelayDirection = .none) {
        owner.record(stage, port: port, connectionID: connectionID, errorNumber: errno, direction: direction)
    }
}
