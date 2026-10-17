import Foundation

/// The LAN endpoint behind one relayed connection.
struct RelayPeer: Equatable, Sendable {
    let address: String
    let port: UInt16
}

/// The two guest services whose logins the host attributes.
enum RelayService: String, Sendable {
    case ssh
    case smb

    init?(advertisedPort: UInt16) {
        switch advertisedPort {
        case 22: self = .ssh
        case 445: self = .smb
        default: return nil
        }
    }

    var advertisedPort: Int {
        switch self {
        case .ssh: return 22
        case .smb: return 445
        }
    }
}

/// Maps the TCP source port the guest shim binds toward `sshd`/`smbd` back to
/// the LAN peer the host relayed.
///
/// Inside the guest every login arrives from the relay at 127.0.0.1, so the
/// only identity `sshd` and `smbd` can log is that connection's source port.
/// The host owns the choice of that port: it is allocated here, sent to the
/// guest shim as a one-line preamble before any client bytes, and bound by the
/// shim with `sourceport=`. An auth log line naming the port therefore names
/// the peer exactly, with no inference from timing.
///
/// A port stays attributable for a grace window after its relay closes,
/// because the syslog line can arrive after a short session has already ended
/// (`ssh host true`). Ports are reused least recently first and never inside
/// that window, so a late line cannot be pinned on the next visitor.
final class RelayAttributionTable: @unchecked Sendable {
    private struct Entry {
        let peer: RelayPeer
        let service: RelayService
        var closedAt: TimeInterval?
    }

    private let lock = NSLock()
    private let grace: TimeInterval
    private let now: @Sendable () -> TimeInterval
    private var entries: [UInt16: Entry] = [:]
    /// Free ports in reuse order: never-used ports first, then released ports
    /// oldest first.
    private var free: [UInt16]

    init(
        range: ClosedRange<UInt16> = 20_000...29_999,
        grace: TimeInterval = 120,
        now: @escaping @Sendable () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    ) {
        self.grace = grace
        self.now = now
        free = Array(range)
    }

    var activeCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return entries.values.filter { $0.closedAt == nil }.count
    }

    /// Reserve a source port for a relay to `peer` on `service`.
    ///
    /// Returns nil only when every port is either open or still inside its
    /// grace window. With a 10,000-port range and a 16-connection ceiling that
    /// means a sustained flood, and the caller treats it as a connect failure
    /// rather than relaying a connection it could never attribute.
    func allocate(peer: RelayPeer, service: RelayService) -> UInt16? {
        lock.lock()
        defer { lock.unlock() }
        let current = now()
        // The head of the queue is the least recently released port. If even
        // that one is inside grace, nothing later in the queue can be older.
        guard let port = free.first else { return nil }
        if let closedAt = entries[port]?.closedAt, current - closedAt <= grace {
            return nil
        }
        free.removeFirst()
        entries[port] = Entry(peer: peer, service: service, closedAt: nil)
        return port
    }

    /// Mark a relay closed. Its port remains resolvable for the grace window.
    func release(_ port: UInt16) {
        lock.lock()
        defer { lock.unlock() }
        guard var entry = entries[port], entry.closedAt == nil else { return }
        entry.closedAt = now()
        entries[port] = entry
        free.append(port)
    }

    /// The peer behind a guest-side source port, if the relay is open or
    /// closed within the grace window, and the service matches.
    func resolve(localPort: UInt16, service: RelayService) -> RelayPeer? {
        lock.lock()
        defer { lock.unlock() }
        guard let entry = entries[localPort], entry.service == service else { return nil }
        if let closedAt = entry.closedAt, now() - closedAt > grace {
            return nil
        }
        return entry.peer
    }
}
