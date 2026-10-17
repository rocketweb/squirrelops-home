import Darwin
import Foundation

/// Streams the guest's syslog ring over a dedicated vsock port and emits one
/// attributed telemetry record per authentication line.
///
/// The guest side is `socat -U VSOCK-LISTEN:10514 EXEC:"logread -f"` in
/// `guest/studio-mini/rootfs/sbin/init`. The channel is read-only from the
/// host's point of view and carries only what `sshd` and `smbd` chose to log.
/// It is not the relay: no client bytes ever travel on it.
///
/// Readiness depends on it. A runtime without the channel would silently lose
/// every login, which is the gap this exists to close, so `start()` fails the
/// same way a missing SSH or SMB service does.
@MainActor
final class GuestAuthenticationChannel {
    static let guestVSOCKPort: UInt32 = 10_514

    typealias Connector = @MainActor () async throws -> any RelayGuestConnection

    private let attribution: RelayAttributionTable
    private let output: RuntimeOutput
    private let connect: Connector
    private var current: (any RelayGuestConnection)?
    private var loop: Task<Void, Never>?
    private var stopped = false

    init(attribution: RelayAttributionTable, output: RuntimeOutput, connect: @escaping Connector) {
        self.attribution = attribution
        self.output = output
        self.connect = connect
    }

    /// Connect with the same retry budget as the relay services, then keep
    /// the stream alive for the life of the runtime.
    func start(attempts: Int = 240, backoff: Duration = .milliseconds(250)) async throws {
        var connection: (any RelayGuestConnection)?
        for attempt in 0..<attempts {
            do {
                connection = try await connect()
                break
            } catch {
                if attempt == attempts - 1 { throw error }
                try await Task.sleep(for: backoff)
            }
        }
        guard let first = connection else {
            throw GuestRuntimeFailure.guestServiceUnavailable(Self.guestVSOCKPort)
        }
        current = first
        loop = Task { @MainActor [weak self] in
            await self?.run(initial: first)
        }
    }

    func stop() {
        stopped = true
        loop?.cancel()
        loop = nil
        if let current {
            // Unblocks the reader thread; the loop sees EOF and exits.
            shutdown(current.fileDescriptor, SHUT_RDWR)
            current.close()
        }
        current = nil
    }

    private func run(initial: any RelayGuestConnection) async {
        var connection: (any RelayGuestConnection)? = initial
        var delay: Duration = .milliseconds(250)
        while !stopped {
            if let active = connection {
                // Only the descriptor crosses to the reader thread; the
                // connection object stays isolated here.
                await Self.pump(descriptor: active.fileDescriptor, attribution: attribution, output: output)
                active.close()
                if current === active { current = nil }
                connection = nil
                delay = .milliseconds(250)
            }
            if stopped { return }
            // The guest listener forks per connection, so a dropped stream is
            // recoverable. Lines logged while disconnected are not replayed:
            // `logread -f` is new-lines-only on purpose, because replaying the
            // ring on reconnect would re-emit every earlier login.
            try? await Task.sleep(for: delay)
            if stopped { return }
            do {
                let next = try await connect()
                current = next
                connection = next
            } catch {
                delay = min(delay * 2, .seconds(5))
            }
        }
    }

    /// Blocking reads on a utility queue; returns at EOF or error.
    private nonisolated static func pump(
        descriptor: Int32,
        attribution: RelayAttributionTable,
        output: RuntimeOutput
    ) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            DispatchQueue.global(qos: .utility).async {
                var buffer = [UInt8](repeating: 0, count: 4096)
                var pending: [UInt8] = []
                var discarding = false
                let limit = GuestAuthenticationParser.maximumLineLength
                while true {
                    let count = Darwin.read(descriptor, &buffer, buffer.count)
                    if count == 0 { break }
                    if count < 0 {
                        if errno == EINTR { continue }
                        break
                    }
                    for byte in buffer[0..<count] {
                        if byte == UInt8(ascii: "\n") {
                            if !discarding {
                                handle(line: pending, attribution: attribution, output: output)
                            }
                            pending.removeAll(keepingCapacity: true)
                            discarding = false
                            continue
                        }
                        if discarding { continue }
                        pending.append(byte)
                        if pending.count > limit {
                            // Oversized record: drop it whole, resynchronize at
                            // the next newline, never let its tail become a line.
                            pending.removeAll(keepingCapacity: true)
                            discarding = true
                        }
                    }
                }
                continuation.resume()
            }
        }
    }

    private nonisolated static func handle(
        line bytes: [UInt8],
        attribution: RelayAttributionTable,
        output: RuntimeOutput
    ) {
        guard !bytes.isEmpty else { return }
        let line = String(decoding: bytes, as: UTF8.self)
        guard let event = GuestAuthenticationParser.parse(line) else { return }
        let peer = attribution.resolve(localPort: event.localPort, service: event.service)
        output.write(GuestAuthenticationTelemetry.payload(
            for: event,
            peer: peer,
            timestamp: ISO8601DateFormatter().string(from: Date())
        ))
    }
}
