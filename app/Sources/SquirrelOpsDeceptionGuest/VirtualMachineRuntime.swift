import Dispatch
import Foundation
import Virtualization

private struct SocketConnectionTransfer: @unchecked Sendable {
    let value: VZVirtioSocketConnection
}

final class RuntimeOutput: @unchecked Sendable {
    private let lock = NSLock()

    func write(_ value: [String: Any]) {
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value),
              var line = String(data: data, encoding: .utf8)
        else { return }
        line.append("\n")
        lock.lock()
        FileHandle.standardOutput.write(Data(line.utf8))
        lock.unlock()
    }
}

@MainActor
final class VirtualMachineRuntime: NSObject, @preconcurrency VZVirtualMachineDelegate {
    private let manifest: ValidatedGuestManifest
    private let bindAddress: String
    private let personaArchive: PersonaArchive
    private let output: RuntimeOutput
    private let limiter: ConnectionLimiter
    private let virtualMachine: VZVirtualMachine
    private var socketDevice: VZVirtioSocketDevice?
    private var listeners: [UInt16: TCPListener] = [:]
    private var stopContinuation: CheckedContinuation<Void, Never>?
    private var stopped = false

    init(
        manifest: ValidatedGuestManifest,
        bindAddress: String,
        personaArchive: PersonaArchive,
        output: RuntimeOutput
    ) throws {
        guard VZVirtualMachine.isSupported else {
            throw GuestRuntimeFailure.unsupportedHost
        }
        let configuration = try manifest.makeVirtualMachineConfiguration()
        do {
            try configuration.validate()
        } catch {
            throw GuestRuntimeFailure.invalidVirtualMachine(error.localizedDescription)
        }
        self.manifest = manifest
        self.bindAddress = bindAddress
        self.personaArchive = personaArchive
        self.output = output
        limiter = ConnectionLimiter(maximum: manifest.manifest.resources.maxConnections)
        virtualMachine = VZVirtualMachine(configuration: configuration)
        super.init()
        virtualMachine.delegate = self
    }

    func start() async throws -> [UInt16: UInt16] {
        try await withCheckedThrowingContinuation { continuation in
            virtualMachine.start { result in
                continuation.resume(with: result)
            }
        }
        guard let device = virtualMachine.socketDevices.first as? VZVirtioSocketDevice else {
            throw GuestRuntimeFailure.missingSocketDevice
        }
        socketDevice = device
        try await sendPersonaArchive(device: device)
        for service in manifest.manifest.services {
            try await waitForGuestService(service.guestVSOCKPort, device: device)
        }

        var ports: [UInt16: UInt16] = [:]
        for service in manifest.manifest.services {
            let handler = guestConnectionHandler(
                limiter: limiter,
                onConnection: { [output] peer in
                    output.write([
                        "event": "connection",
                        "source_ip": peer.address,
                        "source_port": Int(peer.port),
                        "dest_port": Int(service.advertisedPort),
                        "protocol": "tcp",
                        "interaction_type": "\(service.name).connection",
                        "timestamp": ISO8601DateFormatter().string(from: Date()),
                    ])
                },
                onAccepted: { [weak self] connection, _ in
                    await self?.accept(
                        connection: connection,
                        service: service
                    )
                }
            )
            let listener = try TCPListener(bindAddress: bindAddress, handler: handler)
            listeners[service.advertisedPort] = listener
            ports[service.advertisedPort] = listener.localPort
        }
        return ports
    }

    private func sendPersonaArchive(device: VZVirtioSocketDevice) async throws {
        for attempt in 0..<240 {
            do {
                let connection = try await connect(device: device, port: 10_000)
                try writeAll(personaArchive.data, to: connection.fileDescriptor)
                shutdown(connection.fileDescriptor, SHUT_WR)
                connection.close()
                return
            } catch {
                if attempt == 239 {
                    throw GuestRuntimeFailure.guestServiceUnavailable(10_000)
                }
                try await Task.sleep(for: .milliseconds(250))
            }
        }
    }

    private func writeAll(_ data: Data, to descriptor: Int32) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else {
                throw GuestRuntimeFailure.invalidPersonaArchive
            }
            var written = 0
            while written < rawBuffer.count {
                let result = Darwin.write(
                    descriptor,
                    baseAddress.advanced(by: written),
                    rawBuffer.count - written
                )
                if result < 0 {
                    if errno == EINTR { continue }
                    throw GuestRuntimeFailure.listenerFailure("persona transfer")
                }
                if result == 0 {
                    throw GuestRuntimeFailure.listenerFailure("persona transfer")
                }
                written += result
            }
        }
    }

    func activateListeners() {
        for listener in listeners.values {
            listener.start()
        }
    }

    private func waitForGuestService(
        _ port: UInt32,
        device: VZVirtioSocketDevice
    ) async throws {
        for _ in 0..<240 {
            do {
                let connection = try await connect(device: device, port: port)
                connection.close()
                return
            } catch {
                try await Task.sleep(for: .milliseconds(250))
            }
        }
        throw GuestRuntimeFailure.guestServiceUnavailable(port)
    }

    private func connect(
        device: VZVirtioSocketDevice,
        port: UInt32
    ) async throws -> VZVirtioSocketConnection {
        let transferred: SocketConnectionTransfer = try await withCheckedThrowingContinuation { continuation in
            device.connect(toPort: port) { result in
                switch result {
                case let .success(connection):
                    continuation.resume(
                        returning: SocketConnectionTransfer(value: connection)
                    )
                case let .failure(error):
                    continuation.resume(throwing: error)
                }
            }
        }
        return transferred.value
    }

    private func accept(
        connection: RelayConnection,
        service: GuestManifest.Service
    ) async {
        // The connection owns its fd and allowance even if this guard fails.
        guard let socketDevice else { return }
        do {
            let guestConnection = try await connect(
                device: socketDevice,
                port: service.guestVSOCKPort
            )
            SocketRelay(
                client: connection,
                guestConnection: guestConnection
            ).start()
        } catch {
            connection.close()
        }
    }

    func waitUntilStopped() async {
        if stopped { return }
        await withCheckedContinuation { continuation in
            stopContinuation = continuation
        }
    }

    func stop() async {
        guard !stopped else { return }
        for listener in listeners.values {
            listener.stop()
        }
        listeners.removeAll()
        if virtualMachine.canStop {
            await withCheckedContinuation { continuation in
                virtualMachine.stop { _ in continuation.resume() }
            }
        }
        completeStop()
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        completeStop()
    }

    func virtualMachine(
        _ virtualMachine: VZVirtualMachine,
        didStopWithError error: any Error
    ) {
        output.write(["event": "guest_error", "message": error.localizedDescription])
        completeStop()
    }

    private func completeStop() {
        guard !stopped else { return }
        stopped = true
        stopContinuation?.resume()
        stopContinuation = nil
    }
}
