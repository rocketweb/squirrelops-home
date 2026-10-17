import CryptoKit
import Darwin
import Foundation
import Testing
import Virtualization
@testable import SquirrelOpsDeceptionGuest

@Suite("Deception guest containment")
struct GuestRuntimeTests {
    @Test("Persona input is length framed, bounded, and tar-shaped")
    func personaInput() throws {
        var archive = Data(repeating: 0, count: 1_024)
        archive.replaceSubrange(257..<262, with: Data("ustar".utf8))
        var frame = Data([
            UInt8((archive.count >> 24) & 0xff),
            UInt8((archive.count >> 16) & 0xff),
            UInt8((archive.count >> 8) & 0xff),
            UInt8(archive.count & 0xff),
        ])
        frame.append(archive)

        #expect(try PersonaArchive.decodeFrame(frame).data == archive)
        #expect(throws: GuestRuntimeFailure.self) {
            try PersonaArchive.decodeFrame(Data([0, 8, 0, 1]))
        }
    }

    @Test("Arguments accept only the reviewed runtime inputs")
    func arguments() throws {
        let parsed = try GuestArguments.parse([
            "--bundle", "/tmp/guest",
            "--state-dir", "/tmp/state",
            "--bind-address", "127.0.0.1",
        ])

        #expect(parsed.bundleURL.path == "/tmp/guest")
        #expect(parsed.stateDirectoryURL.path == "/tmp/state")
        #expect(throws: GuestRuntimeFailure.self) {
            try GuestArguments.parse([
                "--bundle", "/tmp/guest",
                "--state-dir", "/tmp/state",
                "--bind-address", "127.0.0.1",
                "--extra", "/tmp/other",
            ])
        }
    }

    @Test("Reviewed configuration has no network, host share, or persistent disk")
    func containedConfiguration() throws {
        let bundle = try makeBundle()
        defer { try? FileManager.default.removeItem(at: bundle) }
        let validated = try ValidatedGuestManifest.load(
            bundleURL: bundle,
            trustedUIDs: [getuid()]
        )

        let configuration = try validated.makeVirtualMachineConfiguration()

        #expect(configuration.networkDevices.isEmpty)
        #expect(configuration.directorySharingDevices.isEmpty)
        #expect(configuration.storageDevices.isEmpty)
        #expect(configuration.graphicsDevices.isEmpty)
        #expect(configuration.audioDevices.isEmpty)
        #expect(configuration.keyboards.isEmpty)
        #expect(configuration.pointingDevices.isEmpty)
        #expect(configuration.socketDevices.count == 1)
        #expect(configuration.serialPorts.count == 1)
        #expect(configuration.cpuCount == 2)
        #expect(configuration.memorySize == 1_073_741_824)
    }

    @Test("Manifest accepts only the reviewed SSH and SMB pair")
    func servicePair() throws {
        #expect(ValidatedGuestManifest.expectedServices == [
            GuestManifest.Service(name: "ssh", advertisedPort: 22, guestVSOCKPort: 10_022),
            GuestManifest.Service(name: "smb", advertisedPort: 445, guestVSOCKPort: 10_445),
        ])
    }

    @Test("Closed relay peers cannot terminate the runtime with SIGPIPE")
    func closedPeerDoesNotRaiseSIGPIPE() throws {
        var previous = sigaction()
        #expect(sigaction(SIGPIPE, nil, &previous) == 0)
        defer {
            var restored = previous
            sigaction(SIGPIPE, &restored, nil)
        }
        installRuntimeSignalPolicy()

        var sockets = [Int32](repeating: -1, count: 2)
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
        defer {
            if sockets[0] >= 0 { close(sockets[0]) }
            if sockets[1] >= 0 { close(sockets[1]) }
        }
        close(sockets[1])
        sockets[1] = -1

        var byte: UInt8 = 0
        let result = Darwin.write(sockets[0], &byte, 1)
        #expect(result == -1)
        #expect(errno == EPIPE)
    }

    @Test("Relay overload is rejected at the reviewed connection ceiling")
    func connectionCeiling() {
        let limiter = ConnectionLimiter(maximum: 2)

        #expect(limiter.acquire())
        #expect(limiter.acquire())
        #expect(!limiter.acquire())

        limiter.release()
        #expect(limiter.acquire())
    }

    private func makeBundle() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let kernel = Data("test-linux-kernel".utf8)
        let initramfs = Data("test-memory-only-rootfs".utf8)
        try kernel.write(to: root.appendingPathComponent("vmlinuz"))
        try initramfs.write(to: root.appendingPathComponent("studio-mini.initramfs"))
        let digest: (Data) -> String = { data in
            SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        }
        let manifest: [String: Any] = [
            "schema_version": 1,
            "persona_id": "studio-mini-v1",
            "boot": [
                "kernel": ["path": "vmlinuz", "sha256": digest(kernel)],
                "initial_ramdisk": [
                    "path": "studio-mini.initramfs",
                    "sha256": digest(initramfs),
                ],
                "command_line": "console=hvc0 rdinit=/sbin/init",
            ],
            "resources": [
                "cpu_count": 2,
                "memory_bytes": 1_073_741_824,
                "max_connections": 16,
            ],
            "containment": [
                "network_devices": 0,
                "host_shares": [],
                "clipboard": false,
                "egress": "none",
                "root_filesystem": "memory-only",
            ],
            "services": [
                ["name": "ssh", "advertised_port": 22, "guest_vsock_port": 10_022],
                ["name": "smb", "advertised_port": 445, "guest_vsock_port": 10_445],
            ],
        ]
        let data = try JSONSerialization.data(withJSONObject: manifest)
        try data.write(to: root.appendingPathComponent("manifest.json"))
        return root
    }
}
