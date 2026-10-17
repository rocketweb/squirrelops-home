import CryptoKit
import Darwin
import Foundation
import Virtualization

struct GuestManifest: Decodable, Sendable {
    struct Artifact: Decodable, Sendable {
        let path: String
        let sha256: String
    }

    struct Boot: Decodable, Sendable {
        let kernel: Artifact
        let initialRamdisk: Artifact
        let commandLine: String

        enum CodingKeys: String, CodingKey {
            case kernel
            case initialRamdisk = "initial_ramdisk"
            case commandLine = "command_line"
        }
    }

    struct Resources: Decodable, Sendable {
        let cpuCount: Int
        let memoryBytes: UInt64
        let maxConnections: Int

        enum CodingKeys: String, CodingKey {
            case cpuCount = "cpu_count"
            case memoryBytes = "memory_bytes"
            case maxConnections = "max_connections"
        }
    }

    struct Containment: Decodable, Sendable {
        let networkDevices: Int
        let hostShares: [String]
        let clipboard: Bool
        let egress: String
        let rootFilesystem: String

        enum CodingKeys: String, CodingKey {
            case networkDevices = "network_devices"
            case hostShares = "host_shares"
            case clipboard
            case egress
            case rootFilesystem = "root_filesystem"
        }
    }

    struct Service: Decodable, Equatable, Sendable {
        let name: String
        let advertisedPort: UInt16
        let guestVSOCKPort: UInt32

        enum CodingKeys: String, CodingKey {
            case name
            case advertisedPort = "advertised_port"
            case guestVSOCKPort = "guest_vsock_port"
        }
    }

    let schemaVersion: Int
    let personaID: String
    let boot: Boot
    let resources: Resources
    let containment: Containment
    let services: [Service]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case personaID = "persona_id"
        case boot
        case resources
        case containment
        case services
    }
}

struct ValidatedGuestManifest: Sendable {
    let manifest: GuestManifest
    let kernelURL: URL
    let initialRamdiskURL: URL

    static let expectedServices = [
        GuestManifest.Service(name: "ssh", advertisedPort: 22, guestVSOCKPort: 10_022),
        GuestManifest.Service(name: "smb", advertisedPort: 445, guestVSOCKPort: 10_445),
    ]

    static func load(
        bundleURL: URL,
        trustedUIDs: Set<uid_t> = [0]
    ) throws -> ValidatedGuestManifest {
        try validateDirectory(bundleURL, trustedUIDs: trustedUIDs)
        let manifestURL = bundleURL.appendingPathComponent("manifest.json", isDirectory: false)
        try validateRegularFile(manifestURL, trustedUIDs: trustedUIDs, maximumSize: 64 * 1024)
        let manifestData = try Data(contentsOf: manifestURL, options: [.mappedIfSafe])
        let decoder = JSONDecoder()
        let manifest: GuestManifest
        do {
            manifest = try decoder.decode(GuestManifest.self, from: manifestData)
        } catch {
            throw GuestRuntimeFailure.invalidManifest("JSON does not match schema")
        }
        guard manifest.schemaVersion == 1,
              manifest.personaID == "studio-mini-v1",
              manifest.boot.commandLine == "console=hvc0 rdinit=/sbin/init",
              manifest.resources.cpuCount == 2,
              manifest.resources.memoryBytes == 1_073_741_824,
              manifest.resources.maxConnections == 16,
              manifest.containment.networkDevices == 0,
              manifest.containment.hostShares.isEmpty,
              manifest.containment.clipboard == false,
              manifest.containment.egress == "none",
              manifest.containment.rootFilesystem == "memory-only",
              manifest.services == expectedServices
        else {
            throw GuestRuntimeFailure.invalidManifest("reviewed values changed")
        }

        let kernelURL = try artifactURL(
            manifest.boot.kernel,
            bundleURL: bundleURL,
            trustedUIDs: trustedUIDs,
            maximumSize: 128 * 1024 * 1024
        )
        let initialRamdiskURL = try artifactURL(
            manifest.boot.initialRamdisk,
            bundleURL: bundleURL,
            trustedUIDs: trustedUIDs,
            maximumSize: 384 * 1024 * 1024
        )
        return ValidatedGuestManifest(
            manifest: manifest,
            kernelURL: kernelURL,
            initialRamdiskURL: initialRamdiskURL
        )
    }

    func makeVirtualMachineConfiguration() throws -> VZVirtualMachineConfiguration {
        let configuration = VZVirtualMachineConfiguration()
        let bootLoader = VZLinuxBootLoader(kernelURL: kernelURL)
        bootLoader.initialRamdiskURL = initialRamdiskURL
        bootLoader.commandLine = manifest.boot.commandLine
        configuration.bootLoader = bootLoader
        configuration.cpuCount = manifest.resources.cpuCount
        configuration.memorySize = manifest.resources.memoryBytes
        configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        configuration.socketDevices = [VZVirtioSocketDeviceConfiguration()]
        let console = VZVirtioConsoleDeviceSerialPortConfiguration()
        console.attachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: nil,
            fileHandleForWriting: .standardError
        )
        configuration.serialPorts = [console]

        // These explicit empty lists are the containment boundary. Do not add
        // a NAT adapter, bridged adapter, directory share, disk, graphics,
        // audio, USB, keyboard, or pointing device to this runtime.
        configuration.networkDevices = []
        configuration.directorySharingDevices = []
        configuration.storageDevices = []
        configuration.graphicsDevices = []
        configuration.audioDevices = []
        configuration.keyboards = []
        configuration.pointingDevices = []
        return configuration
    }

    private static func artifactURL(
        _ artifact: GuestManifest.Artifact,
        bundleURL: URL,
        trustedUIDs: Set<uid_t>,
        maximumSize: Int
    ) throws -> URL {
        guard !artifact.path.isEmpty,
              artifact.path == URL(fileURLWithPath: artifact.path).lastPathComponent,
              artifact.sha256.count == 64,
              artifact.sha256.allSatisfy({ $0.isHexDigit && !$0.isUppercase })
        else {
            throw GuestRuntimeFailure.invalidManifest("artifact descriptor")
        }
        let url = bundleURL.appendingPathComponent(artifact.path, isDirectory: false)
        try validateRegularFile(url, trustedUIDs: trustedUIDs, maximumSize: maximumSize)
        guard try digest(url) == artifact.sha256 else {
            throw GuestRuntimeFailure.digestMismatch(artifact.path)
        }
        return url
    }

    private static func validateDirectory(_ url: URL, trustedUIDs: Set<uid_t>) throws {
        var info = stat()
        guard lstat(url.path, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              trustedUIDs.contains(info.st_uid),
              info.st_mode & 0o022 == 0
        else {
            throw GuestRuntimeFailure.unsafeFile(url.lastPathComponent)
        }
    }

    private static func validateRegularFile(
        _ url: URL,
        trustedUIDs: Set<uid_t>,
        maximumSize: Int
    ) throws {
        var info = stat()
        guard lstat(url.path, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              trustedUIDs.contains(info.st_uid),
              info.st_mode & 0o022 == 0,
              info.st_size > 0,
              info.st_size <= maximumSize
        else {
            throw GuestRuntimeFailure.unsafeFile(url.lastPathComponent)
        }
    }

    private static func digest(_ url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while let data = try handle.read(upToCount: 1024 * 1024), !data.isEmpty {
            hasher.update(data: data)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
