import Foundation

struct GuestArguments: Equatable, Sendable {
    let bundleURL: URL
    let stateDirectoryURL: URL
    let bindAddress: String

    static func parse(_ arguments: [String]) throws -> GuestArguments {
        var values: [String: String] = [:]
        var index = 0
        while index < arguments.count {
            let key = arguments[index]
            guard ["--bundle", "--state-dir", "--bind-address"].contains(key),
                  index + 1 < arguments.count,
                  values[key] == nil
            else {
                throw GuestRuntimeFailure.invalidArguments
            }
            values[key] = arguments[index + 1]
            index += 2
        }
        guard values.count == 3,
              let bundle = values["--bundle"],
              let stateDirectory = values["--state-dir"],
              let bindAddress = values["--bind-address"]
        else {
            throw GuestRuntimeFailure.invalidArguments
        }

        return GuestArguments(
            bundleURL: URL(fileURLWithPath: bundle, isDirectory: true).standardizedFileURL,
            stateDirectoryURL: URL(
                fileURLWithPath: stateDirectory,
                isDirectory: true
            ).standardizedFileURL,
            bindAddress: bindAddress
        )
    }
}

enum GuestRuntimeFailure: LocalizedError {
    case invalidArguments
    case invalidPersonaArchive
    case invalidManifest(String)
    case unsafeFile(String)
    case digestMismatch(String)
    case unsupportedHost
    case invalidVirtualMachine(String)
    case missingSocketDevice
    case guestServiceUnavailable(UInt32)
    case listenerFailure(String)

    var errorDescription: String? {
        switch self {
        case .invalidArguments:
            "Expected --bundle, --state-dir, and --bind-address exactly once."
        case .invalidPersonaArchive:
            "The persona archive is missing, oversized, truncated, or not a tar archive."
        case let .invalidManifest(reason):
            "Guest manifest is invalid: \(reason)"
        case let .unsafeFile(name):
            "Guest file is unsafe: \(name)"
        case let .digestMismatch(name):
            "Guest file digest does not match: \(name)"
        case .unsupportedHost:
            "Virtualization.framework is unavailable on this Mac."
        case let .invalidVirtualMachine(reason):
            "Virtual machine configuration is invalid: \(reason)"
        case .missingSocketDevice:
            "Virtual machine did not expose its Virtio socket device."
        case let .guestServiceUnavailable(port):
            "Guest service did not become available on Virtio socket port \(port)."
        case let .listenerFailure(reason):
            "Guest TCP listener failed: \(reason)"
        }
    }
}
