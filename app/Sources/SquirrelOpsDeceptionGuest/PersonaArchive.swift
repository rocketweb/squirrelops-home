import Foundation

struct PersonaArchive: Equatable, Sendable {
    static let maximumBytes = 512 * 1024

    let data: Data

    static func read(from handle: FileHandle) throws -> PersonaArchive {
        guard let prefix = try handle.read(upToCount: 4), prefix.count == 4 else {
            throw GuestRuntimeFailure.invalidPersonaArchive
        }
        let length = prefix.reduce(0) { partial, byte in
            (partial << 8) | Int(byte)
        }
        guard length > 0, length <= maximumBytes else {
            throw GuestRuntimeFailure.invalidPersonaArchive
        }
        var frame = prefix
        var remaining = length
        while remaining > 0 {
            guard let chunk = try handle.read(upToCount: remaining), !chunk.isEmpty else {
                throw GuestRuntimeFailure.invalidPersonaArchive
            }
            frame.append(chunk)
            remaining -= chunk.count
        }
        let trailing = try handle.read(upToCount: 1)
        guard trailing == nil || trailing?.isEmpty == true else {
            throw GuestRuntimeFailure.invalidPersonaArchive
        }
        return try decodeFrame(frame)
    }

    static func decodeFrame(_ frame: Data) throws -> PersonaArchive {
        guard frame.count >= 4 else {
            throw GuestRuntimeFailure.invalidPersonaArchive
        }
        let length = frame.prefix(4).reduce(0) { partial, byte in
            (partial << 8) | Int(byte)
        }
        guard length > 0,
              length <= maximumBytes,
              frame.count == length + 4
        else {
            throw GuestRuntimeFailure.invalidPersonaArchive
        }
        let archive = Data(frame.dropFirst(4))
        guard archive.count > 262,
              archive.subdata(in: 257..<262) == Data("ustar".utf8)
        else {
            throw GuestRuntimeFailure.invalidPersonaArchive
        }
        return PersonaArchive(data: archive)
    }
}
