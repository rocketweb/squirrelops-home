import Foundation

/// A dotted version, parsed out of a release tag.
///
/// Release tags have not used one scheme (`home-v2.0.1` and `v1.1.14` are both
/// published), so parsing looks for the version rather than assuming a fixed
/// prefix. Anything it cannot read returns `nil`, which callers must surface as
/// a failure. The alternative, guessing, produced the worst possible answer:
/// telling someone on an old build that they were up to date.
public struct SemanticVersion: Sendable, Equatable, Comparable, CustomStringConvertible {

    public let major: Int
    public let minor: Int
    public let patch: Int

    public init(major: Int, minor: Int, patch: Int = 0) {
        self.major = major
        self.minor = minor
        self.patch = patch
    }

    /// Parse the first `major.minor[.patch]` run in `raw`.
    ///
    /// A dot is required, so a bare number in a prefix cannot be mistaken for
    /// the version: `release-2024-v1.2.3` reads as `1.2.3`, not `2024`. Any
    /// trailing prerelease or build suffix is ignored.
    public init?(parsing raw: String) {
        var candidate = ""
        for character in raw {
            if character.isNumber || character == "." {
                candidate.append(character)
            } else if candidate.contains("."), candidate.first?.isNumber == true {
                // A complete run already ended; stop before the suffix.
                break
            } else {
                candidate = ""
            }
        }

        guard candidate.first?.isNumber == true else { return nil }
        let parts = candidate.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 2, let major = Int(parts[0]), let minor = Int(parts[1]) else {
            return nil
        }

        self.major = major
        self.minor = minor
        self.patch = parts.count > 2 ? (Int(parts[2]) ?? 0) : 0
    }

    public static func < (lhs: SemanticVersion, rhs: SemanticVersion) -> Bool {
        (lhs.major, lhs.minor, lhs.patch) < (rhs.major, rhs.minor, rhs.patch)
    }

    public var description: String { "\(major).\(minor).\(patch)" }
}
