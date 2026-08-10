import Foundation
import Testing
@testable import SquirrelOpsHome

@Suite("SemanticVersion")
struct SemanticVersionTests {

    @Test("Parses the tag schemes already in use", arguments: [
        ("home-v2.0.1", SemanticVersion(major: 2, minor: 0, patch: 1)),
        ("v1.1.14", SemanticVersion(major: 1, minor: 1, patch: 14)),
        ("2.1.0", SemanticVersion(major: 2, minor: 1, patch: 0)),
    ])
    func parsesKnownSchemes(raw: String, expected: SemanticVersion) {
        #expect(SemanticVersion(parsing: raw) == expected)
    }

    @Test("Parses a prefix it has never seen before")
    func parsesUnknownPrefix() {
        // The old parser silently produced 0.0 here and reported "up to date".
        #expect(
            SemanticVersion(parsing: "sensor-v3.0.0")
                == SemanticVersion(major: 3, minor: 0, patch: 0)
        )
    }

    @Test("Treats a missing patch component as zero")
    func defaultsPatchToZero() {
        #expect(
            SemanticVersion(parsing: "v2.1") == SemanticVersion(major: 2, minor: 1, patch: 0)
        )
    }

    @Test("Ignores a prerelease or build suffix")
    func ignoresSuffix() {
        #expect(
            SemanticVersion(parsing: "2.1.0-beta.4")
                == SemanticVersion(major: 2, minor: 1, patch: 0)
        )
    }

    @Test("Skips a bare number in the prefix and finds the real version")
    func skipsLeadingNumberInPrefix() {
        #expect(
            SemanticVersion(parsing: "release-2024-v1.2.3")
                == SemanticVersion(major: 1, minor: 2, patch: 3)
        )
    }

    @Test("Parses a date-style version")
    func parsesDateStyle() {
        #expect(
            SemanticVersion(parsing: "2026.07.27")
                == SemanticVersion(major: 2026, minor: 7, patch: 27)
        )
    }

    @Test("Returns nil rather than guessing", arguments: [
        "",
        "latest",
        "v2",
        "nightly-build",
    ])
    func returnsNilWhenUnparseable(raw: String) {
        #expect(SemanticVersion(parsing: raw) == nil)
    }

    @Test("Orders by major, then minor, then patch")
    func ordering() {
        let base = SemanticVersion(major: 2, minor: 1, patch: 3)
        #expect(SemanticVersion(major: 3, minor: 0, patch: 0) > base)
        #expect(SemanticVersion(major: 2, minor: 2, patch: 0) > base)
        #expect(SemanticVersion(major: 2, minor: 1, patch: 4) > base)
        #expect(SemanticVersion(major: 1, minor: 9, patch: 9) < base)
        #expect(SemanticVersion(major: 2, minor: 1, patch: 3) == base)
    }

    @Test("Compares multi-digit components numerically, not lexically")
    func comparesNumerically() {
        // "1.1.14" vs "1.1.9" is the case a string comparison gets wrong.
        #expect(
            SemanticVersion(parsing: "v1.1.14")! > SemanticVersion(parsing: "v1.1.9")!
        )
    }

    @Test("Round-trips through its description")
    func describesItself() {
        #expect(SemanticVersion(parsing: "home-v2.0.1")?.description == "2.0.1")
    }
}
