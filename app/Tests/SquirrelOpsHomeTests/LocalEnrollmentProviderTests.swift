import Foundation
import SquirrelOpsLocalEnrollment
import Testing

@testable import SquirrelOpsHome

@Suite("Local enrollment provider trust")
struct LocalEnrollmentProviderTests {
    @Test("release app requires the Developer ID helper identity")
    func releaseRequirementKeepsTeamIdentity() throws {
        #expect(try LocalEnrollmentHelperCodeRequirementPolicy.select(
            isLocalTestBuild: false,
            installedHelperIsRootSecured: false,
            installedHelperDesignatedRequirement: nil
        ) == LocalEnrollmentXPC.helperCodeRequirement)
    }

    @Test("local test app binds to the exact root-installed helper code hash")
    func localTestRequirementUsesExactCodeHash() throws {
        let designatedRequirement =
            "cdhash H\"9a4946f87ac77bd1f9b4c644aace16b7927941d2\""

        #expect(try LocalEnrollmentHelperCodeRequirementPolicy.select(
            isLocalTestBuild: true,
            installedHelperIsRootSecured: true,
            installedHelperDesignatedRequirement: designatedRequirement
        ) == designatedRequirement)
        #expect(throws: LocalEnrollmentHelperCodeRequirementError.self) {
            try LocalEnrollmentHelperCodeRequirementPolicy.select(
                isLocalTestBuild: true,
                installedHelperIsRootSecured: false,
                installedHelperDesignatedRequirement: designatedRequirement
            )
        }
        #expect(throws: LocalEnrollmentHelperCodeRequirementError.self) {
            try LocalEnrollmentHelperCodeRequirementPolicy.select(
                isLocalTestBuild: true,
                installedHelperIsRootSecured: true,
                installedHelperDesignatedRequirement:
                    "identifier \"com.squirrelops.helper\""
            )
        }
    }

    @Test("app pins the privileged helper before resuming XPC")
    func appPinsHelperBeforeConnectionResume() throws {
        let appRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: appRoot.appendingPathComponent(
                "Sources/SquirrelOpsHome/Connection/LocalEnrollmentProvider.swift"
            ),
            encoding: .utf8
        )
        let requirement = try #require(
            source.range(of: "connection.setCodeSigningRequirement(")
        )
        let resume = try #require(source.range(of: "connection.resume()"))

        #expect(requirement.lowerBound < resume.lowerBound)
    }
}
