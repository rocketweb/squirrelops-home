import Foundation
import SquirrelOpsLocalEnrollment
import Testing

@testable import SquirrelOpsHelper

private final class RecordingEnrollmentRequirementSetter:
    EnrollmentCodeSigningRequirementSetting
{
    private(set) var requirement: String?

    func setConnectionCodeSigningRequirement(_ requirement: String) {
        self.requirement = requirement
    }
}

@Suite("Local enrollment boundary")
struct LocalEnrollmentTests {
    @Test("listener applies the exact app code requirement")
    func listenerAppliesAppCodeRequirement() {
        let recorder = RecordingEnrollmentRequirementSetter()

        applyEnrollmentAppCodeRequirement(
            LocalEnrollmentXPC.appCodeRequirement,
            to: recorder
        )

        #expect(recorder.requirement == LocalEnrollmentXPC.appCodeRequirement)
    }

    @Test("local test XPC binds to the exact root-installed app code hash")
    func localTestRequirementUsesExactCodeHash() throws {
        let designatedRequirement =
            "cdhash H\"9a4946f87ac77bd1f9b4c644aace16b7927941d2\""

        #expect(try LocalEnrollmentCodeRequirementPolicy.select(
            isLocalTestBuild: true,
            installedAppIsRootSecured: true,
            installedAppDesignatedRequirement: designatedRequirement
        ) == designatedRequirement)
        #expect(throws: LocalEnrollmentCodeRequirementError.self) {
            try LocalEnrollmentCodeRequirementPolicy.select(
                isLocalTestBuild: true,
                installedAppIsRootSecured: false,
                installedAppDesignatedRequirement: designatedRequirement
            )
        }
        #expect(throws: LocalEnrollmentCodeRequirementError.self) {
            try LocalEnrollmentCodeRequirementPolicy.select(
                isLocalTestBuild: true,
                installedAppIsRootSecured: true,
                installedAppDesignatedRequirement:
                    "identifier \"com.squirrelops.home\""
            )
        }
    }

    @Test("release XPC keeps the Developer ID app requirement")
    func releaseRequirementKeepsTeamIdentity() throws {
        #expect(try LocalEnrollmentCodeRequirementPolicy.select(
            isLocalTestBuild: false,
            installedAppIsRootSecured: false,
            installedAppDesignatedRequirement: nil
        ) == LocalEnrollmentXPC.appCodeRequirement)
    }

    @Test("authorizes only the active console user after XPC signature validation", arguments: [
        (uid: uid_t(501), consoleUID: uid_t(501), expected: true),
        (uid: uid_t(502), consoleUID: uid_t(501), expected: false),
    ])
    func enrollmentPeerAuthorization(
        argument: (uid: uid_t, consoleUID: uid_t, expected: Bool)
    ) {
        #expect(isAuthorizedEnrollmentConsolePeer(
            uid: argument.uid,
            consoleUID: argument.consoleUID
        ) == argument.expected)

        #expect(isAuthorizedEnrollmentConsolePeer(
            uid: argument.uid,
            consoleUID: nil
        ) == false)
    }

    @Test("shared enrollment payload uses the sensor wire keys")
    func sharedEnrollmentCoding() throws {
        let request = LocalEnrollmentRequest(
            requestID: "fa30c034-e031-4b12-947a-01489b5d5e66",
            clientName: "Matt's Mac",
            csrPEM: "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"
        )
        let object = try JSONSerialization.jsonObject(
            with: JSONEncoder().encode(request)
        ) as? [String: Any]

        #expect(object?["request_id"] as? String == request.requestID)
        #expect(object?["client_name"] as? String == request.clientName)
        #expect(object?["csr_pem"] as? String == request.csrPEM)
        #expect(object?["requestID"] == nil)
    }

    @Test("helper rejects malformed enrollment before opening the sensor socket")
    func rejectsMalformedRequest() {
        let client = LocalSensorEnrollmentClient(
            socketPath: "/path/that/must/not/be-opened"
        )
        #expect(throws: LocalSensorEnrollmentError.invalidRequest) {
            try client.enroll(requestData: Data("{}".utf8))
        }
    }
}
