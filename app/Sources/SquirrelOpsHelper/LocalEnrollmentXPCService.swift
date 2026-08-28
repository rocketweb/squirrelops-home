@preconcurrency import Foundation

import SquirrelOpsLocalEnrollment

private let enrollmentErrorDomain = "com.squirrelops.helper.local-enrollment"

protocol EnrollmentCodeSigningRequirementSetting: AnyObject {
    func setConnectionCodeSigningRequirement(_ requirement: String)
}

extension NSXPCListener: EnrollmentCodeSigningRequirementSetting {}

func applyEnrollmentAppCodeRequirement(
    _ requirement: String,
    to listener: any EnrollmentCodeSigningRequirementSetting
) {
    listener.setConnectionCodeSigningRequirement(requirement)
}

func isAuthorizedEnrollmentConsolePeer(
    uid: uid_t,
    consoleUID: uid_t?
) -> Bool {
    guard let consoleUID else { return false }
    return uid == consoleUID
}

private func consoleUserUID() -> uid_t? {
    var metadata = stat()
    guard lstat("/dev/console", &metadata) == 0 else { return nil }
    return metadata.st_uid
}

private final class LocalEnrollmentService: NSObject, LocalEnrollmentXPCProtocol {
    func enrollLocalApp(
        request: Data,
        withReply reply: @escaping (Data?, NSError?) -> Void
    ) {
        do {
            let response = try LocalSensorEnrollmentClient().enroll(
                requestData: request
            )
            reply(response, nil)
        } catch {
            logger.error("Local sensor enrollment failed: \(String(describing: error))")
            reply(nil, NSError(
                domain: enrollmentErrorDomain,
                code: 2,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "The local sensor is not ready for automatic enrollment."
                ]
            ))
        }
    }
}

final class LocalEnrollmentXPCService: NSObject, NSXPCListenerDelegate {
    private let listener: NSXPCListener

    init(appCodeRequirement: String) {
        listener = NSXPCListener(
            machServiceName: LocalEnrollmentXPC.machServiceName
        )
        super.init()
        applyEnrollmentAppCodeRequirement(appCodeRequirement, to: listener)
        listener.delegate = self
    }

    func resume() {
        listener.resume()
    }

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        _ = listener
        let uid = uid_t(connection.effectiveUserIdentifier)
        // NSXPCListener enforces the configured app code-signing requirement
        // before invoking this delegate. Also bind enrollment to the active
        // console user so another signed user's app cannot request a certificate.
        guard isAuthorizedEnrollmentConsolePeer(
            uid: uid,
            consoleUID: consoleUserUID()
        ) else {
            logger.warning("Rejected unauthorized local enrollment XPC peer uid=\(uid)")
            return false
        }

        connection.exportedInterface = NSXPCInterface(
            with: LocalEnrollmentXPCProtocol.self
        )
        connection.exportedObject = LocalEnrollmentService()
        connection.resume()
        return true
    }
}
