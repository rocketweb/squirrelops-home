@preconcurrency import Foundation

import SquirrelOpsLocalEnrollment

private let enrollmentErrorDomain = "com.squirrelops.helper.local-enrollment"

func isAuthorizedEnrollmentPeer(
    uid: uid_t,
    consoleUID: uid_t?,
    signatureIsValid: Bool
) -> Bool {
    guard let consoleUID, uid == consoleUID else { return false }
    return signatureIsValid
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
        listener.setConnectionCodeSigningRequirement(
            appCodeRequirement
        )
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
        guard isAuthorizedEnrollmentPeer(
            uid: uid,
            consoleUID: consoleUserUID(),
            signatureIsValid: true
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
