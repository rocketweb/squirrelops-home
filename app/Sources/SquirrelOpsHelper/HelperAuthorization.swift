// Keep helper authorization outside main.swift. Swift 6.0.3 in Xcode 16.2 can
// crash while lowering closures that call a function capturing executable
// top-level state from main.swift.
#if canImport(Darwin)
import Darwin
#endif

// Optional dedicated service account the sensor may run as (provisioned by the
// installer for a non-root .pkg deployment). Resolved at startup if present.
let sensorServiceAccount = "_squirrelops"

/// UID of the optional dedicated service account, if it has been provisioned.
func serviceAccountUID() -> uid_t? {
    guard let pw = getpwnam(sensorServiceAccount) else { return nil }
    return pw.pointee.pw_uid
}

/// Whether a connecting peer UID is allowed to drive privileged operations.
/// Permits root and the provisioned sensor service account.
func isAuthorizedPeer(_ uid: uid_t) -> Bool {
    isAuthorizedPeer(uid, serviceUID: serviceAccountUID())
}

/// Pure authorization rule used by the socket server and regression tests.
func isAuthorizedPeer(_ uid: uid_t, serviceUID: uid_t?) -> Bool {
    if uid == 0 { return true }
    if let serviceUID, uid == serviceUID { return true }
    return false
}
