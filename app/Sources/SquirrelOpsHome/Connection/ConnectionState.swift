import Foundation

/// Represents the connection lifecycle between the macOS app and the sensor.
///
/// State transitions:
/// ```
/// disconnected -> connecting -> connected -> syncing -> live
///       ^                                                  |
///       +--------------------------------------------------+
///
/// connecting -> [health OK, status 403] -> authFailed
/// authFailed -> [user taps Re-pair]     -> disconnected -> SetupFlow
/// syncing -> [API protocol mismatch]    -> incompatible
/// ```
public enum ConnectionState: String, Sendable {
    case disconnected
    case connecting
    case connected
    case syncing
    case live
    /// Sensor is reachable but our credentials were rejected (pairing lost).
    /// Terminal state — no reconnect. User must re-pair.
    case authFailed
    /// App and sensor component versions may differ, but their explicit API
    /// protocol contracts must match. Terminal state; no blind reconnect.
    case incompatible

    /// Whether the connection is in a usable state where REST requests can be made.
    /// Returns true for `.connected`, `.syncing`, and `.live`.
    public var isUsable: Bool {
        switch self {
        case .connected, .syncing, .live:
            return true
        case .disconnected, .connecting, .authFailed, .incompatible:
            return false
        }
    }
}
