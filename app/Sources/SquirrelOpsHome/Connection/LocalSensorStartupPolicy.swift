import Foundation

enum LocalSensorStartupPolicy {
    enum Decision: Equatable, Sendable {
        case retry
        case timedOut
        case notInstalled
    }

    static let retryInterval: Duration = .seconds(3)
    static let automaticRetryWindowSeconds = 20 * 60

    static func decision(
        isInstalled: Bool,
        elapsedSeconds: Int
    ) -> Decision {
        guard isInstalled else {
            return .notInstalled
        }
        if elapsedSeconds >= automaticRetryWindowSeconds {
            return .timedOut
        }
        return .retry
    }
}
