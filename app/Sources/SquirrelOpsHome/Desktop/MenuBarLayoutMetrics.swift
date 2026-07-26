import Foundation

struct MenuBarLayoutMetrics: Sendable, Equatable {
    let hasUnreadAlerts: Bool
    let severityCount: Int

    let preferredWidth = 320
    let reservesFlexibleAlertSpace = false

    var preferredHeight: Int {
        let compactBaseHeight = 250
        guard hasUnreadAlerts else { return compactBaseHeight }
        return compactBaseHeight + 30 + max(1, severityCount) * 26
    }
}
