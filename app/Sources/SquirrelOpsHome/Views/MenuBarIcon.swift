import SwiftUI

/// Menu bar icon that changes based on the current monitoring status.
public struct MenuBarIcon: View {
    let status: MenuBarStatus

    public init(status: MenuBarStatus) {
        self.status = status
    }

    public var body: some View {
        switch status {
        case .connected:
            Image(systemName: "shield.checkered")
        case .alertsPresent:
            Image(systemName: "exclamationmark.shield")
        case .criticalAlert:
            Image(systemName: "exclamationmark.shield.fill")
        case .disconnected:
            Image(systemName: "shield.slash")
        }
    }
}
