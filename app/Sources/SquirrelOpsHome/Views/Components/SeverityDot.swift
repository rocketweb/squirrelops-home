import SwiftUI

struct SeverityDot: View {
    @Environment(\.colorScheme) private var colorScheme
    let severity: String

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: 6, height: 6)
    }

    private var color: Color {
        switch severity {
        case "critical", "high": return Theme.statusError(colorScheme)
        case "medium": return Theme.statusWarning(colorScheme)
        case "low": return Theme.statusInfo(colorScheme)
        default: return Theme.textTertiary(colorScheme)
        }
    }
}
