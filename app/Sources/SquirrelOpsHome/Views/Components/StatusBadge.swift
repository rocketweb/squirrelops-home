import SwiftUI

struct StatusBadge: View {
    @Environment(\.colorScheme) private var colorScheme
    let label: String
    let style: Style

    enum Style {
        case active, degraded, stopped, critical, offline

        func textColor(_ cs: ColorScheme) -> Color {
            switch self {
            case .active: return Theme.statusSuccess(cs)
            case .degraded: return Theme.statusWarning(cs)
            case .stopped: return Theme.textTertiary(cs)
            case .critical: return Theme.statusError(cs)
            case .offline: return Theme.textTertiary(cs)
            }
        }
    }

    var body: some View {
        Text(label.uppercased())
            .font(.system(size: 11, weight: .semibold))
            .tracking(0.5)
            .foregroundStyle(style.textColor(colorScheme))
            .padding(.horizontal, Spacing.sm)
            .padding(.vertical, Spacing.xs)
            .background(style.textColor(colorScheme).opacity(0.12))
            .overlay(
                RoundedRectangle(cornerRadius: Spacing.radiusFull)
                    .stroke(style.textColor(colorScheme).opacity(0.2), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusFull))
    }
}
