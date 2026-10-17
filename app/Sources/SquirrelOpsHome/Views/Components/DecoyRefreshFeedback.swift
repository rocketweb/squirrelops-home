import SwiftUI

/// Transient feedback for an explicit refresh, not background inventory updates.
@MainActor
@Observable
final class DecoyRefreshFeedback {
    static let confirmationText = "Updated just now"
    static let displayDuration: Duration = .seconds(3)

    private(set) var isRefreshing = false
    private(set) var confirmationID: UUID?

    func refresh(_ operation: @MainActor () async throws -> Void) async throws {
        guard !isRefreshing else { return }
        isRefreshing = true
        confirmationID = nil
        defer { isRefreshing = false }
        try await operation()
        try Task.checkCancellation()
        confirmationID = UUID()
    }

    func dismissConfirmation(_ id: UUID) {
        guard confirmationID == id else { return }
        confirmationID = nil
    }

    func clearConfirmation() {
        confirmationID = nil
    }
}

struct DecoyRefreshConfirmation: View {
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        Label {
            Text(DecoyRefreshFeedback.confirmationText)
                .foregroundStyle(Theme.textPrimary(colorScheme))
        } icon: {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(Theme.statusSuccess(colorScheme))
        }
        .font(Typography.bodySmall)
        .padding(.horizontal, Spacing.s12)
        .padding(.vertical, Spacing.sm)
        .background(Theme.backgroundElevated(colorScheme), in: RoundedRectangle(cornerRadius: Spacing.radiusMd))
        .overlay {
            RoundedRectangle(cornerRadius: Spacing.radiusMd)
                .stroke(Theme.borderDefault(colorScheme), lineWidth: 1)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Decoys updated just now")
    }
}
