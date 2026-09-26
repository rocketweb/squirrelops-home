import SwiftUI

/// Shared, content-sized page chrome. The body below remains free to use the window width.
struct PageHeader<Accessory: View>: View {
    @Environment(\.colorScheme) private var colorScheme
    let title: String
    @ViewBuilder var accessory: Accessory

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: Spacing.md) {
                heading
                Spacer(minLength: Spacing.md)
                accessory.fixedSize(horizontal: true, vertical: false)
            }
            VStack(alignment: .leading, spacing: Spacing.sm) {
                heading
                accessory
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.horizontal, Spacing.lg)
        .padding(.vertical, Spacing.s12)
    }

    private var heading: some View {
        Text(title)
            .font(Typography.pageTitle)
            .foregroundStyle(Theme.textPrimary(colorScheme))
            .fixedSize()
            .accessibilityAddTraits(.isHeader)
    }
}

struct InventorySearchField: View {
    let title: String
    @Binding var text: String

    var body: some View {
        TextField(title, text: $text)
            .textFieldStyle(.roundedBorder)
            .frame(width: 220)
            .accessibilityLabel(title)
    }
}
