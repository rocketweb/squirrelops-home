import AppKit
import SwiftUI

/// Step 2 + 3: Enter the one-time setup key and execute the pairing protocol.
public struct PairingView: View {
    @Environment(\.colorScheme) private var colorScheme
    let pairingManager: PairingManager
    let sensor: PairingManager.DiscoveredSensor
    let onComplete: () -> Void

    @State private var codeText: String = ""
    @State private var isPairing = false
    @State private var errorMessage: String?
    @FocusState private var isFieldFocused: Bool

    public init(
        pairingManager: PairingManager,
        sensor: PairingManager.DiscoveredSensor,
        onComplete: @escaping () -> Void
    ) {
        self.pairingManager = pairingManager
        self.sensor = sensor
        self.onComplete = onComplete
    }

    private let setupKeyLength = 20

    private var rawCode: String {
        String(codeText.filter { $0.isLetter || $0.isNumber })
    }

    private var isCodeComplete: Bool { rawCode.count == setupKeyLength }

    public var body: some View {
        VStack(spacing: Spacing.lg) {
            Spacer()

            if isPairing {
                pairingProgressContent
            } else {
                codeEntryContent
            }

            Spacer()
        }
        .padding(Spacing.xl)
        .onAppear {
            NSApp.activate(ignoringOtherApps: true)
            if let window = NSApp.windows.first(where: { $0.isVisible }) {
                window.makeKey()
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
                isFieldFocused = true
            }
        }
    }

    // MARK: - Code Entry

    private var codeEntryContent: some View {
        VStack(spacing: Spacing.lg) {
            Image(systemName: "lock.shield")
                .font(.system(size: 48))
                .foregroundStyle(Theme.accentDefault(colorScheme))

            Text("Pair with \(sensor.name)")
                .font(Typography.h2)
                .foregroundStyle(Theme.textPrimary(colorScheme))

            Text("Enter the one-time setup key displayed on your sensor.")
                .font(Typography.body)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)

            codeInputFields

            if let errorMessage {
                Text(errorMessage)
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.statusError(colorScheme))
            }

            Button {
                Task { await performPairing() }
            } label: {
                Text("Pair")
                    .font(Typography.body)
                    .foregroundStyle(.white)
                    .frame(maxWidth: 200)
                    .padding(.vertical, Spacing.s12)
                    .background(isCodeComplete
                        ? Theme.accentDefault(colorScheme)
                        : Theme.textTertiary(colorScheme))
                    .cornerRadius(Spacing.radiusMd)
            }
            .buttonStyle(.plain)
            .disabled(!isCodeComplete)
        }
    }

    private var codeInputFields: some View {
        TextField("XXXX-XXXX-XXXX-XXXX-XXXX", text: $codeText)
            .textFieldStyle(.roundedBorder)
            .font(.system(size: 20, weight: .semibold, design: .monospaced))
            .multilineTextAlignment(.center)
            .frame(width: 360)
            .focused($isFieldFocused)
            .onChange(of: codeText) { _, newValue in
                let normalized = String(
                    newValue.uppercased().filter { $0.isLetter || $0.isNumber }
                        .prefix(setupKeyLength)
                )
                let groups = stride(from: 0, to: normalized.count, by: 4).map { start in
                    let lower = normalized.index(normalized.startIndex, offsetBy: start)
                    let upper = normalized.index(
                        lower, offsetBy: min(4, normalized.count - start)
                    )
                    return String(normalized[lower..<upper])
                }
                let formatted = groups.joined(separator: "-")
                if formatted != newValue {
                    codeText = formatted
                }
            }
            .onSubmit {
                if isCodeComplete {
                    Task { await performPairing() }
                }
            }
    }

    // MARK: - Pairing Progress

    private var pairingProgressContent: some View {
        VStack(spacing: Spacing.lg) {
            ProgressView()
                .controlSize(.large)

            Text("Pairing...")
                .font(Typography.h2)
                .foregroundStyle(Theme.textPrimary(colorScheme))

            Text("Exchanging encryption keys with the sensor. This may take a moment.")
                .font(Typography.body)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)
        }
    }

    // MARK: - Actions

    private func performPairing() async {
        isPairing = true
        errorMessage = nil

        do {
            _ = try await pairingManager.pair(sensor: sensor, code: codeText.uppercased())
            onComplete()
        } catch {
            isPairing = false
            errorMessage = "Pairing failed: \(error.localizedDescription)"
        }
    }
}
