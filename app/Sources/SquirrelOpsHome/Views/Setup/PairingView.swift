import AppKit
import SwiftUI

/// Step 2 + 3: Enter the 6-digit pairing code and execute the pairing protocol.
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

    private var isCodeComplete: Bool { codeText.count == 6 && codeText.allSatisfy(\.isNumber) }

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

            Text("Enter the 6-digit code displayed on your sensor.")
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
        ZStack {
            // Hidden TextField captures keyboard input
            TextField("", text: $codeText)
                .textFieldStyle(.plain)
                .frame(width: 1, height: 1)
                .opacity(0.01)
                .focused($isFieldFocused)
                .onChange(of: codeText) { _, newValue in
                    let filtered = String(newValue.filter(\.isNumber).prefix(6))
                    if filtered != newValue {
                        codeText = filtered
                    }
                }
                .onSubmit {
                    if isCodeComplete {
                        Task { await performPairing() }
                    }
                }

            // Visual digit boxes
            HStack(spacing: Spacing.sm) {
                ForEach(0..<6, id: \.self) { index in
                    digitBox(at: index)
                }
            }
            .contentShape(Rectangle())
            .onTapGesture {
                isFieldFocused = true
            }
        }
    }

    private func digitBox(at index: Int) -> some View {
        let digit: String = index < codeText.count
            ? String(codeText[codeText.index(codeText.startIndex, offsetBy: index)])
            : ""
        let isCursor = index == codeText.count && isFieldFocused

        return Text(digit)
            .font(.system(size: 28, weight: .semibold, design: .monospaced))
            .foregroundStyle(Theme.textPrimary(colorScheme))
            .frame(width: 48, height: 56)
            .background(
                RoundedRectangle(cornerRadius: Spacing.radiusSm)
                    .fill(Theme.backgroundSecondary(colorScheme))
            )
            .overlay(
                RoundedRectangle(cornerRadius: Spacing.radiusSm)
                    .stroke(
                        isCursor
                            ? Theme.accentDefault(colorScheme)
                            : Theme.textTertiary(colorScheme).opacity(0.3),
                        lineWidth: isCursor ? 2 : 1
                    )
            )
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
            _ = try await pairingManager.pair(sensor: sensor, code: codeText)
            onComplete()
        } catch {
            isPairing = false
            errorMessage = "Pairing failed: \(error.localizedDescription)"
        }
    }
}
