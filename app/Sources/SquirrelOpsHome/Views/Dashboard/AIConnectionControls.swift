import SwiftUI

/// Native controls only. Network requests and saved credentials stay on the sensor.
struct AIConnectionControls: View {
    @Environment(\.colorScheme) private var colorScheme
    let state: AIConnectionState
    @Binding var model: String
    let disabled: Bool
    let run: (Bool) -> Void
    @State private var showingModels = false
    @State private var search = ""

    private var filteredModels: [AIModelOption] {
        state.models.filter {
            search.isEmpty || $0.name.localizedCaseInsensitiveContains(search)
                || $0.id.localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            ViewThatFits(in: .horizontal) {
                HStack { actionButtons }
                VStack(alignment: .leading) { actionButtons }
            }
            if state.isBusy {
                ProgressView("Checking AI from the sensor…")
                    .controlSize(.small)
            }
            if let result = state.discoveryResult {
                resultLabel(result, discovery: true)
            }
            if let result = state.testResult {
                resultLabel(result, discovery: false)
            }
            if let error = state.error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(Theme.statusError(colorScheme))
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text("Checks run from the sensor. Test model sends two small synthetic requests, never your device data. Cloud providers may charge; local servers may load the selected model into memory.")
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder private var actionButtons: some View {
        Button(state.models.isEmpty ? "Connect and load models" : "Refresh models") { run(true) }
            .disabled(disabled || state.isBusy)
        Button("Choose model…") { showingModels = true }
            .disabled(disabled || state.isBusy || state.models.isEmpty)
            .popover(isPresented: $showingModels) {
                VStack(alignment: .leading, spacing: Spacing.sm) {
                    TextField("Search models", text: $search)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityLabel("Search available AI models")
                    List(filteredModels) { option in
                        Button {
                            model = option.id
                            showingModels = false
                        } label: {
                            VStack(alignment: .leading) {
                                Text(option.name)
                                if option.name != option.id {
                                    Text(option.id).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Select AI model \(option.name), \(option.id)")
                    }
                    if filteredModels.isEmpty { Text("No matching models. You can enter a model ID manually.") }
                    Button("Done") { showingModels = false }
                        .keyboardShortcut(.cancelAction)
                }
                .padding()
                .frame(width: 380, height: 320)
            }
        Button("Test model") { run(false) }
            .disabled(disabled || state.isBusy || model.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
    }

    private func resultLabel(_ result: AIProbeResponse, discovery: Bool) -> some View {
        let success = result.status == "ok"
        let icon = success ? (discovery ? "info.circle" : "checkmark.circle.fill") : "exclamationmark.triangle.fill"
        let elapsed = String(format: "%.1f", Double(result.elapsedMs) / 1000)
        return Label(discovery ? result.message : "\(result.message) (\(elapsed) s)", systemImage: icon)
            .font(Typography.bodySmall)
            .foregroundStyle(success ? Theme.textSecondary(colorScheme) : Theme.statusError(colorScheme))
            .fixedSize(horizontal: false, vertical: true)
    }
}
