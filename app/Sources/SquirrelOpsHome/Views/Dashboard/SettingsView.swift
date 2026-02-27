import SwiftUI

public enum AppearanceMode {
    public static func resolvedColorScheme(for mode: String) -> ColorScheme? {
        switch mode {
        case "light": return .light
        case "dark": return .dark
        default: return nil
        }
    }
}

/// Settings view with resource profile, sensor info, and alert methods.
struct SettingsView: View {
    @Environment(\.colorScheme) private var colorScheme
    @AppStorage("appearanceMode") private var appearanceMode: String = "system"
    let appState: AppState

    @State private var selectedProfile: String = "standard"
    @State private var pushEnabled = true
    @State private var menuBarEnabled = true
    @State private var slackEnabled = false
    @State private var isLoading = true
    @State private var saveError: String?
    @State private var slackWebhookURL: String = ""
    @State private var pushMinSeverity: String = "low"
    @State private var menuBarMinSeverity: String = "low"
    @State private var slackMinSeverity: String = "low"
    @State private var llmEndpoint: String = ""
    @State private var llmModel: String = ""
    @State private var llmApiKey: String = ""
    @State private var autoApproveThreshold: String = "0.75"
    @State private var slackIncludeDeviceInfo = false
    @State private var credentialFilename: String = "passwords.txt"
    @State private var updateStatus: String = ""
    @State private var isCheckingUpdates = false

    // Home Assistant
    @State private var haEnabled = false
    @State private var haURL: String = ""
    @State private var haToken: String = ""
    @State private var haTestStatus: HATestStatus = .idle

    enum HATestStatus: Equatable {
        case idle, testing, success(deviceCount: Int), failed
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                Text("Settings")
                    .font(Typography.h2)
                    .foregroundStyle(Theme.textPrimary(colorScheme))

                appearanceSection
                profileSection
                alertMethodsSection
                fingerprintSection
                credentialSection
                if selectedProfile == "standard" || selectedProfile == "full" {
                    llmConfigSection
                }
                homeAssistantSection
                sensorSection
                updatesSection

                Spacer()
            }
            .padding(Spacing.lg)
        }
        .background(Theme.background(colorScheme))
        .task {
            await loadConfig()
        }
        .overlay {
            if isLoading {
                ProgressView("Loading settings...")
                    .padding()
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }

    private var profileSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("RESOURCE PROFILE")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            Picker("Profile", selection: $selectedProfile) {
                Text("Lite").tag("lite")
                Text("Standard").tag("standard")
                Text("Full").tag("full")
            }
            .pickerStyle(.segmented)
            .onChange(of: selectedProfile) { _, newValue in
                guard !isLoading else { return }
                Task {
                    try? await appState.sensorClient?.request(.updateProfile(profile: newValue))
                }
            }

            profileDescription
        }
        .padding(Spacing.md)
        .background(Theme.backgroundSecondary(colorScheme))
        .cornerRadius(Spacing.radiusLg)
    }

    @ViewBuilder
    private var profileDescription: some View {
        switch selectedProfile {
        case "lite":
            Text("Scan every 15 min. Up to 3 decoys. Local signature DB only.")
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))
        case "standard":
            Text("Scan every 5 min. Up to 8 decoys. Cloud LLM classification.")
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))
        case "full":
            Text("Scan every 1 min. 16+ decoys. Local LLM classification.")
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))
        default:
            EmptyView()
        }
    }

    private var appearanceSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("APPEARANCE")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            Picker("Appearance", selection: $appearanceMode) {
                Text("System").tag("system")
                Text("Light").tag("light")
                Text("Dark").tag("dark")
            }
            .pickerStyle(.segmented)
        }
        .padding(Spacing.md)
        .background(Theme.backgroundSecondary(colorScheme))
        .cornerRadius(Spacing.radiusLg)
    }

    private var alertMethodsSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("ALERT METHODS")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            Toggle("Push Notifications", isOn: $pushEnabled)
                .font(Typography.body)
                .foregroundStyle(Theme.textPrimary(colorScheme))
                .disabled(isLoading)
                .onChange(of: pushEnabled) { _, newValue in
                    guard !isLoading else { return }
                    saveAlertMethod("push", config: ["enabled": .bool(newValue), "min_severity": .string(pushMinSeverity)])
                }

            if pushEnabled {
                severityPicker(label: "Push Severity", selection: $pushMinSeverity, method: "push", enabled: pushEnabled)
            }

            Toggle("Menu Bar Alerts", isOn: $menuBarEnabled)
                .font(Typography.body)
                .foregroundStyle(Theme.textPrimary(colorScheme))
                .disabled(isLoading)
                .onChange(of: menuBarEnabled) { _, newValue in
                    guard !isLoading else { return }
                    saveAlertMethod("menu_bar", config: ["enabled": .bool(newValue), "min_severity": .string(menuBarMinSeverity)])
                }

            if menuBarEnabled {
                severityPicker(label: "Menu Bar Severity", selection: $menuBarMinSeverity, method: "menu_bar", enabled: menuBarEnabled)
            }

            Toggle("Slack Webhook", isOn: $slackEnabled)
                .font(Typography.body)
                .foregroundStyle(Theme.textPrimary(colorScheme))
                .disabled(isLoading)
                .onChange(of: slackEnabled) { _, newValue in
                    guard !isLoading else { return }
                    saveAlertMethod("slack", config: [
                        "enabled": .bool(newValue),
                        "webhook_url": .string(slackWebhookURL),
                        "min_severity": .string(slackMinSeverity),
                        "include_device_info": .bool(slackIncludeDeviceInfo),
                    ])
                }

            if slackEnabled {
                TextField("Webhook URL", text: $slackWebhookURL)
                    .textFieldStyle(.roundedBorder)
                    .font(Typography.mono)
                    .task(id: slackWebhookURL) {
                        guard !isLoading else { return }
                        do {
                            try await Task.sleep(for: .seconds(1))
                        } catch { return }
                        saveAlertMethod("slack", config: [
                            "enabled": .bool(slackEnabled),
                            "webhook_url": .string(slackWebhookURL),
                            "min_severity": .string(slackMinSeverity),
                            "include_device_info": .bool(slackIncludeDeviceInfo),
                        ])
                    }
            }

            if slackEnabled {
                severityPicker(
                    label: "Slack Severity",
                    selection: $slackMinSeverity,
                    method: "slack",
                    enabled: slackEnabled,
                    extraConfig: ["webhook_url": .string(slackWebhookURL), "include_device_info": .bool(slackIncludeDeviceInfo)]
                )
            }

            if slackEnabled {
                VStack(alignment: .leading, spacing: Spacing.xs) {
                    Toggle("Include Device Identifiers", isOn: $slackIncludeDeviceInfo)
                        .font(Typography.body)
                        .foregroundStyle(Theme.textPrimary(colorScheme))
                        .disabled(isLoading)
                        .onChange(of: slackIncludeDeviceInfo) { _, newValue in
                            guard !isLoading else { return }
                            saveAlertMethod("slack", config: [
                                "enabled": .bool(slackEnabled),
                                "webhook_url": .string(slackWebhookURL),
                                "min_severity": .string(slackMinSeverity),
                                "include_device_info": .bool(newValue),
                            ])
                        }

                    if slackIncludeDeviceInfo {
                        Text("MAC addresses and device IDs will be sent to your Slack webhook. This data will leave your local network.")
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.statusWarning(colorScheme))
                    }
                }
            }

            if let saveError {
                Text(saveError)
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.statusError(colorScheme))
            }
        }
        .padding(Spacing.md)
        .background(Theme.backgroundSecondary(colorScheme))
        .cornerRadius(Spacing.radiusLg)
    }

    private var llmConfigSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("LLM CONFIGURATION")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            if selectedProfile == "full" {
                Text("Local LLM endpoint for device classification (LM Studio or Ollama).")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
            } else {
                Text("Cloud LLM endpoint for device classification (requires API key).")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
            }

            VStack(alignment: .leading, spacing: Spacing.sm) {
                Text("Endpoint")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))

                TextField(
                    selectedProfile == "full" ? "http://localhost:1234/v1" : "https://api.openai.com/v1",
                    text: $llmEndpoint
                )
                .textFieldStyle(.roundedBorder)
                .font(Typography.mono)
                .disabled(isLoading)
                .task(id: llmEndpoint) {
                    guard !isLoading else { return }
                    do {
                        try await Task.sleep(for: .seconds(1))
                    } catch { return }
                    saveLLMConfig()
                }
            }

            VStack(alignment: .leading, spacing: Spacing.sm) {
                Text("Model")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))

                TextField(
                    selectedProfile == "full" ? "llama-3.2-3b" : "gpt-4o-mini",
                    text: $llmModel
                )
                .textFieldStyle(.roundedBorder)
                .font(Typography.mono)
                .disabled(isLoading)
                .task(id: llmModel) {
                    guard !isLoading else { return }
                    do {
                        try await Task.sleep(for: .seconds(1))
                    } catch { return }
                    saveLLMConfig()
                }
            }

            VStack(alignment: .leading, spacing: Spacing.sm) {
                Text("API Key")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))

                SecureField("sk-...", text: $llmApiKey)
                    .textFieldStyle(.roundedBorder)
                    .font(Typography.mono)
                    .disabled(isLoading)
                    .task(id: llmApiKey) {
                        guard !isLoading else { return }
                        do {
                            try await Task.sleep(for: .seconds(1))
                        } catch { return }
                        saveLLMConfig()
                    }

                if selectedProfile == "full" {
                    Text("Not required for local LLM servers (LM Studio, Ollama).")
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                }
            }
        }
        .padding(Spacing.md)
        .background(Theme.backgroundSecondary(colorScheme))
        .cornerRadius(Spacing.radiusLg)
    }

    private var fingerprintSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("DEVICE MATCHING")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            Text("How strictly devices must match their fingerprint to be auto-approved.")
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))

            Picker("Threshold", selection: $autoApproveThreshold) {
                Text("Relaxed (0.60)").tag("0.60")
                Text("Standard (0.75)").tag("0.75")
                Text("Strict (0.90)").tag("0.90")
            }
            .pickerStyle(.segmented)
            .disabled(isLoading)
            .onChange(of: autoApproveThreshold) { _, newValue in
                guard !isLoading else { return }
                saveError = nil
                Task {
                    do {
                        let body: [String: AnyCodableValue] = [
                            "fingerprint": .object([
                                "auto_approve_threshold": .double(Double(newValue) ?? 0.75)
                            ])
                        ]
                        try await appState.sensorClient?.request(.updateConfig(body: body))
                    } catch {
                        saveError = "Failed to save threshold: \(error.localizedDescription)"
                    }
                }
            }
        }
        .padding(Spacing.md)
        .background(Theme.backgroundSecondary(colorScheme))
        .cornerRadius(Spacing.radiusLg)
    }

    private var credentialSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("CREDENTIAL DECOYS")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            Text("Filename for the planted credential file served by decoy file shares.")
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))

            TextField("passwords.txt", text: $credentialFilename)
                .textFieldStyle(.roundedBorder)
                .font(Typography.mono)
                .disabled(isLoading)
                .task(id: credentialFilename) {
                    guard !isLoading else { return }
                    do {
                        try await Task.sleep(for: .seconds(1))
                    } catch { return }
                    guard !credentialFilename.isEmpty else { return }
                    saveError = nil
                    Task {
                        do {
                            let body: [String: AnyCodableValue] = [
                                "credential_filename": .string(credentialFilename)
                            ]
                            try await appState.sensorClient?.request(.updateConfig(body: body))
                        } catch {
                            saveError = "Failed to save: \(error.localizedDescription)"
                        }
                    }
                }
        }
        .padding(Spacing.md)
        .background(Theme.backgroundSecondary(colorScheme))
        .cornerRadius(Spacing.radiusLg)
    }

    private var homeAssistantSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("HOME ASSISTANT")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            Text("Connect to a local Home Assistant instance for richer device data (names, manufacturers, models, areas).")
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))

            Toggle("Enable Home Assistant", isOn: $haEnabled)
                .font(Typography.body)
                .foregroundStyle(Theme.textPrimary(colorScheme))
                .disabled(isLoading)
                .onChange(of: haEnabled) { _, _ in
                    guard !isLoading else { return }
                    saveHAConfig()
                }

            if haEnabled {
                VStack(alignment: .leading, spacing: Spacing.sm) {
                    Text("URL")
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textSecondary(colorScheme))

                    TextField("http://homeassistant.local:8123", text: $haURL)
                        .textFieldStyle(.roundedBorder)
                        .font(Typography.mono)
                        .disabled(isLoading)
                        .task(id: haURL) {
                            guard !isLoading else { return }
                            do {
                                try await Task.sleep(for: .seconds(1))
                            } catch { return }
                            saveHAConfig()
                        }
                }

                VStack(alignment: .leading, spacing: Spacing.sm) {
                    Text("Long-Lived Access Token")
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textSecondary(colorScheme))

                    SecureField("Paste token here", text: $haToken)
                        .textFieldStyle(.roundedBorder)
                        .font(Typography.mono)
                        .disabled(isLoading)
                        .task(id: haToken) {
                            guard !isLoading else { return }
                            do {
                                try await Task.sleep(for: .seconds(1))
                            } catch { return }
                            saveHAConfig()
                        }
                }

                Button {
                    testHAConnection()
                } label: {
                    HStack(spacing: Spacing.sm) {
                        switch haTestStatus {
                        case .idle:
                            Text("Test Connection")
                        case .testing:
                            ProgressView()
                                .controlSize(.small)
                            Text("Testing...")
                        case .success(let count):
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(Theme.statusSuccess(colorScheme))
                            Text("Connected (\(count) devices)")
                        case .failed:
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(Theme.statusError(colorScheme))
                            Text("Connection Failed")
                        }
                    }
                }
                .disabled(haURL.isEmpty || haToken.isEmpty || haTestStatus == .testing)
            }
        }
        .padding(Spacing.md)
        .background(Theme.backgroundSecondary(colorScheme))
        .cornerRadius(Spacing.radiusLg)
    }

    private var sensorSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("SENSOR")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            if let sensor = appState.pairedSensor {
                infoRow("Name", value: sensor.name)
                infoRow("URL", value: sensor.baseURL.absoluteString)
            }
            if let info = appState.sensorInfo {
                infoRow("Version", value: info.version)
                infoRow("Uptime", value: formatUptime(info.uptimeSeconds))
            }
        }
        .padding(Spacing.md)
        .background(Theme.backgroundSecondary(colorScheme))
        .cornerRadius(Spacing.radiusLg)
    }

    private func formatUptime(_ seconds: Double) -> String {
        let total = Int(seconds)
        let days = total / 86400
        let hours = (total % 86400) / 3600
        let mins = (total % 3600) / 60
        if days > 0 {
            return "\(days)d \(hours)h \(mins)m"
        } else if hours > 0 {
            return "\(hours)h \(mins)m"
        } else {
            return "\(mins)m"
        }
    }

    private var updatesSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("UPDATES")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            Button {
                isCheckingUpdates = true
                updateStatus = ""
                Task {
                    do {
                        let result: UpdateCheckResponse = try await appState.sensorClient!.request(.checkUpdates)
                        updateStatus = result.message
                    } catch {
                        updateStatus = "Check failed: \(error.localizedDescription)"
                    }
                    isCheckingUpdates = false
                }
            } label: {
                HStack {
                    if isCheckingUpdates {
                        ProgressView()
                            .controlSize(.small)
                    }
                    Text("Check for Updates")
                }
            }
            .disabled(isCheckingUpdates || isLoading)

            if !updateStatus.isEmpty {
                Text(updateStatus)
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
            }
        }
        .padding(Spacing.md)
        .background(Theme.backgroundSecondary(colorScheme))
        .cornerRadius(Spacing.radiusLg)
    }

    private func infoRow(_ label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))
            Spacer()
            Text(value)
                .font(Typography.mono)
                .tracking(Typography.monoTracking)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .lineLimit(1)
        }
    }

    private func severityPicker(label: String, selection: Binding<String>, method: String, enabled: Bool, extraConfig: [String: AnyCodableValue] = [:]) -> some View {
        VStack(alignment: .leading, spacing: Spacing.xs) {
            Text("Minimum Severity")
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))

            Picker(label, selection: selection) {
                Text("All").tag("low")
                Text("Medium+").tag("medium")
                Text("High+").tag("high")
                Text("Critical").tag("critical")
            }
            .pickerStyle(.segmented)
            .disabled(!enabled || isLoading)
            .onChange(of: selection.wrappedValue) { _, newValue in
                guard !isLoading else { return }
                var config: [String: AnyCodableValue] = [
                    "enabled": .bool(enabled),
                    "min_severity": .string(newValue),
                ]
                for (key, value) in extraConfig {
                    config[key] = value
                }
                saveAlertMethod(method, config: config)
            }
        }
    }

    private func loadConfig() async {
        // Refresh sensor info (version, uptime) each time settings is opened
        if let client = appState.sensorClient {
            if let health: HealthResponse = try? await client.request(.health) {
                appState.sensorInfo = health
            }
        }

        do {
            let config: [String: AnyCodableValue] = try await appState.sensorClient!.request(.config)

            if case .string(let profile) = config["profile"] {
                selectedProfile = profile
            }

            if case .object(let methods) = config["alert_methods"] {
                if case .object(let push) = methods["push"] {
                    if case .bool(let enabled) = push["enabled"] {
                        pushEnabled = enabled
                    }
                    if case .string(let severity) = push["min_severity"] {
                        pushMinSeverity = severity
                    }
                }
                if case .object(let menuBar) = methods["menu_bar"] {
                    if case .bool(let enabled) = menuBar["enabled"] {
                        menuBarEnabled = enabled
                    }
                    if case .string(let severity) = menuBar["min_severity"] {
                        menuBarMinSeverity = severity
                    }
                }
                if case .object(let slack) = methods["slack"] {
                    if case .bool(let enabled) = slack["enabled"] {
                        slackEnabled = enabled
                    }
                    if case .string(let url) = slack["webhook_url"] {
                        slackWebhookURL = url
                    }
                    if case .string(let severity) = slack["min_severity"] {
                        slackMinSeverity = severity
                    }
                    if case .bool(let includeInfo) = slack["include_device_info"] {
                        slackIncludeDeviceInfo = includeInfo
                    }
                }
            }

            // LLM config: nested under "classifier", with top-level fallback for compat
            if case .object(let cls) = config["classifier"] {
                if case .string(let endpoint) = cls["llm_endpoint"] {
                    llmEndpoint = endpoint
                }
                if case .string(let model) = cls["llm_model"] {
                    llmModel = model
                }
                if case .string(let apiKey) = cls["llm_api_key"] {
                    llmApiKey = apiKey
                }
            } else {
                if case .string(let endpoint) = config["llm_endpoint"] {
                    llmEndpoint = endpoint
                }
                if case .string(let model) = config["llm_model"] {
                    llmModel = model
                }
                if case .string(let apiKey) = config["llm_api_key"] {
                    llmApiKey = apiKey
                }
            }

            if case .object(let fingerprint) = config["fingerprint"],
               case .double(let threshold) = fingerprint["auto_approve_threshold"] {
                if threshold <= 0.67 {
                    autoApproveThreshold = "0.60"
                } else if threshold <= 0.82 {
                    autoApproveThreshold = "0.75"
                } else {
                    autoApproveThreshold = "0.90"
                }
            }

            if case .string(let filename) = config["credential_filename"] {
                credentialFilename = filename
            }

            if case .object(let ha) = config["home_assistant"] {
                if case .bool(let enabled) = ha["enabled"] {
                    haEnabled = enabled
                }
                if case .string(let url) = ha["url"] {
                    haURL = url
                }
                if case .string(let token) = ha["token"] {
                    haToken = token
                }
            }
        } catch {
            saveError = "Failed to load settings: \(error.localizedDescription)"
        }
        isLoading = false
    }

    private func saveHAConfig() {
        saveError = nil
        Task {
            do {
                let body: [String: AnyCodableValue] = [
                    "home_assistant": .object([
                        "enabled": .bool(haEnabled),
                        "url": .string(haURL),
                        "token": .string(haToken),
                    ])
                ]
                try await appState.sensorClient?.request(.updateConfig(body: body))
            } catch {
                saveError = "Failed to save HA config: \(error.localizedDescription)"
            }
        }
    }

    private func testHAConnection() {
        haTestStatus = .testing
        Task {
            do {
                let response: HAStatusResponse = try await appState.sensorClient!.request(.haStatus)
                if response.connected {
                    haTestStatus = .success(deviceCount: response.deviceCount)
                } else {
                    haTestStatus = .failed
                }
            } catch {
                haTestStatus = .failed
            }
        }
    }

    private func saveLLMConfig() {
        saveError = nil
        Task {
            do {
                var classifierDict: [String: AnyCodableValue] = [
                    "llm_endpoint": .string(llmEndpoint),
                    "llm_model": .string(llmModel),
                ]
                if !llmApiKey.isEmpty {
                    classifierDict["llm_api_key"] = .string(llmApiKey)
                }
                let body: [String: AnyCodableValue] = [
                    "classifier": .object(classifierDict)
                ]
                try await appState.sensorClient?.request(.updateConfig(body: body))
            } catch {
                saveError = "Failed to save LLM config: \(error.localizedDescription)"
            }
        }
    }

    private func saveAlertMethod(_ method: String, config: [String: AnyCodableValue]) {
        saveError = nil
        Task {
            do {
                let body: [String: AnyCodableValue] = [method: .object(config)]
                try await appState.sensorClient?.request(.updateAlertMethods(body: body))
            } catch {
                saveError = "Failed to save: \(error.localizedDescription)"
            }
        }
    }
}
