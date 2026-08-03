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
    @State private var profileDetails: ResourceProfileResponse?
    @State private var isUpdatingProfile = false
    @State private var profileSaveMessage: String?
    @AppStorage(MacNotificationPreferences.enabledKey)
    private var pushEnabled = true
    @State private var menuBarEnabled = true
    @State private var slackEnabled = false
    @State private var isLoading = true
    @State private var saveError: String?
    @State private var slackWebhookURL: String = ""
    @AppStorage(MacNotificationPreferences.minimumSeverityKey)
    private var pushMinSeverity: String = "low"
    @State private var menuBarMinSeverity: String = "low"
    @State private var slackMinSeverity: String = "low"
    @State private var llmProvider: String = "none"
    @State private var llmEndpoint: String = ""
    @State private var llmModel: String = ""
    @State private var llmApiKey: String = ""
    @State private var llmSaveCoordinator = LLMConfigSaveCoordinator()
    @State private var autoApproveThreshold: String = "0.75"
    @State private var slackIncludeDeviceInfo = false
    @State private var credentialFilename: String = "passwords.txt"

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

                if let saveError {
                    settingsNotice(
                        saveError,
                        icon: "exclamationmark.triangle.fill",
                        color: Theme.statusError(colorScheme)
                    )
                }

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
            .disabled(isLoading || isUpdatingProfile)
            .onChange(of: selectedProfile) { _, newValue in
                guard !isLoading, !isUpdatingProfile else { return }
                isUpdatingProfile = true
                Task {
                    await updateProfile(newValue)
                }
            }

            profileDescription

            if let profileSaveMessage {
                Label(profileSaveMessage, systemImage: "checkmark.circle.fill")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.statusSuccess(colorScheme))
            }
        }
        .padding(Spacing.md)
        .background(Theme.backgroundSecondary(colorScheme))
        .cornerRadius(Spacing.radiusLg)
    }

    @ViewBuilder
    private var profileDescription: some View {
        if isUpdatingProfile {
            HStack(spacing: Spacing.sm) {
                ProgressView()
                    .controlSize(.small)
                Text("Applying \(selectedProfile.capitalized) profile...")
            }
            .font(Typography.bodySmall)
            .foregroundStyle(Theme.textSecondary(colorScheme))
        } else if let profileDetails, profileDetails.profile == selectedProfile {
            Text(profileDetails.userSummary)
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))
        } else {
            Text("Loading profile limits...")
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textTertiary(colorScheme))
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

            Toggle("macOS Notifications", isOn: $pushEnabled)
                .font(Typography.body)
                .foregroundStyle(Theme.textPrimary(colorScheme))
                .disabled(isLoading)
                .onChange(of: pushEnabled) { _, newValue in
                    guard !isLoading else { return }
                    saveAlertMethod("push", config: ["enabled": .bool(newValue), "min_severity": .string(pushMinSeverity)])
                    Task {
                        await MacNotificationService.shared.updatePreferences(
                            enabled: newValue,
                            minimumSeverity: pushMinSeverity
                        )
                    }
                }

            if pushEnabled {
                severityPicker(
                    label: "macOS Severity",
                    selection: $pushMinSeverity,
                    method: "push",
                    enabled: pushEnabled
                )
                Text("Shows standard macOS banners with sound. You can also manage permission in System Settings → Notifications.")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textTertiary(colorScheme))
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
                SecureField("Webhook URL", text: $slackWebhookURL)
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

        }
        .padding(Spacing.md)
        .background(Theme.backgroundSecondary(colorScheme))
        .cornerRadius(Spacing.radiusLg)
    }

    private var llmConfigSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("OPTIONAL AI DEVICE CLASSIFICATION AND DECOY NAMING")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            Text(llmProviderDescription)
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))

            VStack(alignment: .leading, spacing: Spacing.sm) {
                Text("Provider")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))

                Picker("Provider", selection: $llmProvider) {
                    Text("None").tag("none")
                    Text("LM Studio").tag("lmstudio")
                    Text("Ollama").tag("ollama")
                    Text("OpenRouter").tag("openrouter")
                    Text("Fireworks.ai").tag("fireworks")
                    Text("Custom OpenAI-compatible").tag("custom")
                }
                .labelsHidden()
                .pickerStyle(.menu)
                .disabled(isLoading)
                .onChange(of: llmProvider) { oldValue, newValue in
                    guard !isLoading else { return }
                    updateLLMProvider(from: oldValue, to: newValue)
                }
            }

            if llmProvider != "none" {
                VStack(alignment: .leading, spacing: Spacing.sm) {
                    Text("Endpoint")
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textSecondary(colorScheme))

                    TextField(llmEndpointPlaceholder, text: $llmEndpoint)
                        .textFieldStyle(.roundedBorder)
                        .font(Typography.mono)
                        .disabled(isLoading || isFixedCloudLLMProvider)
                        .onChange(of: llmEndpoint) { _, _ in
                            guard !isLoading else { return }
                            scheduleLLMConfigSave()
                        }
                }

                VStack(alignment: .leading, spacing: Spacing.sm) {
                    Text("Model")
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textSecondary(colorScheme))

                    TextField(llmModelPlaceholder, text: $llmModel)
                        .textFieldStyle(.roundedBorder)
                        .font(Typography.mono)
                        .disabled(isLoading)
                        .onChange(of: llmModel) { _, _ in
                            guard !isLoading else { return }
                            scheduleLLMConfigSave()
                        }
                }

                VStack(alignment: .leading, spacing: Spacing.sm) {
                    Text("API Key")
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textSecondary(colorScheme))

                    SecureField("Provider API key", text: $llmApiKey)
                        .textFieldStyle(.roundedBorder)
                        .font(Typography.mono)
                        .disabled(isLoading)
                        .onChange(of: llmApiKey) { _, _ in
                            guard !isLoading else { return }
                            scheduleLLMConfigSave()
                        }

                    Text(
                        llmAPIKeyHelp
                    )
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

    private static let appVersion: String = {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
    }()
    private static let distributionVersion: String = {
        Bundle.main.infoDictionary?["SquirrelOpsDistributionVersion"] as? String
            ?? appVersion
    }()

    private var sensorSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("SENSOR")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            infoRow("Home Distribution", value: Self.distributionVersion)
            infoRow("App Version", value: Self.appVersion)
            if let sensor = appState.pairedSensor {
                infoRow("Name", value: sensor.name)
                infoRow("URL", value: sensor.baseURL.absoluteString)
            }
            if let info = appState.sensorInfo {
                infoRow("Sensor Version", value: info.version ?? "Unknown")
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
                Task { await appState.updateChecker.check(force: true) }
            } label: {
                HStack {
                    if appState.updateChecker.isChecking {
                        ProgressView()
                            .controlSize(.small)
                    }
                    Text("Check for Updates")
                }
            }
            .disabled(appState.updateChecker.isChecking)

            switch appState.updateChecker.result {
            case .available(let update):
                VStack(alignment: .leading, spacing: Spacing.sm) {
                    Text("Update available: v\(update.version) (you have v\(Self.distributionVersion))")
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.statusWarning(colorScheme))

                    Link(destination: update.url) {
                        HStack(spacing: Spacing.xs) {
                            Image(systemName: "arrow.down.circle")
                            Text("Download from GitHub")
                        }
                        .font(Typography.bodySmall)
                    }
                }
            case .upToDate(let current):
                Text("You're up to date (v\(current)).")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
            case .failed(let message):
                Text(message)
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
            case .skipped, .none:
                EmptyView()
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

    private func settingsNotice(_ message: String, icon: String, color: Color) -> some View {
        Label(message, systemImage: icon)
            .font(Typography.bodySmall)
            .foregroundStyle(color)
            .padding(Spacing.s12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.backgroundSecondary(colorScheme))
            .overlay(
                RoundedRectangle(cornerRadius: Spacing.radiusMd)
                    .stroke(color.opacity(0.35), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
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
                if method == "push" {
                    Task {
                        await MacNotificationService.shared.updatePreferences(
                            enabled: enabled,
                            minimumSeverity: newValue
                        )
                    }
                }
            }
        }
    }

    private func loadConfig() async {
        guard let client = appState.sensorClient else {
            saveError = "Sensor is not connected."
            isLoading = false
            return
        }

        // Refresh sensor info (version, uptime) each time settings is opened
        if let health: HealthResponse = try? await client.request(.health) {
            appState.sensorInfo = HealthResponse(
                version: appState.sensorInfo?.version,
                sensorId: health.sensorId,
                uptimeSeconds: health.uptimeSeconds
            )
        }
        try? await appState.refreshSystemStatus()

        if let profile: ResourceProfileResponse = try? await client.request(.profile) {
            profileDetails = profile
            selectedProfile = profile.profile
            appState.applyResourceProfile(profile)
        }

        do {
            let config: [String: AnyCodableValue] = try await client.request(.config)

            if profileDetails == nil, case .string(let profile) = config["profile"] {
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
            var loadedProvider = false
            if case .object(let cls) = config["classifier"] {
                if case .string(let provider) = cls["llm_provider"] {
                    let supported = Set([
                        "none", "lmstudio", "ollama",
                        "openrouter", "fireworks", "custom",
                    ])
                    let normalized = provider.lowercased()
                    llmProvider = supported.contains(normalized)
                        ? normalized
                        : "custom"
                    loadedProvider = !provider.isEmpty
                }
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
            if !loadedProvider {
                llmProvider = inferredLLMProvider(for: llmEndpoint)
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

    private func updateProfile(_ newValue: String) async {
        saveError = nil
        profileSaveMessage = nil
        let previousProfile = profileDetails?.profile ?? appState.systemStatus?.profile ?? "standard"

        guard let client = appState.sensorClient else {
            selectedProfile = previousProfile
            saveError = "Sensor is not connected."
            isUpdatingProfile = false
            return
        }

        do {
            let updated: ResourceProfileResponse = try await client.request(
                .updateProfile(profile: newValue)
            )
            profileDetails = updated
            selectedProfile = updated.profile
            appState.applyResourceProfile(updated)
            try? await appState.refreshSystemStatus()
            await appState.refreshDecoys()
            profileSaveMessage = "\(updated.profile.capitalized) profile is active."
        } catch {
            selectedProfile = previousProfile
            saveError = "Failed to change resource profile: \(error.localizedDescription)"
        }
        isUpdatingProfile = false
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

    private func scheduleLLMConfigSave() {
        saveError = nil
        guard let client = appState.sensorClient else {
            saveError = "Sensor is not connected."
            return
        }
        let classifierDict: [String: AnyCodableValue] = [
            "llm_provider": .string(llmProvider),
            "llm_endpoint": .string(llmEndpoint),
            "llm_model": .string(llmModel),
            "llm_api_key": llmApiKey.isEmpty
                ? .null
                : .string(llmApiKey),
        ]
        let body: [String: AnyCodableValue] = [
            "classifier": .object(classifierDict)
        ]

        llmSaveCoordinator.submit {
            do {
                try await client.request(.updateConfig(body: body))
                guard !Task.isCancelled else { return }
                if let profile: ResourceProfileResponse = try? await client.request(.profile) {
                    profileDetails = profile
                    appState.applyResourceProfile(profile)
                }
                try? await appState.refreshSystemStatus()
            } catch {
                guard !Task.isCancelled else { return }
                saveError = "Failed to save AI configuration: \(error.localizedDescription)"
            }
        }
    }

    private var isCloudLLMProvider: Bool {
        llmProvider == "openrouter" || llmProvider == "fireworks"
    }

    private var isFixedCloudLLMProvider: Bool {
        isCloudLLMProvider
    }

    private var llmProviderDescription: String {
        switch llmProvider {
        case "lmstudio":
            return "Use LM Studio for fallback device classification and pattern-aware names for some new fake hosts."
        case "ollama":
            return "Use Ollama for fallback device classification and pattern-aware names for some new fake hosts."
        case "openrouter":
            return "Use OpenRouter for fallback device classification and pattern-aware decoy naming."
        case "fireworks":
            return "Use Fireworks.ai for fallback device classification and pattern-aware decoy naming."
        case "custom":
            return "Use another OpenAI-compatible endpoint for both optional AI features."
        default:
            return "Disabled. Local signatures classify devices and deterministic home and business names are used for fake hosts."
        }
    }

    private var llmEndpointPlaceholder: String {
        llmDefaultEndpoint(for: llmProvider) ?? "https://provider.example/v1"
    }

    private var llmModelPlaceholder: String {
        switch llmProvider {
        case "openrouter":
            return "provider/model"
        case "fireworks":
            return "accounts/account/models/model"
        default:
            return "Model identifier"
        }
    }

    private var llmAPIKeyHelp: String {
        switch llmProvider {
        case "openrouter", "fireworks":
            return "Required. The key is sent only to this provider's HTTPS API."
        case "custom":
            return "Required only if your endpoint uses bearer authentication."
        default:
            return "Not required for LM Studio or Ollama."
        }
    }

    private func llmDefaultEndpoint(for provider: String) -> String? {
        switch provider {
        case "lmstudio":
            return "http://localhost:1234/v1"
        case "ollama":
            return "http://localhost:11434/v1"
        case "openrouter":
            return "https://openrouter.ai/api/v1"
        case "fireworks":
            return "https://api.fireworks.ai/inference/v1"
        default:
            return nil
        }
    }

    private func inferredLLMProvider(for endpoint: String) -> String {
        let normalized = endpoint
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if normalized.isEmpty {
            return "none"
        }
        for provider in ["lmstudio", "ollama", "openrouter", "fireworks"] {
            if let candidate = llmDefaultEndpoint(for: provider),
               normalized == candidate.lowercased() {
                return provider
            }
        }
        return "custom"
    }

    private func updateLLMProvider(from oldValue: String, to newValue: String) {
        if let preset = llmDefaultEndpoint(for: newValue) {
            llmEndpoint = preset
        } else if newValue == "custom" && oldValue != "custom" {
            llmEndpoint = ""
        }
        // Provider credentials are never portable. Clear them before the
        // provider update is persisted so an OpenRouter key cannot be sent to
        // Fireworks (or any custom endpoint), and vice versa.
        if oldValue != newValue {
            llmApiKey = ""
        }
        scheduleLLMConfigSave()
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
