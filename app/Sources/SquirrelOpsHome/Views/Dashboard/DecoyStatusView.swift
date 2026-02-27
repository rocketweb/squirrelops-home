import SwiftUI

/// Grid of decoy cards showing status, connection counts, and actions.
struct DecoyStatusView: View {
    @Environment(\.colorScheme) private var colorScheme
    let appState: AppState

    @State private var selectedDecoy: DecoySummary?

    private let columns = [GridItem(.adaptive(minimum: 280), spacing: Spacing.md)]

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            if appState.decoys.isEmpty {
                emptyState
            } else {
                decoyGrid
            }
        }
        .background(Theme.background(colorScheme))
        .sheet(item: $selectedDecoy) { decoy in
            DecoyDetailSheet(decoy: decoy, appState: appState)
        }
    }

    private var toolbar: some View {
        HStack {
            Text("Decoys")
                .font(Typography.h3)
                .tracking(Typography.h3Tracking)
                .foregroundStyle(Theme.textPrimary(colorScheme))
            Spacer()
            Text("\(appState.decoys.count) deployed")
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))
        }
        .padding(Spacing.md)
    }

    private var decoyGrid: some View {
        ScrollView {
            LazyVGrid(columns: columns, spacing: Spacing.md) {
                ForEach(appState.decoys) { decoy in
                    decoyCard(decoy)
                        .onTapGesture {
                            selectedDecoy = decoy
                        }
                }
            }
            .padding(Spacing.lg)
        }
    }

    private func decoyCard(_ decoy: DecoySummary) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            // Header
            HStack {
                Image(systemName: decoyIcon(decoy.decoyType))
                    .font(.system(size: 20))
                    .foregroundStyle(Theme.textSecondary(colorScheme))
                Text(decoy.name)
                    .font(Typography.h4)
                    .tracking(Typography.h4Tracking)
                    .foregroundStyle(Theme.textPrimary(colorScheme))
                Spacer()
                StatusBadge(
                    label: decoy.status,
                    style: decoyStatusStyle(decoy.status)
                )
            }

            // Address
            Text("\(decoy.bindAddress):\(String(decoy.port))")
                .font(Typography.mono)
                .tracking(Typography.monoTracking)
                .foregroundStyle(Theme.textSecondary(colorScheme))

            // Enable/disable toggle
            DecoyToggle(decoy: decoy, appState: appState)

            Divider()

            // Metrics
            HStack(spacing: Spacing.lg) {
                VStack(alignment: .leading) {
                    Text("\(decoy.connectionCount)")
                        .font(Typography.h4)
                        .tracking(Typography.h4Tracking)
                        .foregroundStyle(Theme.textPrimary(colorScheme))
                    Text("CONNECTIONS")
                        .font(Typography.caption)
                        .tracking(Typography.captionTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                }
                VStack(alignment: .leading) {
                    Text("\(decoy.credentialTripCount)")
                        .font(Typography.h4)
                        .tracking(Typography.h4Tracking)
                        .foregroundStyle(decoy.credentialTripCount > 0
                            ? Theme.statusError(colorScheme)
                            : Theme.textPrimary(colorScheme))
                    Text("CREDENTIAL TRIPS")
                        .font(Typography.caption)
                        .tracking(Typography.captionTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                }
            }

            // Restart button for degraded
            if decoy.status == "degraded" {
                Button {
                    Task {
                        try? await appState.sensorClient?.request(.restartDecoy(id: decoy.id))
                        await appState.refreshDecoys()
                    }
                } label: {
                    Text("Restart")
                        .font(Typography.bodySmall)
                        .foregroundStyle(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, Spacing.sm)
                        .background(Theme.accentDefault(colorScheme))
                        .cornerRadius(Spacing.radiusMd)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(Spacing.md)
        .background(Theme.backgroundSecondary(colorScheme))
        .overlay(
            RoundedRectangle(cornerRadius: Spacing.radiusLg)
                .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
        )
        .cornerRadius(Spacing.radiusLg)
    }

    private func decoyIcon(_ type: String) -> String {
        switch type {
        case "dev_server": return "chevron.left.forwardslash.chevron.right"
        case "home_assistant": return "house"
        case "file_share": return "folder"
        default: return "ant"
        }
    }

    private func decoyStatusStyle(_ status: String) -> StatusBadge.Style {
        switch status {
        case "active": return .active
        case "degraded": return .degraded
        case "stopped": return .stopped
        default: return .offline
        }
    }

    private var emptyState: some View {
        VStack(spacing: Spacing.md) {
            Spacer()
            Image(systemName: "ant")
                .font(.system(size: 48))
                .foregroundStyle(Theme.textTertiary(colorScheme))
            Text("No decoys deployed")
                .font(Typography.h3)
                .tracking(Typography.h3Tracking)
                .foregroundStyle(Theme.textSecondary(colorScheme))
            Text("Decoys will be deployed by the sensor based on your resource profile.")
                .font(Typography.body)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .multilineTextAlignment(.center)
                .frame(maxWidth: 300)
            Spacer()
        }
    }
}

// MARK: - DecoyToggle

private struct DecoyToggle: View {
    @Environment(\.colorScheme) private var colorScheme
    let decoy: DecoySummary
    let appState: AppState

    @State private var isToggling = false

    var isEnabled: Bool {
        decoy.status == "active" || decoy.status == "degraded"
    }

    var body: some View {
        HStack {
            Text(isEnabled ? "Enabled" : "Disabled")
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))
            Spacer()
            Toggle("", isOn: Binding(
                get: { isEnabled },
                set: { newValue in
                    guard !isToggling else { return }
                    isToggling = true
                    Task {
                        if newValue {
                            try? await appState.sensorClient?.request(.enableDecoy(id: decoy.id))
                        } else {
                            try? await appState.sensorClient?.request(.disableDecoy(id: decoy.id))
                        }
                        await appState.refreshDecoys()
                        isToggling = false
                    }
                }
            ))
            .labelsHidden()
            .disabled(isToggling)
        }
    }
}

// MARK: - DecoyDetailSheet

struct DecoyDetailSheet: View {
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.dismiss) private var dismiss
    let decoy: DecoySummary
    let appState: AppState

    @State private var detail: DecoyDetail?
    @State private var credentials: [DecoyCredentialEntry] = []
    @State private var connections: [DecoyConnectionEntry] = []
    @State private var connectionTotal: Int = 0
    @State private var isLoading = true
    @State private var isEditingConfig = false
    @State private var editedConfig: [String: String] = [:]
    @State private var isSaving = false
    @State private var configError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerSection
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.lg) {
                    infoSection
                    configSection
                    credentialSection
                    connectionSection
                }
                .padding(Spacing.lg)
            }
        }
        .frame(minWidth: 420, idealWidth: 480, minHeight: 500, idealHeight: 600)
        .background(Theme.background(colorScheme))
        .task {
            do {
                let d: DecoyDetail = try await appState.sensorClient!.request(.decoy(id: decoy.id))
                detail = d
                let creds: [DecoyCredentialEntry] = try await appState.sensorClient!.request(.decoyCredentials(id: decoy.id))
                credentials = creds
                let c: PaginatedDecoyConnections = try await appState.sensorClient!.request(.decoyConnections(id: decoy.id))
                connections = c.items
                connectionTotal = c.total
            } catch {
                // Keep showing what we have
            }
            isLoading = false
        }
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack(alignment: .top) {
            HStack(spacing: Spacing.s12) {
                Image(systemName: decoyIcon(decoy.decoyType))
                    .font(.system(size: 32))
                    .foregroundStyle(Theme.textSecondary(colorScheme))

                VStack(alignment: .leading, spacing: Spacing.xs) {
                    Text(decoy.name)
                        .font(Typography.h3)
                        .tracking(Typography.h3Tracking)
                        .foregroundStyle(Theme.textPrimary(colorScheme))

                    StatusBadge(
                        label: decoy.status,
                        style: decoyStatusStyle(decoy.status)
                    )
                }
            }

            Spacer()

            HStack(spacing: Spacing.sm) {
                if isEditingConfig {
                    Button("Cancel") {
                        isEditingConfig = false
                        configError = nil
                    }
                    Button("Save") {
                        saveConfig()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.accentDefault(colorScheme))
                    .disabled(isSaving)
                } else {
                    if detail != nil {
                        Button("Edit Config") {
                            startEditing()
                        }
                    }
                    Button("Done") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                }
            }
        }
        .padding(Spacing.lg)
    }

    // MARK: - Info

    private var infoSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("DECOY INFO")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            VStack(spacing: Spacing.sm) {
                infoRow(label: "Type", value: decoy.decoyType.replacingOccurrences(of: "_", with: " ").capitalized)
                infoRow(label: "Address", value: "\(decoy.bindAddress):\(String(decoy.port))")
                infoRow(label: "Connections", value: "\(decoy.connectionCount)")
                infoRow(label: "Cred Trips", value: "\(decoy.credentialTripCount)")
                if let d = detail {
                    infoRow(label: "Failures", value: "\(d.failureCount)")
                    infoRow(label: "Created", value: d.createdAt)
                    infoRow(label: "Updated", value: d.updatedAt)
                }
            }
            .padding(Spacing.md)
            .background(Theme.backgroundSecondary(colorScheme))
            .overlay(
                RoundedRectangle(cornerRadius: Spacing.radiusMd)
                    .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
        }
    }

    // MARK: - Config

    private var configSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("CONFIGURATION")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            if let d = detail {
                configContent(d.config)
            } else if isLoading {
                ProgressView()
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(Spacing.md)
            } else {
                Text("No configuration data")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
                    .padding(Spacing.md)
            }
        }
    }

    @ViewBuilder
    private func configContent(_ config: AnyCodableValue) -> some View {
        if isEditingConfig {
            VStack(spacing: Spacing.sm) {
                ForEach(editedConfig.keys.sorted(), id: \.self) { key in
                    editableConfigRow(key: key)
                }
                if let configError {
                    Text(configError)
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.statusError(colorScheme))
                }
            }
            .padding(Spacing.md)
            .background(Theme.backgroundSecondary(colorScheme))
            .overlay(
                RoundedRectangle(cornerRadius: Spacing.radiusMd)
                    .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
        } else if case .object(let dict) = config, !dict.isEmpty {
            VStack(spacing: Spacing.sm) {
                ForEach(dict.keys.sorted(), id: \.self) { key in
                    infoRow(label: key, value: configValueString(dict[key]!))
                }
            }
            .padding(Spacing.md)
            .background(Theme.backgroundSecondary(colorScheme))
            .overlay(
                RoundedRectangle(cornerRadius: Spacing.radiusMd)
                    .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
        } else {
            Text("No configuration set")
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .padding(Spacing.md)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Theme.backgroundSecondary(colorScheme))
                .overlay(
                    RoundedRectangle(cornerRadius: Spacing.radiusMd)
                        .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
        }
    }

    private func editableConfigRow(key: String) -> some View {
        HStack {
            Text(key)
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .frame(width: 100, alignment: .leading)
            TextField(key, text: Binding(
                get: { editedConfig[key] ?? "" },
                set: { editedConfig[key] = $0 }
            ))
            .textFieldStyle(.roundedBorder)
            .font(Typography.mono)
        }
        .padding(.vertical, Spacing.xs)
    }

    private func startEditing() {
        guard let d = detail, case .object(let dict) = d.config else { return }
        var mapped: [String: String] = [:]
        for (key, value) in dict {
            mapped[key] = configValueString(value)
        }
        editedConfig = mapped
        configError = nil
        isEditingConfig = true
    }

    private func saveConfig() {
        isSaving = true
        configError = nil
        Task {
            do {
                var converted: [String: AnyCodableValue] = [:]
                for (key, value) in editedConfig {
                    converted[key] = parseConfigValue(value)
                }
                let updated: DecoyDetail = try await appState.sensorClient!.request(
                    .updateDecoyConfig(id: decoy.id, config: converted)
                )
                detail = updated
                isEditingConfig = false
            } catch {
                configError = "Save failed: \(error.localizedDescription)"
            }
            isSaving = false
        }
    }

    private func parseConfigValue(_ value: String) -> AnyCodableValue {
        // Bool
        let lowered = value.lowercased()
        if lowered == "true" { return .bool(true) }
        if lowered == "false" { return .bool(false) }
        // Int
        if let intVal = Int(value) { return .int(intVal) }
        // Double
        if let doubleVal = Double(value), value.contains(".") { return .double(doubleVal) }
        // String
        return .string(value)
    }

    private func configValueString(_ value: AnyCodableValue) -> String {
        switch value {
        case .string(let s): return s
        case .int(let i): return "\(i)"
        case .double(let d): return "\(d)"
        case .bool(let b): return b ? "true" : "false"
        case .null: return "null"
        default: return "..."
        }
    }

    // MARK: - Credentials

    private var credentialSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("PLANTED CREDENTIALS")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            if credentials.isEmpty {
                Text("No credentials planted")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(Spacing.md)
                    .background(Theme.backgroundSecondary(colorScheme))
                    .overlay(
                        RoundedRectangle(cornerRadius: Spacing.radiusMd)
                            .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
                    )
                    .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
            } else {
                VStack(spacing: 0) {
                    ForEach(credentials) { cred in
                        HStack {
                            VStack(alignment: .leading, spacing: Spacing.xs) {
                                Text(cred.plantedLocation)
                                    .font(Typography.mono)
                                    .tracking(Typography.monoTracking)
                                    .foregroundStyle(Theme.textPrimary(colorScheme))
                                Text(cred.credentialType.replacingOccurrences(of: "_", with: " "))
                                    .font(Typography.bodySmall)
                                    .foregroundStyle(Theme.textSecondary(colorScheme))
                            }
                            Spacer()
                            if cred.tripped {
                                Text("TRIPPED")
                                    .font(Typography.caption)
                                    .tracking(Typography.captionTracking)
                                    .foregroundStyle(Theme.statusError(colorScheme))
                            }
                        }
                        .padding(.vertical, Spacing.sm)
                        .padding(.horizontal, Spacing.md)
                        if cred.id != credentials.last?.id {
                            Divider()
                        }
                    }
                }
                .background(Theme.backgroundSecondary(colorScheme))
                .overlay(
                    RoundedRectangle(cornerRadius: Spacing.radiusMd)
                        .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
            }
        }
    }

    // MARK: - Connections

    private var connectionSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            HStack {
                Text("CONNECTION LOG")
                    .font(Typography.caption)
                    .tracking(Typography.captionTracking)
                    .foregroundStyle(Theme.textTertiary(colorScheme))
                Spacer()
                Text("\(connectionTotal) total")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
            }

            if isLoading {
                ProgressView()
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(Spacing.md)
            } else if connections.isEmpty {
                Text("No connections recorded")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(Spacing.md)
                    .background(Theme.backgroundSecondary(colorScheme))
                    .overlay(
                        RoundedRectangle(cornerRadius: Spacing.radiusMd)
                            .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
                    )
                    .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
            } else {
                VStack(spacing: 0) {
                    ForEach(connections) { conn in
                        connectionRow(conn)
                        if conn.id != connections.last?.id {
                            Divider()
                        }
                    }
                }
                .background(Theme.backgroundSecondary(colorScheme))
                .overlay(
                    RoundedRectangle(cornerRadius: Spacing.radiusMd)
                        .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
            }
        }
    }

    private func connectionRow(_ conn: DecoyConnectionEntry) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: Spacing.xs) {
                Text(conn.sourceIp)
                    .font(Typography.mono)
                    .tracking(Typography.monoTracking)
                    .foregroundStyle(Theme.textPrimary(colorScheme))
                if let path = conn.requestPath {
                    Text(path)
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                }
            }

            Spacer()

            VStack(alignment: .trailing, spacing: Spacing.xs) {
                Text(conn.timestamp)
                    .font(Typography.mono)
                    .tracking(Typography.monoTracking)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
                    .lineLimit(1)
                if conn.credentialUsed != nil {
                    Text("CREDENTIAL")
                        .font(Typography.caption)
                        .tracking(Typography.captionTracking)
                        .foregroundStyle(Theme.statusError(colorScheme))
                }
            }
        }
        .padding(.vertical, Spacing.sm)
        .padding(.horizontal, Spacing.md)
    }

    // MARK: - Helpers

    private func infoRow(label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .frame(width: 100, alignment: .leading)
            Text(value)
                .font(Typography.mono)
                .tracking(Typography.monoTracking)
                .foregroundStyle(Theme.textPrimary(colorScheme))
                .lineLimit(1)
                .textSelection(.enabled)
            Spacer()
        }
        .padding(.vertical, Spacing.xs)
    }

    private func decoyIcon(_ type: String) -> String {
        switch type {
        case "dev_server": return "chevron.left.forwardslash.chevron.right"
        case "home_assistant": return "house"
        case "file_share": return "folder"
        default: return "ant"
        }
    }

    private func decoyStatusStyle(_ status: String) -> StatusBadge.Style {
        switch status {
        case "active": return .active
        case "degraded": return .degraded
        case "stopped": return .stopped
        default: return .offline
        }
    }
}
