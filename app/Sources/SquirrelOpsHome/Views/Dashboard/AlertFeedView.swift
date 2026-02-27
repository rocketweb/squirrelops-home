import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct AlertFeedView: View {
    let appState: AppState
    @Environment(\.colorScheme) private var colorScheme

    @State private var searchText: String = ""
    @State private var severityFilter: String? = nil
    @State private var selectedIncident: IncidentDetail?
    @State private var isLoadingIncident = false
    @State private var incidentError: String?
    @State private var showExportPopover = false
    @State private var exportDateFrom: Date = Calendar.current.date(byAdding: .day, value: -30, to: Date())!
    @State private var exportDateTo: Date = Date()
    @State private var isExporting = false
    @State private var typeFilter: String? = nil
    @State private var filterDateFrom: Date? = nil
    @State private var filterDateTo: Date? = nil
    @State private var showDateFilter = false
    @State private var selectedAlertId: Int?

    // MARK: - Severity filter options

    private static let severityLevels: [(label: String, value: String)] = [
        ("Critical", "critical"),
        ("High", "high"),
        ("Medium", "medium"),
        ("Low", "low"),
    ]

    private static let alertTypes: [(label: String, types: [String])] = [
        ("Decoy Trip", ["decoy.trip", "decoy.credential_trip"]),
        ("New Device", ["device.new", "device.verification_needed"]),
        ("MAC Changed", ["device.mac_changed"]),
        ("Security", ["security.port_risk", "security.vendor_advisory"]),
        ("System", ["system.sensor_offline", "system.learning_complete"]),
    ]

    private static let isoFormatter = ISO8601DateFormatter()

    // MARK: - Filtered alerts

    private var filteredAlerts: [AlertSummary] {
        let query = searchText.lowercased()

        return appState.alerts
            .filter { alert in
                // Severity filter
                if let filter = severityFilter, alert.severity != filter {
                    return false
                }
                // Type filter
                if let filter = typeFilter,
                   let types = Self.alertTypes.first(where: { $0.label == filter })?.types,
                   !types.contains(alert.alertType) {
                    return false
                }
                // Date range filter
                if let from = filterDateFrom {
                    let fromStr = Self.isoFormatter.string(from: from)
                    if alert.createdAt < fromStr { return false }
                }
                if let to = filterDateTo {
                    // Add a day so "to" date is inclusive
                    guard let endOfDay = Calendar.current.date(byAdding: .day, value: 1, to: to) else { return true }
                    let toStr = Self.isoFormatter.string(from: endOfDay)
                    if alert.createdAt >= toStr { return false }
                }
                // Search filter
                if !query.isEmpty {
                    let matchesTitle = alert.title.lowercased().contains(query)
                    let matchesIp = alert.sourceIp?.lowercased().contains(query) ?? false
                    let matchesType = alert.alertType.lowercased().contains(query)
                    if !(matchesTitle || matchesIp || matchesType) {
                        return false
                    }
                }
                return true
            }
            .sorted { $0.createdAt > $1.createdAt }
    }

    // MARK: - Body

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            toolbar
            Divider()

            if filteredAlerts.isEmpty {
                emptyState
            } else {
                List(filteredAlerts, selection: $selectedAlertId) { alert in
                    AlertRow(alert: alert)
                        .tag(alert.id)
                        .listRowInsets(EdgeInsets())
                        .listRowSeparator(.visible)
                        .contextMenu {
                            if alert.readAt == nil {
                                Button("Mark as Read") {
                                    Task {
                                        try? await appState.sensorClient?.request(.readAlert(id: alert.id))
                                        appState.markAlertRead(alert.id)
                                    }
                                }
                            }
                        }
                }
                .listStyle(.plain)
                .onChange(of: selectedAlertId) { _, newValue in
                    guard let alertId = newValue,
                          let alert = filteredAlerts.first(where: { $0.id == alertId })
                    else { return }
                    selectedAlertId = nil

                    // Mark as read on click
                    if alert.readAt == nil {
                        appState.markAlertRead(alert.id)
                        Task {
                            try? await appState.sensorClient?.request(.readAlert(id: alert.id))
                        }
                    }

                    // Open incident detail if available
                    if alert.incidentId != nil {
                        openIncidentForAlert(alert)
                    }
                }
            }
        }
        .background(Theme.background(colorScheme))
        .sheet(item: $selectedIncident) { incident in
            IncidentDetailView(incident: incident, appState: appState)
        }
        .overlay {
            if isLoadingIncident {
                ProgressView("Loading incident...")
                    .padding()
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }

    // MARK: - Toolbar

    private var toolbar: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            HStack(spacing: Spacing.md) {
                Text("Alerts")
                    .font(Typography.h3)
                    .tracking(Typography.h3Tracking)
                    .foregroundStyle(Theme.textPrimary(colorScheme))

                Spacer()

                if appState.alerts.contains(where: { $0.readAt == nil }) {
                    Button {
                        markAllRead()
                    } label: {
                        HStack(spacing: Spacing.xs) {
                            Image(systemName: "checkmark.circle")
                            Text("Mark All Read")
                                .font(Typography.bodySmall)
                        }
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                        .padding(.horizontal, Spacing.s12)
                        .padding(.vertical, Spacing.xs)
                        .background(Theme.backgroundTertiary(colorScheme))
                        .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusFull))
                        .overlay(
                            RoundedRectangle(cornerRadius: Spacing.radiusFull)
                                .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
                        )
                    }
                    .buttonStyle(.plain)
                }

                Button {
                    showExportPopover = true
                } label: {
                    HStack(spacing: Spacing.xs) {
                        Image(systemName: "square.and.arrow.up")
                        Text("Export")
                            .font(Typography.bodySmall)
                    }
                    .foregroundStyle(Theme.textSecondary(colorScheme))
                    .padding(.horizontal, Spacing.s12)
                    .padding(.vertical, Spacing.xs)
                    .background(Theme.backgroundTertiary(colorScheme))
                    .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusFull))
                    .overlay(
                        RoundedRectangle(cornerRadius: Spacing.radiusFull)
                            .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
                    )
                }
                .buttonStyle(.plain)
                .popover(isPresented: $showExportPopover) {
                    exportPopover
                }

                TextField("Search alerts...", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 220)
            }

            // Severity filter chips
            HStack(spacing: Spacing.sm) {
                filterChip(label: "All", value: nil)

                ForEach(Self.severityLevels, id: \.value) { level in
                    filterChip(label: level.label, value: level.value, severity: level.value)
                }
            }

            // Type filter chips
            HStack(spacing: Spacing.sm) {
                typeChip(label: "All Types", value: nil)

                ForEach(Self.alertTypes, id: \.label) { alertType in
                    typeChip(label: alertType.label, value: alertType.label)
                }

                Spacer()

                // Date filter toggle
                Button {
                    if showDateFilter {
                        showDateFilter = false
                        filterDateFrom = nil
                        filterDateTo = nil
                    } else {
                        showDateFilter = true
                        filterDateFrom = Calendar.current.date(byAdding: .day, value: -7, to: Date())
                        filterDateTo = Date()
                    }
                } label: {
                    HStack(spacing: Spacing.xs) {
                        Image(systemName: "calendar")
                        Text(showDateFilter ? "Clear Dates" : "Date Range")
                            .font(Typography.bodySmall)
                    }
                    .foregroundStyle(
                        showDateFilter
                            ? Theme.textPrimary(colorScheme)
                            : Theme.textSecondary(colorScheme)
                    )
                    .padding(.horizontal, Spacing.s12)
                    .padding(.vertical, Spacing.xs)
                    .background(
                        showDateFilter
                            ? Theme.backgroundTertiary(colorScheme)
                            : Color.clear
                    )
                    .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusFull))
                    .overlay(
                        RoundedRectangle(cornerRadius: Spacing.radiusFull)
                            .stroke(
                                showDateFilter
                                    ? Theme.borderDefault(colorScheme)
                                    : Theme.borderSubtle(colorScheme),
                                lineWidth: 1
                            )
                    )
                }
                .buttonStyle(.plain)
            }

            // Date range pickers (when active)
            if showDateFilter {
                HStack(spacing: Spacing.md) {
                    HStack(spacing: Spacing.sm) {
                        Text("FROM")
                            .font(Typography.caption)
                            .tracking(Typography.captionTracking)
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                        DatePicker("", selection: Binding(
                            get: { filterDateFrom ?? Date() },
                            set: { filterDateFrom = $0 }
                        ), displayedComponents: .date)
                            .labelsHidden()
                    }
                    HStack(spacing: Spacing.sm) {
                        Text("TO")
                            .font(Typography.caption)
                            .tracking(Typography.captionTracking)
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                        DatePicker("", selection: Binding(
                            get: { filterDateTo ?? Date() },
                            set: { filterDateTo = $0 }
                        ), displayedComponents: .date)
                            .labelsHidden()
                    }
                }
            }
        }
        .padding(.horizontal, Spacing.lg)
        .padding(.vertical, Spacing.md)
    }

    private func filterChip(label: String, value: String?, severity: String? = nil) -> some View {
        let isActive = severityFilter == value

        return Button {
            severityFilter = value
        } label: {
            HStack(spacing: Spacing.xs) {
                if let severity = severity {
                    SeverityDot(severity: severity)
                }
                Text(label)
                    .font(Typography.bodySmall)
                    .foregroundStyle(
                        isActive
                            ? Theme.textPrimary(colorScheme)
                            : Theme.textSecondary(colorScheme)
                    )
            }
            .padding(.horizontal, Spacing.s12)
            .padding(.vertical, Spacing.xs)
            .background(
                isActive
                    ? Theme.backgroundTertiary(colorScheme)
                    : Color.clear
            )
            .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusFull))
            .overlay(
                RoundedRectangle(cornerRadius: Spacing.radiusFull)
                    .stroke(
                        isActive
                            ? Theme.borderDefault(colorScheme)
                            : Theme.borderSubtle(colorScheme),
                        lineWidth: 1
                    )
            )
        }
        .buttonStyle(.plain)
    }

    private func typeChip(label: String, value: String?) -> some View {
        let isActive = typeFilter == value

        return Button {
            typeFilter = value
        } label: {
            Text(label)
                .font(Typography.bodySmall)
                .foregroundStyle(
                    isActive
                        ? Theme.textPrimary(colorScheme)
                        : Theme.textSecondary(colorScheme)
                )
                .padding(.horizontal, Spacing.s12)
                .padding(.vertical, Spacing.xs)
                .background(
                    isActive
                        ? Theme.backgroundTertiary(colorScheme)
                        : Color.clear
                )
                .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusFull))
                .overlay(
                    RoundedRectangle(cornerRadius: Spacing.radiusFull)
                        .stroke(
                            isActive
                                ? Theme.borderDefault(colorScheme)
                                : Theme.borderSubtle(colorScheme),
                            lineWidth: 1
                        )
                )
        }
        .buttonStyle(.plain)
    }

    // MARK: - Empty state

    private var emptyState: some View {
        VStack(spacing: Spacing.md) {
            Image(systemName: "bell.slash")
                .font(.system(size: 40))
                .foregroundStyle(Theme.textTertiary(colorScheme))

            Text(emptyStateMessage)
                .font(Typography.body)
                .foregroundStyle(Theme.textSecondary(colorScheme))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyStateMessage: String {
        if !searchText.isEmpty {
            return "No alerts match \"\(searchText)\""
        } else if severityFilter != nil || typeFilter != nil || showDateFilter {
            return "No alerts match the current filters"
        } else {
            return "No alerts yet"
        }
    }

    // MARK: - Export

    private var exportPopover: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            Text("Export Alerts")
                .font(Typography.h4)
                .tracking(Typography.h4Tracking)
                .foregroundStyle(Theme.textPrimary(colorScheme))

            VStack(alignment: .leading, spacing: Spacing.sm) {
                Text("FROM")
                    .font(Typography.caption)
                    .tracking(Typography.captionTracking)
                    .foregroundStyle(Theme.textTertiary(colorScheme))
                DatePicker("", selection: $exportDateFrom, displayedComponents: .date)
                    .labelsHidden()
            }

            VStack(alignment: .leading, spacing: Spacing.sm) {
                Text("TO")
                    .font(Typography.caption)
                    .tracking(Typography.captionTracking)
                    .foregroundStyle(Theme.textTertiary(colorScheme))
                DatePicker("", selection: $exportDateTo, displayedComponents: .date)
                    .labelsHidden()
            }

            HStack(spacing: Spacing.s12) {
                Button("Export All") {
                    performExport(dateFrom: nil, dateTo: nil)
                }
                .buttonStyle(.plain)
                .foregroundStyle(Theme.textSecondary(colorScheme))

                Spacer()

                Button {
                    let formatter = ISO8601DateFormatter()
                    performExport(
                        dateFrom: formatter.string(from: exportDateFrom),
                        dateTo: formatter.string(from: exportDateTo)
                    )
                } label: {
                    Text("Export Range")
                        .font(Typography.body)
                        .foregroundStyle(.white)
                        .padding(.vertical, Spacing.sm)
                        .padding(.horizontal, Spacing.md)
                        .background(Theme.accentDefault(colorScheme))
                        .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
                }
                .buttonStyle(.plain)
            }
        }
        .padding(Spacing.lg)
        .frame(width: 280)
    }

    // MARK: - Actions

    private func markAllRead() {
        let unread = appState.alerts.filter { $0.readAt == nil }
        for alert in unread {
            appState.markAlertRead(alert.id)
        }
        Task {
            for alert in unread {
                try? await appState.sensorClient?.request(.readAlert(id: alert.id))
            }
        }
    }

    // MARK: - Navigation

    private func openIncidentForAlert(_ alert: AlertSummary) {
        guard let incidentId = alert.incidentId else { return }

        // Check cache first
        if let cached = appState.incidents.first(where: { $0.id == incidentId }) {
            selectedIncident = cached
            return
        }

        // Fetch on-demand
        isLoadingIncident = true
        incidentError = nil
        Task {
            do {
                let incident: IncidentDetail = try await appState.sensorClient!.request(.incident(id: incidentId))
                await MainActor.run {
                    appState.addIncident(incident)
                    selectedIncident = incident
                    isLoadingIncident = false
                }
            } catch {
                await MainActor.run {
                    incidentError = "Failed to load incident: \(error.localizedDescription)"
                    isLoadingIncident = false
                }
            }
        }
    }

    private func performExport(dateFrom: String?, dateTo: String?) {
        showExportPopover = false
        isExporting = true

        Task {
            defer { isExporting = false }

            do {
                let response: ExportResponse = try await appState.sensorClient!.request(
                    .exportAlerts(dateFrom: dateFrom, dateTo: dateTo)
                )

                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(response)

                await MainActor.run {
                    let panel = NSSavePanel()
                    let dateStr = String(ISO8601DateFormatter().string(from: Date()).prefix(10))
                    panel.nameFieldStringValue = "squirrelops-alerts-\(dateStr).json"
                    panel.allowedContentTypes = [.json]

                    if panel.runModal() == .OK, let url = panel.url {
                        try? data.write(to: url)
                    }
                }
            } catch {
                // Export failed silently — user can retry
            }
        }
    }
}
