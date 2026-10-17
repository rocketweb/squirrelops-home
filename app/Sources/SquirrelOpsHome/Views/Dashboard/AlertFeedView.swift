import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct AlertFeedView: View {
    let appState: AppState
    @Environment(\.colorScheme) private var colorScheme

    @State private var searchText: String = ""
    @State private var severityFilter: String? = nil
    @State private var selectedIncident: IncidentDetail?
    @State private var selectedAlertDetail: AlertDetail?
    @State private var isLoadingIncident = false
    @State private var isLoadingAlertDetail = false
    @State private var incidentError: String?
    @State private var showExportPopover = false
    @State private var exportDateFrom: Date = Calendar.current.date(byAdding: .day, value: -30, to: Date())!
    @State private var exportDateTo: Date = Date()
    @State private var isExporting = false
    @State private var typeFilter: String? = nil
    @State private var filterDateFrom: Date? = nil
    @State private var filterDateTo: Date? = nil
    @State private var showDateFilter = false
    @State private var showDismissed = false
    @State private var selectedAlertId: Int?
    @State private var alertDetailId: Int?
    @State private var showClearConfirmation = false
    @State private var isClearingHistory = false
    @State private var historyClearMessage: String?
    @State private var historyClearError: String?

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
        (
            "Security",
            [
                "security.arp_conflict",
                "security.port_risk",
                "security.vendor_advisory",
            ]
        ),
        ("System", ["system.sensor_offline", "system.learning_complete"]),
    ]

    private static let isoFormatter = ISO8601DateFormatter()

    // MARK: - Filtered alerts

    private var filteredAlerts: [AlertSummary] {
        let query = searchText.lowercased()

        return appState.alerts
            .filter { alert in
                // Active/dismissed filter: hide read alerts unless "Show History" is on
                if !showDismissed && alert.readAt != nil {
                    return false
                }
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

            if let historyClearMessage {
                historyNotice(historyClearMessage, isError: false)
            }
            if let historyClearError {
                historyNotice(historyClearError, isError: true)
            }

            if filteredAlerts.isEmpty {
                emptyState
            } else {
                List(filteredAlerts, selection: $selectedAlertId) { alert in
                    AlertRow(alert: alert, onDismiss: alert.readAt == nil ? {
                        dismissAlert(alert)
                    } : nil)
                        .tag(alert.id)
                        .listRowInsets(EdgeInsets())
                        .listRowSeparator(.visible)
                        .contextMenu {
                            if alert.readAt == nil {
                                Button("Dismiss") {
                                    dismissAlert(alert)
                                }
                            }
                            if alert.incidentId != nil {
                                Button("View Incident") {
                                    openIncidentForAlert(alert)
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

                    // Always open the alert detail sheet
                    alertDetailId = alert.id
                }
            }
        }
        .background(Theme.background(colorScheme))
        .sheet(item: $selectedIncident) { incident in
            IncidentDetailView(incident: incident, appState: appState)
        }
        .sheet(isPresented: Binding(
            get: { alertDetailId != nil },
            set: { if !$0 { alertDetailId = nil } }
        )) {
            if let id = alertDetailId {
                AlertDetailView(alertId: id, appState: appState)
            }
        }
        .overlay {
            if isLoadingIncident || isLoadingAlertDetail {
                ProgressView(isLoadingAlertDetail ? "Loading alert..." : "Loading incident...")
                    .padding()
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
            }
        }
        .confirmationDialog(
            "Clear all alert history?",
            isPresented: $showClearConfirmation,
            titleVisibility: .visible
        ) {
            Button("Clear Alert History", role: .destructive) {
                Task { await clearAlertHistory() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "This removes every alert and incident from the dashboard. "
                + "The sensor creates a recovery backup before deleting them."
            )
        }
    }

    // MARK: - Toolbar

    private var toolbar: some View {
        VStack(alignment: .leading, spacing: 0) {
            PageHeader(title: "Alerts") {
                InventorySearchField(title: "Search alerts…", text: $searchText)
            }

            HStack(spacing: Spacing.sm) {
                Picker("Severity", selection: $severityFilter) {
                    Text("All").tag(nil as String?)
                    ForEach(Self.severityLevels, id: \.value) { level in
                        Text(level.label).tag(Optional(level.value))
                    }
                }
                .frame(width: 145)

                Picker("Type", selection: $typeFilter) {
                    Text("All Types").tag(nil as String?)
                    ForEach(Self.alertTypes, id: \.label) { type in
                        Text(type.label).tag(Optional(type.label))
                    }
                }
                .labelsHidden()
                .frame(width: 130)

                Button {
                    showDateFilter.toggle()
                    filterDateFrom = showDateFilter
                        ? Calendar.current.date(byAdding: .day, value: -7, to: Date()) : nil
                    filterDateTo = showDateFilter ? Date() : nil
                } label: {
                    Label(showDateFilter ? "Clear Dates" : "Dates", systemImage: "calendar")
                }
                .help(showDateFilter ? "Remove date filter" : "Filter by date range")

                Spacer(minLength: 0)

                Menu("Actions") {
                    Toggle("Show History", isOn: $showDismissed)
                    Divider()
                    Button("Dismiss All", systemImage: "checkmark.circle") { dismissAll() }
                        .disabled(!appState.alerts.contains { $0.readAt == nil })
                    Button("Export…", systemImage: "square.and.arrow.up") { showExportPopover = true }
                    Divider()
                    Button("Clear History…", systemImage: "trash", role: .destructive) {
                        showClearConfirmation = true
                    }
                    .disabled(!hasAlertHistory || isClearingHistory)
                }
                .fixedSize()
                .popover(isPresented: $showExportPopover) { exportPopover }
            }
            .pickerStyle(.menu)
            .padding(.horizontal, Spacing.lg)
            .padding(.bottom, Spacing.s12)

            if showDismissed {
                Label("Showing history, including dismissed alerts", systemImage: "clock")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
                    .padding(.horizontal, Spacing.lg)
                    .padding(.bottom, Spacing.sm)
            }
            if showDateFilter {
                HStack(spacing: Spacing.md) {
                    DatePicker("From", selection: Binding(
                        get: { filterDateFrom ?? Date() },
                        set: { filterDateFrom = $0 }
                    ), displayedComponents: .date)
                    DatePicker("To", selection: Binding(
                        get: { filterDateTo ?? Date() },
                        set: { filterDateTo = $0 }
                    ), displayedComponents: .date)
                    Spacer(minLength: 0)
                }
                .padding(.horizontal, Spacing.lg)
                .padding(.bottom, Spacing.s12)
            }
        }
    }

    // MARK: - Empty state

    private var emptyState: some View {
        VStack(spacing: Spacing.md) {
            Image(systemName: !showDismissed && appState.alerts.contains(where: { $0.readAt != nil })
                  ? "checkmark.circle" : "bell.slash")
                .font(.system(size: 40))
                .foregroundStyle(Theme.textTertiary(colorScheme))

            Text(emptyStateMessage)
                .font(Typography.body)
                .foregroundStyle(Theme.textSecondary(colorScheme))

            if !showDismissed && appState.alerts.contains(where: { $0.readAt != nil }) {
                Button("Show History") {
                    showDismissed = true
                }
                .buttonStyle(.plain)
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.accentText(colorScheme))
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyStateMessage: String {
        if !searchText.isEmpty {
            return "No alerts match \"\(searchText)\""
        } else if severityFilter != nil || typeFilter != nil || showDateFilter {
            return "No alerts match the current filters"
        } else if !showDismissed && appState.alerts.contains(where: { $0.readAt != nil }) {
            return "All alerts dismissed"
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

    private var hasAlertHistory: Bool {
        !appState.alerts.isEmpty || (appState.systemStatus?.alertCount ?? 0) > 0
    }

    private func historyNotice(_ message: String, isError: Bool) -> some View {
        let color = isError
            ? Theme.statusError(colorScheme)
            : Theme.statusSuccess(colorScheme)
        return Label(
            message,
            systemImage: isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill"
        )
        .font(Typography.bodySmall)
        .foregroundStyle(color)
        .padding(.horizontal, Spacing.lg)
        .padding(.vertical, Spacing.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(0.08))
    }

    private func clearAlertHistory() async {
        isClearingHistory = true
        historyClearMessage = nil
        historyClearError = nil
        do {
            let response = try await appState.clearAlertHistory()
            selectedAlertId = nil
            alertDetailId = nil
            selectedAlertDetail = nil
            selectedIncident = nil
            showDismissed = false
            historyClearMessage = response.userSummary
        } catch {
            historyClearError = "Could not clear alert history: \(error.localizedDescription)"
        }
        isClearingHistory = false
    }

    private func dismissAlert(_ alert: AlertSummary) {
        appState.markAlertRead(alert.id)
        Task {
            try? await appState.sensorClient?.request(.readAlert(id: alert.id))
        }
    }

    private func dismissAll() {
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

    private func openAlertDetail(_ alert: AlertSummary) {
        isLoadingAlertDetail = true
        Task {
            do {
                let detail: AlertDetail = try await appState.requireSensorClient().request(.alert(id: alert.id))
                await MainActor.run {
                    selectedAlertDetail = detail
                    isLoadingAlertDetail = false
                }
            } catch {
                await MainActor.run {
                    isLoadingAlertDetail = false
                }
            }
        }
    }

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
                let incident: IncidentDetail = try await appState.requireSensorClient().request(.incident(id: incidentId))
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
                let response: ExportResponse = try await appState.requireSensorClient().request(
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
