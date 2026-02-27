import SwiftUI

struct IncidentDetailView: View {
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.dismiss) private var dismiss
    let incident: IncidentDetail
    let appState: AppState
    @State private var expandedAlertId: Int? = nil
    @State private var isMarkingRead = false

    private var statusBadgeStyle: StatusBadge.Style {
        switch incident.status {
        case "active": return .critical
        case "closed": return .stopped
        default: return .degraded
        }
    }

    @MainActor private func markAllRead() {
        isMarkingRead = true
        Task {
            try? await appState.sensorClient?.request(.readIncident(id: incident.id))
            for alert in incident.alerts {
                appState.markAlertRead(alert.id)
            }
            isMarkingRead = false
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerSection
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.lg) {
                    if let summary = incident.summary, !summary.isEmpty {
                        summarySection(summary)
                    }
                    childAlertsSection
                }
                .padding(Spacing.lg)
            }
        }
        .frame(minWidth: 460, idealWidth: 520, minHeight: 500, idealHeight: 640)
        .background(Theme.background(colorScheme))
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: Spacing.sm) {
                HStack(spacing: Spacing.sm) {
                    SeverityDot(severity: incident.severity)

                    Text("Incident #\(incident.id)")
                        .font(Typography.h3)
                        .tracking(Typography.h3Tracking)
                        .foregroundStyle(Theme.textPrimary(colorScheme))
                }

                HStack(spacing: Spacing.sm) {
                    Text(incident.sourceIp)
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(Theme.textSecondary(colorScheme))

                    if let mac = incident.sourceMac {
                        Text(mac)
                            .font(Typography.mono)
                            .tracking(Typography.monoTracking)
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                    }
                }

                HStack(spacing: Spacing.s12) {
                    StatusBadge(
                        label: incident.status,
                        style: statusBadgeStyle
                    )

                    Text("\(incident.alertCount) alert\(incident.alertCount == 1 ? "" : "s")")
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                }

                HStack(spacing: Spacing.xs) {
                    Text(incident.firstAlertAt)
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))

                    if incident.firstAlertAt != incident.lastAlertAt {
                        Text("—")
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                        Text(incident.lastAlertAt)
                            .font(Typography.mono)
                            .tracking(Typography.monoTracking)
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                    }
                }
            }

            Spacer()

            HStack(spacing: Spacing.sm) {
                Button {
                    markAllRead()
                } label: {
                    Text("Mark All Read")
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                }
                .buttonStyle(.plain)
                .disabled(isMarkingRead)

                Button("Done") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
            }
        }
        .padding(Spacing.lg)
    }

    // MARK: - Summary

    private func summarySection(_ summary: String) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("SUMMARY")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            Text(summary)
                .font(Typography.body)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(Spacing.md)
                .background(Theme.backgroundSecondary(colorScheme))
                .overlay(
                    RoundedRectangle(cornerRadius: Spacing.radiusMd)
                        .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
        }
    }

    // MARK: - Child Alerts

    private var childAlertsSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("CHILD ALERTS")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            if incident.alerts.isEmpty {
                Text("No child alerts recorded for this incident")
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
                    ForEach(incident.alerts) { alert in
                        childAlertRow(alert)

                        if alert.id != incident.alerts.last?.id {
                            Divider()
                                .foregroundStyle(Theme.borderSubtle(colorScheme))
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

    private func childAlertRow(_ alert: AlertDetail) -> some View {
        let isExpanded = expandedAlertId == alert.id

        return VStack(alignment: .leading, spacing: 0) {
            // Collapsed row (always visible)
            Button {
                withAnimation(.easeInOut(duration: 0.2)) {
                    expandedAlertId = isExpanded ? nil : alert.id
                }
            } label: {
                HStack(spacing: Spacing.s12) {
                    SeverityDot(severity: alert.severity)

                    Text(alert.title)
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textPrimary(colorScheme))
                        .lineLimit(1)

                    Spacer()

                    Text(alert.createdAt)
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                        .lineLimit(1)

                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                        .font(.system(size: 10))
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                }
                .padding(.vertical, Spacing.sm)
                .padding(.horizontal, Spacing.md)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            // Expanded detail
            if isExpanded {
                VStack(alignment: .leading, spacing: Spacing.sm) {
                    detailRow(label: "Type", value: alert.alertType)

                    if let ip = alert.sourceIp {
                        detailRow(label: "Source IP", value: ip, mono: true)
                    }
                    if let mac = alert.sourceMac {
                        detailRow(label: "Source MAC", value: mac, mono: true)
                    }
                    if let deviceId = alert.deviceId {
                        detailRow(label: "Device ID", value: "#\(deviceId)")
                    }
                    if let decoyId = alert.decoyId {
                        detailRow(label: "Decoy ID", value: "#\(decoyId)")
                    }
                    if let readAt = alert.readAt {
                        detailRow(label: "Read", value: readAt, mono: true)
                    }
                    if let actionedAt = alert.actionedAt {
                        detailRow(label: "Actioned", value: actionedAt, mono: true)
                    }
                    if let note = alert.actionNote {
                        detailRow(label: "Note", value: note)
                    }

                    // Render detail JSON
                    detailSection(alert.detail)
                }
                .padding(.horizontal, Spacing.md)
                .padding(.bottom, Spacing.sm)
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
    }

    private func detailRow(label: String, value: String, mono: Bool = false) -> some View {
        HStack(alignment: .top, spacing: Spacing.sm) {
            Text(label)
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))
                .frame(width: 80, alignment: .trailing)

            if mono {
                Text(value)
                    .font(Typography.mono)
                    .tracking(Typography.monoTracking)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
            } else {
                Text(value)
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
            }
        }
    }

    private func detailSection(_ detail: AnyCodableValue) -> some View {
        Group {
            switch detail {
            case .object(let dict) where !dict.isEmpty:
                ForEach(dict.keys.sorted(), id: \.self) { key in
                    detailRow(
                        label: key,
                        value: formatAnyCodableValue(dict[key]!)
                    )
                }
            case .string(let str) where !str.isEmpty:
                detailRow(label: "Detail", value: str)
            default:
                EmptyView()
            }
        }
    }

    private func formatAnyCodableValue(_ value: AnyCodableValue) -> String {
        switch value {
        case .string(let s): return s
        case .int(let i): return String(i)
        case .double(let d): return String(d)
        case .bool(let b): return b ? "true" : "false"
        case .null: return "—"
        case .array(let arr): return "[\(arr.map { formatAnyCodableValue($0) }.joined(separator: ", "))]"
        case .object(let dict): return dict.keys.sorted().map { "\($0): \(formatAnyCodableValue(dict[$0]!))" }.joined(separator: ", ")
        }
    }
}
