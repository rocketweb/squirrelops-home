import SwiftUI

/// Squirrel Scouts view: scout status, service profiles, and virtual network (mimic decoys).
struct SquirrelScoutsView: View {
    @Environment(\.colorScheme) private var colorScheme
    let appState: AppState

    @State private var scoutStatus: ScoutStatusResponse?
    @State private var profiles: [ServiceProfileSummary] = []
    @State private var mimics: [MimicDecoySummary] = []
    @State private var isLoading = true
    @State private var isRunningScout = false
    @State private var isDeployingMimics = false
    @State private var selectedProfile: ServiceProfileSummary?
    @State private var selectedMimic: MimicDecoySummary?

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            if isLoading {
                loadingState
            } else {
                content
            }
        }
        .background(Theme.background(colorScheme))
        .task { await loadAll() }
    }

    // MARK: - Toolbar

    private var toolbar: some View {
        HStack {
            Text("Squirrel Scouts")
                .font(Typography.h3)
                .tracking(Typography.h3Tracking)
                .foregroundStyle(Theme.textPrimary(colorScheme))
            Spacer()
            if let status = scoutStatus {
                Text(status.enabled ? "Enabled" : "Disabled")
                    .font(Typography.bodySmall)
                    .foregroundStyle(status.enabled
                        ? Theme.statusSuccess(colorScheme)
                        : Theme.textTertiary(colorScheme))
            }
        }
        .padding(Spacing.md)
    }

    // MARK: - Content

    private var content: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                scoutStatusSection
                virtualNetworkSection
                serviceProfilesSection
            }
            .padding(Spacing.lg)
        }
    }

    // MARK: - Scout Status Section

    private var scoutStatusSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            HStack {
                Text("SCOUT ENGINE")
                    .font(Typography.caption)
                    .tracking(Typography.captionTracking)
                    .foregroundStyle(Theme.textTertiary(colorScheme))
                Spacer()
                Button {
                    Task { await runScout() }
                } label: {
                    HStack(spacing: Spacing.xs) {
                        if isRunningScout {
                            ProgressView()
                                .controlSize(.small)
                        } else {
                            Image(systemName: "binoculars")
                                .font(.system(size: 12))
                        }
                        Text("Run Scout")
                            .font(Typography.bodySmall)
                    }
                    .foregroundStyle(Theme.accentDefault(colorScheme))
                }
                .buttonStyle(.plain)
                .disabled(isRunningScout || scoutStatus?.enabled != true)
            }

            if let status = scoutStatus {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 140), spacing: Spacing.md)], spacing: Spacing.md) {
                    MetricCard(title: "Profiles", value: "\(status.totalProfiles)", icon: "doc.text.magnifyingglass")
                    MetricCard(title: "Active Mimics", value: "\(status.activeMimics)/\(status.maxMimics)", icon: "theatermasks")
                    MetricCard(title: "Interval", value: "\(status.intervalMinutes)m", icon: "timer")
                    MetricCard(title: "Status", value: status.isRunning ? "Scouting" : "Idle", icon: "circle.fill")
                }

                if let lastScout = status.lastScoutAt {
                    HStack(spacing: Spacing.sm) {
                        Image(systemName: "clock")
                            .font(.system(size: 12))
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                        Text("Last scout: \(lastScout)")
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textSecondary(colorScheme))
                        if let durationMs = status.lastScoutDurationMs {
                            Text("(\(durationMs)ms)")
                                .font(Typography.mono)
                                .tracking(Typography.monoTracking)
                                .foregroundStyle(Theme.textTertiary(colorScheme))
                        }
                    }
                }
            } else {
                notEnabledCard
            }
        }
    }

    private var notEnabledCard: some View {
        HStack(spacing: Spacing.md) {
            Image(systemName: "binoculars")
                .font(.system(size: 24))
                .foregroundStyle(Theme.textTertiary(colorScheme))
            VStack(alignment: .leading, spacing: Spacing.xs) {
                Text("Scouts Not Enabled")
                    .font(Typography.h4)
                    .tracking(Typography.h4Tracking)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
                Text("Switch to Standard or Full profile to enable Squirrel Scouts.")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textTertiary(colorScheme))
            }
        }
        .padding(Spacing.md)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.backgroundSecondary(colorScheme))
        .overlay(
            RoundedRectangle(cornerRadius: Spacing.radiusLg)
                .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
        )
        .cornerRadius(Spacing.radiusLg)
    }

    // MARK: - Virtual Network Section

    private var virtualNetworkSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            HStack {
                Text("VIRTUAL NETWORK")
                    .font(Typography.caption)
                    .tracking(Typography.captionTracking)
                    .foregroundStyle(Theme.textTertiary(colorScheme))
                Spacer()
                Button {
                    Task { await deployMimics() }
                } label: {
                    HStack(spacing: Spacing.xs) {
                        if isDeployingMimics {
                            ProgressView()
                                .controlSize(.small)
                        } else {
                            Image(systemName: "plus.circle")
                                .font(.system(size: 12))
                        }
                        Text("Deploy")
                            .font(Typography.bodySmall)
                    }
                    .foregroundStyle(Theme.accentDefault(colorScheme))
                }
                .buttonStyle(.plain)
                .disabled(isDeployingMimics || scoutStatus?.enabled != true)
            }

            if mimics.isEmpty {
                HStack(spacing: Spacing.md) {
                    Image(systemName: "theatermasks")
                        .font(.system(size: 24))
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                    Text("No mimic decoys deployed yet. Run a scout cycle first, then deploy.")
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                }
                .padding(Spacing.md)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Theme.backgroundSecondary(colorScheme))
                .overlay(
                    RoundedRectangle(cornerRadius: Spacing.radiusLg)
                        .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
                )
                .cornerRadius(Spacing.radiusLg)
            } else {
                mimicGrid
            }
        }
    }

    private let mimicColumns = [GridItem(.adaptive(minimum: 260), spacing: Spacing.md)]

    private var mimicGrid: some View {
        LazyVGrid(columns: mimicColumns, spacing: Spacing.md) {
            ForEach(mimics) { mimic in
                mimicCard(mimic)
            }
        }
    }

    private func mimicCard(_ mimic: MimicDecoySummary) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            HStack {
                Image(systemName: mimicCategoryIcon(mimic.deviceCategory))
                    .font(.system(size: 18))
                    .foregroundStyle(Theme.textSecondary(colorScheme))
                Text(mimic.name)
                    .font(Typography.h4)
                    .tracking(Typography.h4Tracking)
                    .foregroundStyle(Theme.textPrimary(colorScheme))
                    .lineLimit(1)
                Spacer()
                StatusBadge(
                    label: mimic.status,
                    style: mimicStatusStyle(mimic.status)
                )
            }

            HStack(spacing: Spacing.lg) {
                VStack(alignment: .leading, spacing: Spacing.xs) {
                    Text(mimic.bindAddress)
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(Theme.textPrimary(colorScheme))
                    Text("VIRTUAL IP")
                        .font(Typography.caption)
                        .tracking(Typography.captionTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                }
                VStack(alignment: .leading, spacing: Spacing.xs) {
                    Text(":\(String(mimic.port))")
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(Theme.textPrimary(colorScheme))
                    Text("PORT")
                        .font(Typography.caption)
                        .tracking(Typography.captionTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                }
                VStack(alignment: .leading, spacing: Spacing.xs) {
                    Text("\(mimic.connectionCount)")
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(mimic.connectionCount > 0
                            ? Theme.statusWarning(colorScheme)
                            : Theme.textPrimary(colorScheme))
                    Text("HITS")
                        .font(Typography.caption)
                        .tracking(Typography.captionTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                }
            }

            HStack(spacing: Spacing.xs) {
                if let category = mimic.deviceCategory {
                    Text(category.replacingOccurrences(of: "_", with: " ").capitalized)
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                }
                if let hostname = mimic.mdnsHostname {
                    if mimic.deviceCategory != nil {
                        Text("·")
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                    }
                    Text(hostname + ".local")
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                }
            }

            HStack {
                Spacer()
                if mimic.status == "stopped" {
                    Button {
                        Task { await restartMimic(mimic.id) }
                    } label: {
                        HStack(spacing: Spacing.xs) {
                            Image(systemName: "arrow.clockwise")
                                .font(.system(size: 11))
                            Text("Restart")
                        }
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.accentDefault(colorScheme))
                    }
                    .buttonStyle(.plain)
                }
                Button {
                    Task { await removeMimic(mimic.id) }
                } label: {
                    Text("Remove")
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.statusError(colorScheme))
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

    // MARK: - Service Profiles Section

    private var serviceProfilesSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            HStack {
                Text("SERVICE PROFILES")
                    .font(Typography.caption)
                    .tracking(Typography.captionTracking)
                    .foregroundStyle(Theme.textTertiary(colorScheme))
                Spacer()
                Text("\(profiles.count) profiles")
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
            }

            if profiles.isEmpty {
                Text("No service profiles collected yet. Run a scout cycle to probe devices.")
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
            } else {
                profileList
            }
        }
    }

    private var profileList: some View {
        VStack(spacing: 0) {
            ForEach(profiles) { profile in
                profileRow(profile)
                if profile.id != profiles.last?.id {
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

    private func profileRow(_ profile: ServiceProfileSummary) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: Spacing.xs) {
                HStack(spacing: Spacing.sm) {
                    Text(profile.ipAddress)
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(Theme.textPrimary(colorScheme))
                    Text(":\(String(profile.port))")
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(Theme.accentDefault(colorScheme))
                }
                HStack(spacing: Spacing.sm) {
                    if let service = profile.serviceName {
                        Text(service)
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textSecondary(colorScheme))
                    }
                    if let server = profile.httpServerHeader {
                        Text(server)
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                            .lineLimit(1)
                    }
                    if let proto = profile.protocolVersion {
                        Text(proto)
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                            .lineLimit(1)
                    }
                }
            }

            Spacer()

            VStack(alignment: .trailing, spacing: Spacing.xs) {
                if let httpStatus = profile.httpStatus {
                    Text("HTTP \(httpStatus)")
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(httpStatusColor(httpStatus))
                }
                if let tls = profile.tlsCn {
                    HStack(spacing: 2) {
                        Image(systemName: "lock.fill")
                            .font(.system(size: 10))
                        Text(tls)
                            .lineLimit(1)
                    }
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.statusSuccess(colorScheme))
                }
            }
        }
        .padding(.vertical, Spacing.sm)
        .padding(.horizontal, Spacing.md)
    }

    // MARK: - Loading State

    private var loadingState: some View {
        VStack {
            Spacer()
            ProgressView("Loading scout data...")
                .foregroundStyle(Theme.textSecondary(colorScheme))
            Spacer()
        }
    }

    // MARK: - Actions

    private func loadAll() async {
        guard let client = appState.sensorClient else {
            isLoading = false
            return
        }
        do {
            async let statusReq: ScoutStatusResponse = client.request(.scoutStatus)
            async let profilesReq: [ServiceProfileSummary] = client.request(.scoutProfiles)
            async let mimicsReq: [MimicDecoySummary] = client.request(.mimicDecoys)

            let (s, p, m) = try await (statusReq, profilesReq, mimicsReq)
            scoutStatus = s
            profiles = p
            mimics = m
        } catch {
            // Show whatever we managed to load
        }
        isLoading = false
    }

    private func runScout() async {
        guard let client = appState.sensorClient else { return }
        isRunningScout = true
        do {
            let _: ScoutRunResponse = try await client.request(.runScout)
            await loadAll()
        } catch {
            // Silently fail
        }
        isRunningScout = false
    }

    private func deployMimics() async {
        guard let client = appState.sensorClient else { return }
        isDeployingMimics = true
        do {
            let _: MimicDeployResponse = try await client.request(.deployMimics)
            await loadAll()
        } catch {
            // Silently fail
        }
        isDeployingMimics = false
    }

    private func restartMimic(_ id: Int) async {
        guard let client = appState.sensorClient else { return }
        do {
            try await client.request(.restartMimic(id: id))
            await loadAll()
        } catch {
            // Silently fail
        }
    }

    private func removeMimic(_ id: Int) async {
        guard let client = appState.sensorClient else { return }
        do {
            try await client.request(.removeMimic(id: id))
            mimics.removeAll { $0.id == id }
            // Refresh status to update active mimic count
            if let status: ScoutStatusResponse = try? await client.request(.scoutStatus) {
                scoutStatus = status
            }
        } catch {
            // Silently fail
        }
    }

    // MARK: - Helpers

    private func mimicCategoryIcon(_ category: String?) -> String {
        switch category {
        case "smart_home": return "house"
        case "camera": return "video"
        case "nas": return "externaldrive"
        case "media": return "play.tv"
        case "printer": return "printer"
        case "router": return "wifi.router"
        case "dev_server": return "chevron.left.forwardslash.chevron.right"
        default: return "theatermasks"
        }
    }

    private func mimicStatusStyle(_ status: String) -> StatusBadge.Style {
        switch status {
        case "active": return .active
        case "degraded": return .degraded
        case "stopped": return .stopped
        default: return .offline
        }
    }

    private func httpStatusColor(_ code: Int) -> Color {
        switch code {
        case 200..<300: return Theme.statusSuccess(colorScheme)
        case 300..<400: return Theme.statusWarning(colorScheme)
        case 400..<500: return Theme.statusError(colorScheme)
        case 500...: return Theme.statusError(colorScheme)
        default: return Theme.textSecondary(colorScheme)
        }
    }
}
