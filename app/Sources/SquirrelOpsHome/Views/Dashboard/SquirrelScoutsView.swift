import SwiftUI

struct ScoutMimicRevision: Equatable, Hashable, Sendable {
    let id: Int
    let bindAddress: String
    let port: Int
    let status: String
    let connectionCount: Int
}

struct ScoutRefreshSnapshot: Equatable, Sendable {
    let hasStatus: Bool
    let isRunning: Bool
    let activeMimics: Int
    let maxMimics: Int
    let mimicRevision: [ScoutMimicRevision]

    init(
        isRunning: Bool,
        activeMimics: Int,
        maxMimics: Int,
        mimicRevision: [ScoutMimicRevision]
    ) {
        self.hasStatus = true
        self.isRunning = isRunning
        self.activeMimics = activeMimics
        self.maxMimics = maxMimics
        self.mimicRevision = mimicRevision
    }

    init(status: ScoutStatusResponse?, mimics: [MimicDecoySummary]) {
        self.hasStatus = status != nil
        self.isRunning = status?.isRunning ?? false
        self.activeMimics = status?.activeMimics ?? 0
        self.maxMimics = status?.maxMimics ?? 0
        self.mimicRevision = mimics
            .map {
                ScoutMimicRevision(
                    id: $0.id,
                    bindAddress: $0.bindAddress,
                    port: $0.port,
                    status: $0.status,
                    connectionCount: $0.connectionCount
                )
            }
            .sorted { $0.id < $1.id }
    }

    var isIdleAtCapacity: Bool {
        let activeRows = mimicRevision.lazy.filter { $0.status == "active" }.count
        return hasStatus
            && !isRunning
            && maxMimics > 0
            && activeMimics >= maxMimics
            && activeRows >= activeMimics
    }
}

struct ScoutRefreshPollState {
    private let maximumPolls: Int
    private let requiredStableIdleSamples: Int
    private var pollsStarted = 0
    private var stableIdleSamples = 0
    private var previousSnapshot: ScoutRefreshSnapshot?

    init(maximumPolls: Int = 45, requiredStableIdleSamples: Int = 5) {
        self.maximumPolls = max(0, maximumPolls)
        self.requiredStableIdleSamples = max(1, requiredStableIdleSamples)
    }

    mutating func shouldPoll(after snapshot: ScoutRefreshSnapshot) -> Bool {
        guard pollsStarted < maximumPolls else { return false }

        if snapshot.isRunning {
            stableIdleSamples = 0
        } else if snapshot.isIdleAtCapacity {
            previousSnapshot = snapshot
            return false
        } else if snapshot == previousSnapshot {
            stableIdleSamples += 1
        } else {
            stableIdleSamples = 0
        }
        previousSnapshot = snapshot

        guard snapshot.isRunning || stableIdleSamples < requiredStableIdleSamples else {
            return false
        }
        pollsStarted += 1
        return true
    }
}

enum ScoutRefreshPolicy {
    static func mimicRevision(in decoys: [DecoySummary]) -> [ScoutMimicRevision] {
        decoys
            .filter(\.isVirtualMimic)
            .map {
                ScoutMimicRevision(
                    id: $0.id,
                    bindAddress: $0.bindAddress,
                    port: $0.port,
                    status: $0.status,
                    connectionCount: $0.connectionCount
                )
            }
            .sorted { $0.id < $1.id }
    }

    static func applying(
        _ revisions: [ScoutMimicRevision],
        to mimics: [MimicDecoySummary]
    ) -> [MimicDecoySummary] {
        let connectionCounts = Dictionary(
            uniqueKeysWithValues: revisions.map { ($0.id, $0.connectionCount) }
        )
        return mimics.map { mimic in
            guard let connectionCount = connectionCounts[mimic.id],
                  connectionCount != mimic.connectionCount else {
                return mimic
            }
            return mimic.replacingConnectionCount(connectionCount)
        }
    }
}

/// Squirrel Scouts view: scout status, service profiles, and virtual fake hosts.
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
    @State private var editingMimicGroupID: String?
    @State private var hostnameDraft = ""
    @State private var isSavingHostname = false
    @State private var actionMessage: String?
    @State private var actionMessageIsError = false
    @State private var loadError: String?

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            if let actionMessage {
                noticeBanner(actionMessage, isError: actionMessageIsError)
            }
            if let loadError {
                noticeBanner(loadError, isError: true)
            }
            if isLoading {
                loadingState
            } else {
                content
            }
        }
        .background(Theme.background(colorScheme))
        .task {
            await loadAll()
            await pollWhileCapacitySettles()
        }
        .onChange(of: ScoutRefreshPolicy.mimicRevision(in: appState.decoys)) {
            _, revision in
            mimics = ScoutRefreshPolicy.applying(revision, to: mimics)
            Task {
                await loadAll()
            }
        }
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
        .refreshable {
            await loadAll()
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
                        if isRunningScout || scoutStatus?.isRunning == true {
                            ProgressView()
                                .controlSize(.small)
                        } else {
                            Image(systemName: "binoculars")
                                .font(.system(size: 12))
                        }
                        Text(scoutStatus?.isRunning == true ? "Scout Running" : "Run Scout")
                            .font(Typography.bodySmall)
                    }
                    .foregroundStyle(Theme.accentDefault(colorScheme))
                }
                .buttonStyle(.plain)
                .disabled(
                    isRunningScout
                    || scoutStatus?.isRunning == true
                    || scoutStatus?.enabled != true
                )
            }

            if let status = scoutStatus {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 140), spacing: Spacing.md)], spacing: Spacing.md) {
                    MetricCard(title: "Profiles", value: "\(status.totalProfiles)", icon: "doc.text.magnifyingglass")
                    MetricCard(
                        title: "Fake Hosts",
                        value: "\(status.fakeHostCount ?? status.activeMimics)/\(status.maxMimics)",
                        icon: "theatermasks"
                    )
                    MetricCard(
                        title: "Service Decoys",
                        value: "\(status.serviceDecoyCount ?? mimics.filter { $0.status == "active" }.count)",
                        icon: "network"
                    )
                    MetricCard(title: "Interval", value: "\(status.intervalMinutes)m", icon: "timer")
                    MetricCard(title: "Status", value: status.isRunning ? "Scouting" : "Idle", icon: "circle.fill")
                }

                if let lastScout = status.lastScoutAt {
                    HStack(spacing: Spacing.sm) {
                        Image(systemName: "clock")
                            .font(.system(size: 12))
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                        Text(
                            "Last scout: "
                                + TimestampPresentation.local(lastScout)
                        )
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textSecondary(colorScheme))
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
                        Text("Fill Capacity")
                            .font(Typography.bodySmall)
                    }
                    .foregroundStyle(Theme.accentDefault(colorScheme))
                }
                .buttonStyle(.plain)
                .disabled(
                    isDeployingMimics
                    || isRunningScout
                    || scoutStatus?.isRunning == true
                    || scoutStatus?.enabled != true
                )
            }

            Text(
                "Run Scout refreshes service profiles and fills eligible mimic slots. "
                + "Fill Capacity retries deployment without probing the network again."
            )
            .font(Typography.bodySmall)
            .foregroundStyle(Theme.textSecondary(colorScheme))

            if mimics.isEmpty {
                HStack(spacing: Spacing.md) {
                    Image(systemName: "theatermasks")
                        .font(.system(size: 24))
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                    Text("No fake hosts deployed yet. Run Scout to discover services and fill available capacity.")
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
                Text(
                    "\(mimicGroups.count) fake hosts · "
                    + "\(mimics.count) service decoys"
                )
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                mimicGrid
            }
        }
    }

    private var mimicGroups: [MimicHostGroup] {
        MimicHostGroup.grouping(mimics)
    }

    private let mimicColumns = [GridItem(.adaptive(minimum: 340), spacing: Spacing.md)]

    private var mimicGrid: some View {
        LazyVGrid(columns: mimicColumns, spacing: Spacing.md) {
            ForEach(mimicGroups) { group in
                mimicHostCard(group)
            }
        }
    }

    private func mimicHostCard(_ group: MimicHostGroup) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            HStack(alignment: .top, spacing: Spacing.sm) {
                Image(systemName: mimicCategoryIcon(group.deviceCategory))
                    .font(.system(size: 18))
                    .foregroundStyle(Theme.textSecondary(colorScheme))

                VStack(alignment: .leading, spacing: Spacing.xs) {
                    if editingMimicGroupID == group.id {
                        TextField("hostname.local", text: $hostnameDraft)
                            .textFieldStyle(.roundedBorder)
                            .font(Typography.mono)
                            .onSubmit {
                                Task { await saveHostname(for: group) }
                            }

                        HStack(spacing: Spacing.sm) {
                            Button("Cancel") {
                                editingMimicGroupID = nil
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(Theme.textSecondary(colorScheme))

                            Button {
                                Task { await saveHostname(for: group) }
                            } label: {
                                if isSavingHostname {
                                    ProgressView()
                                        .controlSize(.small)
                                } else {
                                    Text("Save hostname")
                                }
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(Theme.accentDefault(colorScheme))
                            .disabled(
                                isSavingHostname
                                || hostnameDraft.trimmingCharacters(
                                    in: .whitespacesAndNewlines
                                ).isEmpty
                            )
                        }
                        .font(Typography.bodySmall)
                    } else {
                        HStack(spacing: Spacing.xs) {
                            Text(mimicHostTitle(group))
                                .font(Typography.h4)
                                .tracking(Typography.h4Tracking)
                                .foregroundStyle(Theme.textPrimary(colorScheme))
                                .lineLimit(1)

                            Button {
                                beginEditingHostname(group)
                            } label: {
                                Image(systemName: "pencil")
                                    .font(.system(size: 11))
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(Theme.accentDefault(colorScheme))
                            .help("Edit hostname for every service on this fake host")
                        }
                    }

                    Text(group.bindAddress)
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                }

                Spacer()
                StatusBadge(
                    label: mimicGroupStatus(group),
                    style: mimicStatusStyle(mimicGroupStatus(group))
                )
            }

            if let representative = group.services.first {
                HStack(spacing: Spacing.md) {
                    if mimicGroupStatus(group) == "stopped"
                        || mimicGroupStatus(group) == "degraded" {
                        Button {
                            Task { await restartMimic(representative.id) }
                        } label: {
                            Label("Restart fake host", systemImage: "arrow.clockwise")
                                .font(Typography.bodySmall)
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(Theme.accentDefault(colorScheme))
                    }

                    Spacer()

                    Button {
                        Task { await removeMimic(representative.id) }
                    } label: {
                        Label("Remove fake host", systemImage: "trash")
                            .font(Typography.bodySmall)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(Theme.statusError(colorScheme))
                    .help("Remove this fake host and all of its service decoys")
                }
            }

            HStack {
                Text(
                    "\(group.services.count) "
                    + (group.services.count == 1 ? "SERVICE" : "SERVICES")
                )
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))
                Spacer()
                Text("\(group.connectionCount) TOTAL HITS")
                    .font(Typography.caption)
                    .tracking(Typography.captionTracking)
                    .foregroundStyle(group.connectionCount > 0
                        ? Theme.statusWarning(colorScheme)
                        : Theme.textTertiary(colorScheme))
            }

            VStack(spacing: 0) {
                ForEach(group.services) { mimic in
                    mimicServiceRow(mimic)
                    if mimic.id != group.services.last?.id {
                        Divider()
                            .padding(.vertical, Spacing.sm)
                    }
                }
            }
            .padding(Spacing.s12)
            .background(Theme.background(colorScheme).opacity(0.55))
            .overlay(
                RoundedRectangle(cornerRadius: Spacing.radiusMd)
                    .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
        }
        .padding(Spacing.md)
        .background(Theme.backgroundSecondary(colorScheme))
        .overlay(
            RoundedRectangle(cornerRadius: Spacing.radiusLg)
                .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
        )
        .cornerRadius(Spacing.radiusLg)
    }

    private func mimicServiceRow(_ mimic: MimicDecoySummary) -> some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            HStack(spacing: Spacing.sm) {
                Text(mimic.serviceLabel)
                    .font(Typography.body)
                    .foregroundStyle(Theme.textPrimary(colorScheme))
                    .lineLimit(1)
                Spacer()
                StatusBadge(
                    label: mimic.status,
                    style: mimicStatusStyle(mimic.status)
                )
            }

            HStack(spacing: Spacing.sm) {
                Text(":\(mimic.port)")
                    .font(Typography.mono)
                    .tracking(Typography.monoTracking)
                    .foregroundStyle(Theme.accentDefault(colorScheme))
                if let serviceProtocol = mimic.serviceProtocol,
                   !serviceProtocol.isEmpty {
                    Text(serviceProtocol.uppercased())
                        .font(Typography.caption)
                        .tracking(Typography.captionTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                }
                Spacer()
                Text("\(mimic.connectionCount) hits")
                    .font(Typography.mono)
                    .tracking(Typography.monoTracking)
                    .foregroundStyle(mimic.connectionCount > 0
                        ? Theme.statusWarning(colorScheme)
                        : Theme.textSecondary(colorScheme))
            }
        }
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

    private func noticeBanner(_ message: String, isError: Bool) -> some View {
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

    // MARK: - Actions

    private func beginEditingHostname(_ group: MimicHostGroup) {
        hostnameDraft = group.hostname ?? ""
        editingMimicGroupID = group.id
        actionMessage = nil
    }

    private func saveHostname(for group: MimicHostGroup) async {
        guard let client = appState.sensorClient,
              let representative = group.services.first else {
            actionMessage = "Sensor is not connected."
            actionMessageIsError = true
            return
        }

        let hostname = hostnameDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !hostname.isEmpty else { return }

        isSavingHostname = true
        defer { isSavingHostname = false }

        do {
            let response: DecoyHostnameUpdateResponse = try await client.request(
                .updateDecoyHostname(id: representative.id, hostname: hostname)
            )
            let updatedIds = Set(response.decoyIds)
            mimics = mimics.map { mimic in
                guard updatedIds.contains(mimic.id) else { return mimic }
                return mimic.replacingHostname(response.hostname)
            }
            editingMimicGroupID = nil
            actionMessage = "Updated \(response.bindAddress) to \(response.hostname)."
            actionMessageIsError = false
            await loadAll()
            await appState.refreshDecoys()
        } catch {
            actionMessage = "Could not update hostname: \(error.localizedDescription)"
            actionMessageIsError = true
        }
    }

    private func loadAll() async {
        guard let client = appState.sensorClient else {
            loadError = "Sensor is not connected."
            isLoading = false
            return
        }

        var failures: [String] = []
        do {
            let status: ScoutStatusResponse = try await client.request(.scoutStatus)
            scoutStatus = status
        } catch {
            failures.append("status: \(error.localizedDescription)")
        }
        do {
            let updatedProfiles: [ServiceProfileSummary] = try await client.request(.scoutProfiles)
            profiles = updatedProfiles
        } catch {
            failures.append("profiles: \(error.localizedDescription)")
        }
        do {
            let updatedMimics: [MimicDecoySummary] = try await client.request(.mimicDecoys)
            mimics = updatedMimics
        } catch {
            failures.append("mimics: \(error.localizedDescription)")
        }

        loadError = failures.isEmpty
            ? nil
            : "Could not refresh scout \(failures.joined(separator: "; "))."
        isLoading = false
    }

    private func runScout() async {
        guard let client = appState.sensorClient else { return }
        guard scoutStatus?.isRunning != true else {
            actionMessage = "A scout cycle is already running."
            actionMessageIsError = true
            return
        }

        isRunningScout = true
        actionMessage = nil
        actionMessageIsError = false
        do {
            let response: ScoutRunResponse = try await client.request(.runScout)
            await loadAll()
            await appState.refreshDecoys()
            try? await appState.refreshSystemStatus()
            actionMessage = response.userSummary
            actionMessageIsError = response.mimicDeploymentError != nil
        } catch {
            actionMessage = "Scout failed: \(error.localizedDescription)"
            actionMessageIsError = true
        }
        isRunningScout = false
    }

    private func deployMimics() async {
        guard let client = appState.sensorClient else { return }
        guard !isRunningScout, scoutStatus?.isRunning != true else {
            actionMessage = "Wait for the current scout cycle to finish."
            actionMessageIsError = true
            return
        }
        isDeployingMimics = true
        actionMessage = nil
        actionMessageIsError = false
        do {
            let response: MimicDeployResponse = try await client.request(.deployMimics)
            await loadAll()
            await appState.refreshDecoys()
            try? await appState.refreshSystemStatus()
            actionMessage = response.userSummary
        } catch {
            actionMessage = "Could not fill mimic capacity: \(error.localizedDescription)"
            actionMessageIsError = true
        }
        isDeployingMimics = false
    }

    private func restartMimic(_ id: Int) async {
        guard let client = appState.sensorClient else { return }
        do {
            try await client.request(.restartMimic(id: id))
            await loadAll()
            await appState.refreshDecoys()
            actionMessage = "Fake host restarted."
            actionMessageIsError = false
        } catch {
            actionMessage = "Could not restart fake host: \(error.localizedDescription)"
            actionMessageIsError = true
        }
    }

    private func removeMimic(_ id: Int) async {
        guard let client = appState.sensorClient else { return }
        do {
            try await client.request(.removeMimic(id: id))
            await loadAll()
            // Refresh status to update active mimic count
            if let status: ScoutStatusResponse = try? await client.request(.scoutStatus) {
                scoutStatus = status
            }
            await appState.refreshDecoys()
            actionMessage = "Fake host removed."
            actionMessageIsError = false
        } catch {
            actionMessage = "Could not remove fake host: \(error.localizedDescription)"
            actionMessageIsError = true
        }
    }

    private func pollWhileCapacitySettles() async {
        var pollState = ScoutRefreshPollState()
        while !Task.isCancelled,
              pollState.shouldPoll(
                  after: ScoutRefreshSnapshot(status: scoutStatus, mimics: mimics)
              ) {
            do {
                try await Task.sleep(for: .seconds(2))
            } catch {
                return
            }
            await loadAll()
        }
    }

    // MARK: - Helpers

    private func mimicHostTitle(_ group: MimicHostGroup) -> String {
        if let hostname = group.hostname, !hostname.isEmpty {
            return hostname
        }
        return group.services.first?.name ?? "Unnamed fake host"
    }

    private func mimicGroupStatus(_ group: MimicHostGroup) -> String {
        let statuses = Set(group.services.map(\.status))
        if statuses == ["active"] {
            return "active"
        }
        if statuses == ["stopped"] {
            return "stopped"
        }
        if statuses.contains("degraded") || statuses.count > 1 {
            return "degraded"
        }
        return statuses.first ?? "offline"
    }

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
