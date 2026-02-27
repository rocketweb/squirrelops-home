import SwiftUI

struct DeviceInventoryView: View {
    let appState: AppState
    @Environment(\.colorScheme) private var colorScheme

    @State private var searchText: String = ""
    @State private var sortOrder: SortOrder = .name
    @State private var selectedDevice: DeviceSummary?
    @State private var groupByArea = false
    @State private var viewMode: ViewMode = .byDevice

    // Port view state
    @State private var networkPorts: [NetworkPortEntry] = []
    @State private var isLoadingPorts = false
    @State private var portSortOrder: PortSortOrder = .port
    @State private var expandedPorts: Set<Int> = []

    enum ViewMode: String, CaseIterable, Identifiable {
        case byDevice = "By Device"
        case byPort = "By Port"

        var id: String { rawValue }
    }

    enum SortOrder: String, CaseIterable, Identifiable {
        case name = "Name"
        case ipAddress = "IP Address"
        case lastSeen = "Last Seen"
        case status = "Status"

        var id: String { rawValue }
    }

    enum PortSortOrder: String, CaseIterable, Identifiable {
        case port = "Port"
        case service = "Service"
        case devices = "Devices"

        var id: String { rawValue }
    }

    private var filteredDevices: [DeviceSummary] {
        let query = searchText.lowercased()
        let filtered: [DeviceSummary]

        if query.isEmpty {
            filtered = appState.devices
        } else {
            filtered = appState.devices.filter { device in
                (device.customName?.lowercased().contains(query) ?? false)
                    || (device.hostname?.lowercased().contains(query) ?? false)
                    || device.ipAddress.lowercased().contains(query)
                    || (device.macAddress?.lowercased().contains(query) ?? false)
                    || (device.vendor?.lowercased().contains(query) ?? false)
            }
        }

        return filtered.sorted { lhs, rhs in
            switch sortOrder {
            case .name:
                let lhsName = (lhs.customName ?? lhs.hostname ?? "Unknown Device").lowercased()
                let rhsName = (rhs.customName ?? rhs.hostname ?? "Unknown Device").lowercased()
                return lhsName < rhsName
            case .ipAddress:
                return lhs.ipAddress < rhs.ipAddress
            case .lastSeen:
                return lhs.lastSeen > rhs.lastSeen
            case .status:
                return statusRank(lhs.trustStatus) < statusRank(rhs.trustStatus)
            }
        }
    }

    private var devicesByArea: [(area: String, devices: [DeviceSummary])] {
        let grouped = Dictionary(grouping: filteredDevices) { $0.area ?? "Ungrouped" }
        return grouped
            .sorted { lhs, rhs in
                if lhs.key == "Ungrouped" { return false }
                if rhs.key == "Ungrouped" { return true }
                return lhs.key < rhs.key
            }
            .map { (area: $0.key, devices: $0.value) }
    }

    private var filteredPorts: [NetworkPortEntry] {
        let query = searchText.lowercased()
        let filtered: [NetworkPortEntry]

        if query.isEmpty {
            filtered = networkPorts
        } else {
            filtered = networkPorts.filter { entry in
                String(entry.port).contains(query)
                    || (entry.serviceName?.lowercased().contains(query) ?? false)
                    || entry.devices.contains { d in
                        (d.customName?.lowercased().contains(query) ?? false)
                            || (d.hostname?.lowercased().contains(query) ?? false)
                            || d.ipAddress.lowercased().contains(query)
                    }
            }
        }

        return filtered.sorted { lhs, rhs in
            switch portSortOrder {
            case .port:
                return lhs.port < rhs.port
            case .service:
                let lhsName = (lhs.serviceName ?? "zzz").lowercased()
                let rhsName = (rhs.serviceName ?? "zzz").lowercased()
                return lhsName < rhsName
            case .devices:
                return lhs.deviceCount > rhs.deviceCount
            }
        }
    }

    private func statusRank(_ status: String) -> Int {
        switch status {
        case "rejected": return 0
        case "unknown": return 1
        case "approved": return 2
        default: return 3
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Toolbar
            HStack(spacing: Spacing.md) {
                Text("Devices")
                    .font(Typography.h3)
                    .tracking(Typography.h3Tracking)
                    .foregroundStyle(Theme.textPrimary(colorScheme))

                Picker("View", selection: $viewMode) {
                    ForEach(ViewMode.allCases) { mode in
                        Text(mode.rawValue).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .frame(maxWidth: 180)

                Spacer()

                if viewMode == .byDevice {
                    Picker("Sort", selection: $sortOrder) {
                        ForEach(SortOrder.allCases) { order in
                            Text(order.rawValue).tag(order)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(maxWidth: 360)

                    Toggle(isOn: $groupByArea) {
                        Label("Areas", systemImage: "rectangle.3.group")
                    }
                    .toggleStyle(.button)
                } else {
                    Picker("Sort", selection: $portSortOrder) {
                        ForEach(PortSortOrder.allCases) { order in
                            Text(order.rawValue).tag(order)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(maxWidth: 260)
                }

                TextField(
                    viewMode == .byDevice ? "Search devices..." : "Search ports...",
                    text: $searchText
                )
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 220)
            }
            .padding(.horizontal, Spacing.lg)
            .padding(.vertical, Spacing.md)

            Divider()

            // Content
            if viewMode == .byDevice {
                deviceListContent
            } else {
                portListContent
            }
        }
        .background(Theme.background(colorScheme))
        .sheet(item: $selectedDevice) { device in
            DeviceDetailView(deviceId: device.id, appState: appState)
        }
        .onChange(of: viewMode) { _, newValue in
            if newValue == .byPort && networkPorts.isEmpty {
                fetchNetworkPorts()
            }
        }
    }

    // MARK: - Device List Content

    private var deviceListContent: some View {
        Group {
            if filteredDevices.isEmpty {
                emptyState
            } else if groupByArea {
                List(selection: $selectedDevice) {
                    ForEach(devicesByArea, id: \.area) { group in
                        Section {
                            ForEach(group.devices) { device in
                                DeviceRow(device: device)
                                    .tag(device)
                                    .listRowInsets(EdgeInsets())
                                    .listRowSeparator(.visible)
                            }
                        } header: {
                            Text(group.area)
                                .font(Typography.caption)
                                .tracking(Typography.captionTracking)
                                .foregroundStyle(Theme.textTertiary(colorScheme))
                        }
                    }
                }
                .listStyle(.plain)
            } else {
                List(filteredDevices, selection: $selectedDevice) { device in
                    DeviceRow(device: device)
                        .tag(device)
                        .listRowInsets(EdgeInsets())
                        .listRowSeparator(.visible)
                }
                .listStyle(.plain)
            }
        }
    }

    // MARK: - Port List Content

    private var portListContent: some View {
        Group {
            if isLoadingPorts {
                VStack(spacing: Spacing.md) {
                    ProgressView()
                    Text("Loading network ports...")
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if filteredPorts.isEmpty {
                VStack(spacing: Spacing.md) {
                    Image(systemName: "network.slash")
                        .font(.system(size: 40))
                        .foregroundStyle(Theme.textTertiary(colorScheme))

                    Text(searchText.isEmpty
                        ? "No open ports detected"
                        : "No ports match \"\(searchText)\"")
                        .font(Typography.body)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(filteredPorts) { entry in
                        portRow(entry)
                            .listRowInsets(EdgeInsets())
                            .listRowSeparator(.visible)
                    }
                }
                .listStyle(.plain)
            }
        }
    }

    private func portRow(_ entry: NetworkPortEntry) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            // Port header row
            Button {
                withAnimation(.easeInOut(duration: 0.2)) {
                    if expandedPorts.contains(entry.port) {
                        expandedPorts.remove(entry.port)
                    } else {
                        expandedPorts.insert(entry.port)
                    }
                }
            } label: {
                HStack(spacing: Spacing.s12) {
                    Image(systemName: expandedPorts.contains(entry.port)
                        ? "chevron.down"
                        : "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                        .frame(width: 12)

                    Text(String(entry.port))
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(Theme.textPrimary(colorScheme))
                        .frame(width: 60, alignment: .leading)

                    Text(entry.protocol_.uppercased())
                        .font(Typography.caption)
                        .tracking(Typography.captionTracking)
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                        .frame(width: 36, alignment: .leading)

                    Text(entry.serviceName ?? "Unknown")
                        .font(Typography.bodySmall)
                        .foregroundStyle(entry.serviceName != nil
                            ? Theme.textSecondary(colorScheme)
                            : Theme.textTertiary(colorScheme))
                        .frame(minWidth: 100, alignment: .leading)

                    Spacer()

                    Text("\(entry.deviceCount)")
                        .font(Typography.mono)
                        .tracking(Typography.monoTracking)
                        .foregroundStyle(Theme.textSecondary(colorScheme))

                    Text(entry.deviceCount == 1 ? "device" : "devices")
                        .font(Typography.bodySmall)
                        .foregroundStyle(Theme.textTertiary(colorScheme))
                }
                .padding(.vertical, Spacing.sm)
                .padding(.horizontal, Spacing.md)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            // Expanded device list
            if expandedPorts.contains(entry.port) {
                VStack(spacing: 0) {
                    ForEach(entry.devices) { device in
                        HStack(spacing: Spacing.s12) {
                            Image(systemName: deviceIcon(for: device.deviceType))
                                .font(.system(size: 13))
                                .foregroundStyle(Theme.textTertiary(colorScheme))
                                .frame(width: 18, alignment: .center)

                            Text(device.customName ?? device.hostname ?? "Device \(device.deviceId)")
                                .font(Typography.bodySmall)
                                .foregroundStyle(Theme.textPrimary(colorScheme))
                                .lineLimit(1)

                            Text(device.ipAddress)
                                .font(Typography.mono)
                                .tracking(Typography.monoTracking)
                                .foregroundStyle(Theme.textSecondary(colorScheme))

                            Spacer()

                            if let banner = device.banner {
                                Text(banner)
                                    .font(Typography.mono)
                                    .tracking(Typography.monoTracking)
                                    .foregroundStyle(Theme.textTertiary(colorScheme))
                                    .lineLimit(1)
                                    .truncationMode(.tail)
                                    .frame(maxWidth: 200, alignment: .trailing)
                            }
                        }
                        .padding(.vertical, Spacing.xs)
                        .padding(.horizontal, Spacing.md)
                        .padding(.leading, Spacing.xl)
                    }
                }
                .background(Theme.backgroundSecondary(colorScheme))
            }
        }
    }

    private func deviceIcon(for deviceType: String) -> String {
        switch deviceType {
        case "computer": return "desktopcomputer"
        case "phone": return "iphone"
        case "tablet": return "ipad"
        case "router": return "wifi.router"
        case "smart_home": return "homekit"
        case "media": return "tv"
        case "printer": return "printer"
        case "camera": return "video"
        default: return "questionmark.circle"
        }
    }

    private func fetchNetworkPorts() {
        guard let client = appState.sensorClient else { return }
        isLoadingPorts = true
        Task {
            do {
                let response: NetworkPortsResponse = try await client.request(.networkPorts)
                await MainActor.run {
                    networkPorts = response.items
                    isLoadingPorts = false
                }
            } catch {
                await MainActor.run {
                    networkPorts = []
                    isLoadingPorts = false
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: Spacing.md) {
            Image(systemName: "laptopcomputer.slash")
                .font(.system(size: 40))
                .foregroundStyle(Theme.textTertiary(colorScheme))

            Text(searchText.isEmpty
                ? "No devices discovered yet"
                : "No devices match \"\(searchText)\"")
                .font(Typography.body)
                .foregroundStyle(Theme.textSecondary(colorScheme))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
