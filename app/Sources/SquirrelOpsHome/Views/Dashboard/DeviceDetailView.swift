import SwiftUI

struct DeviceDetailView: View {
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.dismiss) private var dismiss
    let deviceId: Int
    let appState: AppState

    @State private var isApproving = false
    @State private var isRejecting = false
    @State private var isIgnoring = false
    @State private var isVerifying = false
    @State private var actionError: String?
    @State private var fingerprint: FingerprintEntry?
    @State private var isFingerprintLoading = true
    @State private var openPorts: [OpenPortEntry]?
    @State private var isPortsLoading = true
    @State private var isProbing = false
    @State private var isEditing = false
    @State private var editName: String = ""
    @State private var isSaving = false

    private var device: DeviceSummary {
        appState.devices.first { $0.id == deviceId }!
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            headerSection

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.lg) {
                    networkInfoSection
                    openPortsSection
                    fingerprintSection
                    actionsSection
                }
                .padding(Spacing.lg)
            }
        }
        .frame(minWidth: 420, idealWidth: 480, minHeight: 500, idealHeight: 600)
        .background(Theme.background(colorScheme))
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack(alignment: .top) {
            HStack(spacing: Spacing.s12) {
                Image(systemName: device.deviceIcon)
                    .font(.system(size: 32))
                    .foregroundStyle(Theme.textSecondary(colorScheme))

                VStack(alignment: .leading, spacing: Spacing.xs) {
                    Text(device.displayName)
                        .font(Typography.h3)
                        .tracking(Typography.h3Tracking)
                        .foregroundStyle(Theme.textPrimary(colorScheme))

                    HStack(spacing: Spacing.sm) {
                        Circle()
                            .fill(device.isOnline
                                ? Theme.statusSuccess(colorScheme)
                                : Theme.textTertiary(colorScheme))
                            .frame(width: 8, height: 8)

                        Text(device.isOnline ? "Online" : "Offline")
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textSecondary(colorScheme))
                    }

                    StatusBadge(
                        label: device.trustStatus,
                        style: device.trustBadgeStyle
                    )
                }
            }

            Spacer()

            HStack(spacing: Spacing.sm) {
                if isEditing {
                    Button("Cancel") {
                        isEditing = false
                    }
                    Button("Save") {
                        saveEdits()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.accentDefault(colorScheme))
                    .disabled(isSaving)
                } else {
                    Button("Edit") {
                        editName = device.customName ?? ""
                        isEditing = true
                    }
                    Button("Done") {
                        dismiss()
                    }
                    .keyboardShortcut(.cancelAction)
                }
            }
        }
        .padding(Spacing.lg)
    }

    // MARK: - Network Info

    private var networkInfoSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("NETWORK INFO")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            VStack(spacing: Spacing.sm) {
                infoRow(label: "IP Address", value: device.ipAddress)
                infoRow(label: "MAC Address", value: device.macAddress ?? "--")
                infoRow(label: "Hostname", value: device.hostname ?? "--")
                infoRow(label: "Vendor", value: device.vendor ?? "--")

                if let modelName = device.modelName {
                    infoRow(label: "Model", value: modelName)
                }

                if isEditing {
                    HStack {
                        Text("Name")
                            .font(Typography.bodySmall)
                            .foregroundStyle(Theme.textSecondary(colorScheme))
                            .frame(width: 100, alignment: .leading)
                        TextField("Device name", text: $editName)
                            .textFieldStyle(.roundedBorder)
                            .font(Typography.mono)
                    }
                    .padding(.vertical, Spacing.xs)
                } else {
                    if let customName = device.customName {
                        infoRow(label: "Name", value: customName)
                    }
                    infoRow(label: "Type", value: device.deviceType.capitalized)
                }

                if let area = device.area {
                    infoRow(label: "Area", value: area)
                }

                infoRow(label: "First Seen", value: device.firstSeen)
                infoRow(label: "Last Seen", value: device.lastSeen)
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

    // MARK: - Open Ports

    private var openPortsSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            HStack {
                Text("OPEN PORTS")
                    .font(Typography.caption)
                    .tracking(Typography.captionTracking)
                    .foregroundStyle(Theme.textTertiary(colorScheme))

                Spacer()

                if let openPorts, openPorts.contains(where: { $0.serviceName == nil && $0.banner == nil }) {
                    Button {
                        probeUnknownPorts()
                    } label: {
                        HStack(spacing: Spacing.xs) {
                            if isProbing {
                                ProgressView()
                                    .controlSize(.mini)
                            } else {
                                Image(systemName: "magnifyingglass")
                            }
                            Text("Scan Unknown")
                                .font(Typography.caption)
                        }
                        .foregroundStyle(Theme.accentDefault(colorScheme))
                    }
                    .buttonStyle(.plain)
                    .disabled(isProbing)
                }
            }

            if isPortsLoading {
                ProgressView()
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(Spacing.md)
            } else if let openPorts, !openPorts.isEmpty {
                VStack(spacing: 0) {
                    ForEach(openPorts) { entry in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text(String(entry.port))
                                    .font(Typography.mono)
                                    .tracking(Typography.monoTracking)
                                    .foregroundStyle(Theme.textPrimary(colorScheme))

                                Text(entry.protocol_.uppercased())
                                    .font(Typography.caption)
                                    .tracking(Typography.captionTracking)
                                    .foregroundStyle(Theme.textTertiary(colorScheme))

                                Spacer()

                                Text(entry.serviceName ?? Self.serviceName(for: entry.port))
                                    .font(Typography.bodySmall)
                                    .foregroundStyle(Theme.textSecondary(colorScheme))
                            }

                            if let banner = entry.banner {
                                Text(banner)
                                    .font(Typography.mono)
                                    .tracking(Typography.monoTracking)
                                    .foregroundStyle(Theme.textTertiary(colorScheme))
                                    .lineLimit(1)
                                    .truncationMode(.tail)
                            }
                        }
                        .padding(.vertical, Spacing.sm)
                        .padding(.horizontal, Spacing.md)
                    }
                }
                .background(Theme.backgroundSecondary(colorScheme))
                .overlay(
                    RoundedRectangle(cornerRadius: Spacing.radiusMd)
                        .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
            } else {
                Text("No open ports detected")
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
            }
        }
        .task {
            do {
                let response: DeviceOpenPortsResponse = try await appState.sensorClient!.request(.devicePorts(id: device.id))
                openPorts = response.items
            } catch {
                openPorts = []
            }
            isPortsLoading = false
        }
    }

    private func probeUnknownPorts() {
        guard let openPorts, let client = appState.sensorClient else { return }
        let unknownPorts = openPorts
            .filter { $0.serviceName == nil && $0.banner == nil }
            .map(\.port)
        guard !unknownPorts.isEmpty else { return }

        isProbing = true
        Task {
            do {
                let results: [ProbeResult] = try await client.request(
                    .probePorts(body: ProbeRequest(ipAddress: device.ipAddress, ports: unknownPorts))
                )
                // Refresh port list to pick up new service names/banners
                let response: DeviceOpenPortsResponse = try await client.request(.devicePorts(id: device.id))
                await MainActor.run {
                    self.openPorts = response.items
                    _ = results // silence unused warning
                    isProbing = false
                }
            } catch {
                await MainActor.run {
                    isProbing = false
                }
            }
        }
    }

    private static func serviceName(for port: Int) -> String {
        switch port {
        case 21: return "FTP"
        case 22: return "SSH"
        case 23: return "Telnet"
        case 25: return "SMTP"
        case 53: return "DNS"
        case 80: return "HTTP"
        case 443: return "HTTPS"
        case 445: return "SMB"
        case 554: return "RTSP"
        case 3306: return "MySQL"
        case 3389: return "RDP"
        case 5432: return "PostgreSQL"
        case 5900: return "VNC"
        case 8080, 8000, 8888: return "HTTP Alt"
        case 9090: return "HTTP Admin"
        default: return ""
        }
    }

    // MARK: - Fingerprint Status

    private var fingerprintSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("FINGERPRINT STATUS")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            if isFingerprintLoading {
                ProgressView()
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(Spacing.md)
            } else if let fp = fingerprint {
                VStack(spacing: 0) {
                    HStack {
                        VStack(alignment: .leading, spacing: Spacing.xs) {
                            if let mac = fp.macAddress {
                                Text(mac)
                                    .font(Typography.mono)
                                    .tracking(Typography.monoTracking)
                                    .foregroundStyle(Theme.textPrimary(colorScheme))
                            }
                            if let mdns = fp.mdnsHostname {
                                Text(mdns)
                                    .font(Typography.bodySmall)
                                    .foregroundStyle(Theme.textSecondary(colorScheme))
                            }
                        }

                        Spacer()

                        VStack(alignment: .trailing, spacing: Spacing.xs) {
                            if let confidence = fp.confidence {
                                Text("\(Int(confidence * 100))%")
                                    .font(Typography.mono)
                                    .tracking(Typography.monoTracking)
                                    .foregroundStyle(Theme.textSecondary(colorScheme))
                            }
                            Text("\(fp.signalCount) signals")
                                .font(Typography.bodySmall)
                                .foregroundStyle(Theme.textTertiary(colorScheme))
                        }
                    }
                    .padding(.vertical, Spacing.sm)
                    .padding(.horizontal, Spacing.md)
                }
                .background(Theme.backgroundSecondary(colorScheme))
                .overlay(
                    RoundedRectangle(cornerRadius: Spacing.radiusMd)
                        .stroke(Theme.borderSubtle(colorScheme), lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusMd))
            } else {
                Text("No fingerprint data available")
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
            }
        }
        .task {
            do {
                let response: PaginatedFingerprints = try await appState.sensorClient!.request(.deviceFingerprints(id: device.id))
                fingerprint = response.items.first
            } catch {
                fingerprint = nil
            }
            isFingerprintLoading = false
        }
    }

    // MARK: - Actions

    private var actionsSection: some View {
        VStack(alignment: .leading, spacing: Spacing.s12) {
            Text("ACTIONS")
                .font(Typography.caption)
                .tracking(Typography.captionTracking)
                .foregroundStyle(Theme.textTertiary(colorScheme))

            HStack(spacing: Spacing.s12) {
                if device.trustStatus != "approved" {
                    Button {
                        isApproving = true
                        actionError = nil
                        Task {
                            do {
                                try await appState.sensorClient?.request(.approveDevice(id: device.id))
                                updateDeviceTrust("approved")
                            } catch {
                                actionError = "Approve failed: \(error.localizedDescription)"
                            }
                            isApproving = false
                        }
                    } label: {
                        Label("Approve Device", systemImage: "checkmark.shield")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.statusSuccess(colorScheme))
                    .disabled(isApproving || isRejecting || isIgnoring || isVerifying)
                }

                if device.trustStatus != "rejected" {
                    Button {
                        isRejecting = true
                        actionError = nil
                        Task {
                            do {
                                try await appState.sensorClient?.request(.rejectDevice(id: device.id))
                                updateDeviceTrust("rejected")
                            } catch {
                                actionError = "Reject failed: \(error.localizedDescription)"
                            }
                            isRejecting = false
                        }
                    } label: {
                        Label("Reject Device", systemImage: "xmark.shield")
                    }
                    .buttonStyle(.bordered)
                    .tint(Theme.statusError(colorScheme))
                    .disabled(isApproving || isRejecting || isIgnoring || isVerifying)
                }

                if device.trustStatus != "unknown" {
                    Button {
                        isIgnoring = true
                        actionError = nil
                        Task {
                            do {
                                try await appState.sensorClient?.request(.ignoreDevice(id: device.id))
                                updateDeviceTrust("unknown")
                            } catch {
                                actionError = "Ignore failed: \(error.localizedDescription)"
                            }
                            isIgnoring = false
                        }
                    } label: {
                        Label("Reset to Unknown", systemImage: "questionmark.circle")
                    }
                    .buttonStyle(.bordered)
                    .disabled(isApproving || isRejecting || isIgnoring || isVerifying)
                }

                Button {
                    isVerifying = true
                    actionError = nil
                    Task {
                        do {
                            try await appState.sensorClient?.request(.verifyDevice(id: device.id))
                        } catch {
                            actionError = "Verify failed: \(error.localizedDescription)"
                        }
                        isVerifying = false
                    }
                } label: {
                    Label("Request Verification", systemImage: "arrow.triangle.2.circlepath")
                }
                .buttonStyle(.bordered)
                .disabled(isApproving || isRejecting || isIgnoring || isVerifying)
            }

            if let actionError {
                Text(actionError)
                    .font(Typography.bodySmall)
                    .foregroundStyle(Theme.statusError(colorScheme))
            }
        }
    }

    // MARK: - State Updates

    private func saveEdits() {
        isSaving = true
        Task {
            do {
                let body = DeviceUpdateRequest(
                    customName: editName.isEmpty ? nil : editName
                )
                try await appState.sensorClient?.request(.updateDevice(id: device.id, body: body))
                let d = device
                appState.updateDevice(DeviceSummary(
                    id: d.id, ipAddress: d.ipAddress, macAddress: d.macAddress,
                    hostname: d.hostname, vendor: d.vendor, deviceType: d.deviceType,
                    modelName: d.modelName, area: d.area,
                    customName: editName.isEmpty ? nil : editName,
                    trustStatus: d.trustStatus,
                    isOnline: d.isOnline, firstSeen: d.firstSeen, lastSeen: d.lastSeen
                ))
                isEditing = false
            } catch {
                actionError = "Save failed: \(error.localizedDescription)"
            }
            isSaving = false
        }
    }

    private func updateDeviceTrust(_ newStatus: String) {
        let d = device
        appState.updateDevice(DeviceSummary(
            id: d.id, ipAddress: d.ipAddress, macAddress: d.macAddress,
            hostname: d.hostname, vendor: d.vendor, deviceType: d.deviceType,
            modelName: d.modelName, area: d.area, customName: d.customName,
            trustStatus: newStatus,
            isOnline: d.isOnline, firstSeen: d.firstSeen, lastSeen: d.lastSeen
        ))
    }
}
