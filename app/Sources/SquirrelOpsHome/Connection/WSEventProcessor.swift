import Foundation

/// Processes incoming WebSocket event frames and applies them to AppState.
///
/// ALL event types are batched over a short window (200ms) so that a burst
/// of WebSocket events from a scan completion results in a single atomic
/// mutation to AppState.  This prevents NSTableView reentrant delegate
/// warnings caused by multiple `@Observable` property mutations across
/// separate run-loop turns.
@MainActor
public enum WSEventProcessor {

    // MARK: - Pending Batches

    private static var pendingDeviceUpdates: [DeviceSummary] = []
    private static var pendingOnlineChanges: [(id: Int, online: Bool)] = []
    private static var pendingAlerts: [AlertSummary] = []
    private static var pendingDecoys: [DecoySummary] = []
    private static var pendingSystemStatus: StatusResponse?
    private static var flushTask: Task<Void, Never>?

    /// Process a single WebSocket frame, queuing changes for batched flush.
    public static func process(_ frame: WSFrame, into state: AppState) {
        guard case .event(_, let eventType, let payload) = frame else { return }

        switch eventType {
        case "device.new", "device.updated":
            if let device = decodeDevice(from: payload) {
                pendingDeviceUpdates.append(device)
                scheduleFlush(into: state)
            }

        case "device.online":
            if let deviceId = extractInt(payload, key: "device_id") {
                pendingOnlineChanges.append((id: deviceId, online: true))
                scheduleFlush(into: state)
            }

        case "device.offline":
            if let deviceId = extractInt(payload, key: "device_id") {
                pendingOnlineChanges.append((id: deviceId, online: false))
                scheduleFlush(into: state)
            }

        case "alert.new":
            if let alert = decodeAlert(from: payload) {
                pendingAlerts.append(alert)
                scheduleFlush(into: state)
            }

        case "decoy.status_changed":
            if let decoy = decodeDecoy(from: payload) {
                pendingDecoys.append(decoy)
                scheduleFlush(into: state)
            }

        case "system.status_changed":
            if let status = decodeStatus(from: payload) {
                pendingSystemStatus = status
                scheduleFlush(into: state)
            }

        default:
            break
        }
    }

    /// Schedule a flush of all pending updates after a short delay.
    /// Multiple events within the window coalesce into a single state mutation.
    private static func scheduleFlush(into state: AppState) {
        guard flushTask == nil else { return }
        flushTask = Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(200))
            flushAll(into: state)
        }
    }

    /// Immediately flush any pending updates. Used by tests.
    public static func flushPendingUpdates(into state: AppState) {
        flushTask?.cancel()
        flushAll(into: state)
    }

    /// Apply ALL pending updates as a single synchronous batch.
    /// Because this runs in one synchronous MainActor block, SwiftUI
    /// coalesces the @Observable notifications into a single layout pass.
    private static func flushAll(into state: AppState) {
        let deviceUpdates = pendingDeviceUpdates
        let onlineChanges = pendingOnlineChanges
        let alerts = pendingAlerts
        let decoys = pendingDecoys
        let systemStatus = pendingSystemStatus

        pendingDeviceUpdates.removeAll()
        pendingOnlineChanges.removeAll()
        pendingAlerts.removeAll()
        pendingDecoys.removeAll()
        pendingSystemStatus = nil
        flushTask = nil

        let hasDeviceChanges = !deviceUpdates.isEmpty || !onlineChanges.isEmpty
        let hasAny = hasDeviceChanges || !alerts.isEmpty || !decoys.isEmpty || systemStatus != nil
        guard hasAny else { return }

        // -- Devices --
        if hasDeviceChanges {
            var devices = state.devices

            for device in deviceUpdates {
                if let index = devices.firstIndex(where: { $0.id == device.id }) {
                    devices[index] = device
                } else {
                    devices.append(device)
                }
            }

            for change in onlineChanges {
                if let index = devices.firstIndex(where: { $0.id == change.id }) {
                    let old = devices[index]
                    devices[index] = DeviceSummary(
                        id: old.id, ipAddress: old.ipAddress, macAddress: old.macAddress,
                        hostname: old.hostname, vendor: old.vendor, deviceType: old.deviceType,
                        modelName: old.modelName, area: old.area, customName: old.customName,
                        trustStatus: old.trustStatus,
                        isOnline: change.online, firstSeen: old.firstSeen, lastSeen: old.lastSeen
                    )
                }
            }

            state.devices = devices
        }

        // -- Alerts --
        if !alerts.isEmpty {
            var current = state.alerts
            for alert in alerts {
                current.insert(alert, at: 0)
            }
            state.alerts = current
        }

        // -- Decoys --
        if !decoys.isEmpty {
            var current = state.decoys
            for decoy in decoys {
                if let index = current.firstIndex(where: { $0.id == decoy.id }) {
                    current[index] = decoy
                } else {
                    current.append(decoy)
                }
            }
            state.decoys = current
        }

        // -- System Status --
        if let systemStatus {
            state.systemStatus = systemStatus
        }
    }

    // MARK: - Private Helpers

    private static let encoder = JSONEncoder()
    private static let decoder = JSONDecoder()

    private static func decodeDevice(from payload: [String: AnyCodableValue]) -> DeviceSummary? {
        guard let data = try? encoder.encode(payload) else { return nil }
        return try? decoder.decode(DeviceSummary.self, from: data)
    }

    private static func decodeAlert(from payload: [String: AnyCodableValue]) -> AlertSummary? {
        guard let data = try? encoder.encode(payload) else { return nil }
        return try? decoder.decode(AlertSummary.self, from: data)
    }

    private static func decodeDecoy(from payload: [String: AnyCodableValue]) -> DecoySummary? {
        guard let data = try? encoder.encode(payload) else { return nil }
        return try? decoder.decode(DecoySummary.self, from: data)
    }

    private static func decodeStatus(from payload: [String: AnyCodableValue]) -> StatusResponse? {
        guard let data = try? encoder.encode(payload) else { return nil }
        return try? decoder.decode(StatusResponse.self, from: data)
    }

    private static func extractInt(_ payload: [String: AnyCodableValue], key: String) -> Int? {
        if case .int(let value) = payload[key] { return value }
        return nil
    }
}
