import Foundation

/// Static mock data for SwiftUI previews and development builds.
enum PreviewData {

    // MARK: - Devices

    /// Eight devices covering all device types with a mix of trust statuses,
    /// online/offline states, and with/without custom names.
    static let devices: [DeviceSummary] = [
        DeviceSummary(
            id: 1,
            ipAddress: "192.168.1.10",
            macAddress: "A4:83:E7:2F:1B:04",
            hostname: "matts-macbook-pro.local",
            vendor: "Apple",
            deviceType: "computer",
            modelName: nil,
            area: "Office",
            customName: "Matt's MacBook Pro",
            trustStatus: "approved",
            isOnline: true,
            firstSeen: "2026-01-15T10:23:00Z",
            lastSeen: "2026-02-23T08:45:12Z"
        ),
        DeviceSummary(
            id: 2,
            ipAddress: "192.168.1.11",
            macAddress: "F0:18:98:6A:DD:C2",
            hostname: "iPhone-15.local",
            vendor: "Apple",
            deviceType: "phone",
            modelName: nil,
            customName: nil,
            trustStatus: "approved",
            isOnline: true,
            firstSeen: "2026-01-15T10:30:00Z",
            lastSeen: "2026-02-23T09:01:33Z"
        ),
        DeviceSummary(
            id: 3,
            ipAddress: "192.168.1.42",
            macAddress: "DC:A6:32:8E:5F:A1",
            hostname: "hue-bridge.local",
            vendor: "Signify",
            deviceType: "iot",
            modelName: "Hue Bridge v2",
            area: "Living Room",
            customName: "Philips Hue Bridge",
            trustStatus: "approved",
            isOnline: true,
            firstSeen: "2026-01-15T11:05:00Z",
            lastSeen: "2026-02-23T09:00:00Z"
        ),
        DeviceSummary(
            id: 4,
            ipAddress: "192.168.1.1",
            macAddress: "38:94:ED:10:7C:B8",
            hostname: "router.local",
            vendor: "ASUS",
            deviceType: "infrastructure",
            modelName: nil,
            customName: "ASUS Router",
            trustStatus: "approved",
            isOnline: true,
            firstSeen: "2026-01-15T10:00:00Z",
            lastSeen: "2026-02-23T09:02:00Z"
        ),
        DeviceSummary(
            id: 5,
            ipAddress: "192.168.1.50",
            macAddress: "00:11:32:AB:CD:EF",
            hostname: "synology-nas.local",
            vendor: "Synology",
            deviceType: "server",
            modelName: "DS920+",
            customName: "NAS",
            trustStatus: "approved",
            isOnline: true,
            firstSeen: "2026-01-15T12:00:00Z",
            lastSeen: "2026-02-23T08:58:00Z"
        ),
        DeviceSummary(
            id: 6,
            ipAddress: "192.168.1.60",
            macAddress: "48:B0:2D:3E:9A:77",
            hostname: "roku-ultra.local",
            vendor: "Roku",
            deviceType: "media",
            modelName: "Roku Ultra",
            area: "Kitchen",
            customName: nil,
            trustStatus: "approved",
            isOnline: false,
            firstSeen: "2026-01-16T19:30:00Z",
            lastSeen: "2026-02-22T23:45:00Z"
        ),
        DeviceSummary(
            id: 7,
            ipAddress: "192.168.1.187",
            macAddress: "B2:4C:FF:01:99:A3",
            hostname: nil,
            vendor: nil,
            deviceType: "unknown",
            modelName: nil,
            customName: nil,
            trustStatus: "unknown",
            isOnline: true,
            firstSeen: "2026-02-22T03:17:42Z",
            lastSeen: "2026-02-23T08:30:00Z"
        ),
        DeviceSummary(
            id: 8,
            ipAddress: "192.168.1.203",
            macAddress: "6E:F1:22:AA:00:5D",
            hostname: nil,
            vendor: nil,
            deviceType: "unknown",
            modelName: nil,
            customName: nil,
            trustStatus: "rejected",
            isOnline: false,
            firstSeen: "2026-02-20T01:44:09Z",
            lastSeen: "2026-02-20T02:12:33Z"
        ),
    ]

    // MARK: - Alerts

    /// Five alerts covering all severity levels with a mix of read/unread
    /// and with/without incident association.
    static let alerts: [AlertSummary] = [
        AlertSummary(
            id: 1,
            incidentId: 1,
            alertType: "decoy.credential_trip",
            severity: "critical",
            title: "Credential attempt on dev_server decoy",
            sourceIp: "192.168.1.187",
            readAt: nil,
            actionedAt: nil,
            createdAt: "2026-02-23T02:14:08Z",
            alertCount: 1
        ),
        AlertSummary(
            id: 2,
            incidentId: nil,
            alertType: "device.new",
            severity: "high",
            title: "New device detected: 192.168.1.187",
            sourceIp: "192.168.1.187",
            readAt: nil,
            actionedAt: nil,
            createdAt: "2026-02-22T03:17:42Z",
            alertCount: 1
        ),
        AlertSummary(
            id: 3,
            incidentId: 1,
            alertType: "decoy.trip",
            severity: "high",
            title: "Connection to dev_server decoy from 192.168.1.187",
            sourceIp: "192.168.1.187",
            readAt: "2026-02-23T07:00:00Z",
            actionedAt: nil,
            createdAt: "2026-02-23T02:10:55Z",
            alertCount: 1
        ),
        AlertSummary(
            id: 4,
            incidentId: nil,
            alertType: "device.verification_needed",
            severity: "medium",
            title: "Device verification needed: roku-ultra.local",
            sourceIp: "192.168.1.60",
            readAt: "2026-02-21T10:00:00Z",
            actionedAt: "2026-02-21T10:05:00Z",
            createdAt: "2026-02-20T18:30:00Z",
            alertCount: 1
        ),
        AlertSummary(
            id: 5,
            incidentId: nil,
            alertType: "system.learning_complete",
            severity: "low",
            title: "Learning mode complete — baseline established",
            sourceIp: nil,
            readAt: "2026-01-17T10:01:00Z",
            actionedAt: nil,
            createdAt: "2026-01-17T10:00:00Z",
            alertCount: 1
        ),
    ]

    // MARK: - Incidents

    /// One active incident tied to the credential trip and decoy trip alerts.
    static let incidents: [IncidentDetail] = [
        IncidentDetail(
            id: 1,
            sourceIp: "192.168.1.187",
            sourceMac: "B2:4C:FF:01:99:A3",
            status: "active",
            severity: "critical",
            alertCount: 2,
            firstAlertAt: "2026-02-23T02:10:55Z",
            lastAlertAt: "2026-02-23T02:14:08Z",
            closedAt: nil,
            summary: "Unknown device accessed dev_server decoy and attempted credentials",
            alerts: [
                AlertDetail(
                    id: 3,
                    incidentId: 1,
                    alertType: "decoy.trip",
                    severity: "high",
                    title: "Connection to dev_server decoy from 192.168.1.187",
                    detail: .object([
                        "decoy_name": .string("dev_server"),
                        "port": .int(8080),
                        "protocol": .string("HTTP"),
                    ]),
                    sourceIp: "192.168.1.187",
                    sourceMac: "B2:4C:FF:01:99:A3",
                    deviceId: 7,
                    decoyId: 1,
                    readAt: "2026-02-23T07:00:00Z",
                    actionedAt: nil,
                    actionNote: nil,
                    createdAt: "2026-02-23T02:10:55Z"
                ),
                AlertDetail(
                    id: 1,
                    incidentId: 1,
                    alertType: "decoy.credential_trip",
                    severity: "critical",
                    title: "Credential attempt on dev_server decoy",
                    detail: .object([
                        "decoy_name": .string("dev_server"),
                        "port": .int(8080),
                        "protocol": .string("HTTP"),
                        "username": .string("admin"),
                        "path": .string("/api/login"),
                    ]),
                    sourceIp: "192.168.1.187",
                    sourceMac: "B2:4C:FF:01:99:A3",
                    deviceId: 7,
                    decoyId: 1,
                    readAt: nil,
                    actionedAt: nil,
                    actionNote: nil,
                    createdAt: "2026-02-23T02:14:08Z"
                ),
            ]
        ),
    ]

    // MARK: - Decoys

    /// Three decoys: dev_server (active), home_assistant (active), file_share (degraded).
    static let decoys: [DecoySummary] = [
        DecoySummary(
            id: 1,
            name: "dev_server",
            decoyType: "dev_server",
            bindAddress: "192.168.1.100",
            port: 8080,
            status: "active",
            connectionCount: 3,
            credentialTripCount: 1,
            createdAt: "2026-01-17T12:00:00Z",
            updatedAt: "2026-02-23T02:14:08Z"
        ),
        DecoySummary(
            id: 2,
            name: "home_assistant",
            decoyType: "home_assistant",
            bindAddress: "192.168.1.100",
            port: 8123,
            status: "active",
            connectionCount: 0,
            credentialTripCount: 0,
            createdAt: "2026-01-17T12:05:00Z",
            updatedAt: "2026-01-17T12:05:00Z"
        ),
        DecoySummary(
            id: 3,
            name: "file_share",
            decoyType: "file_share",
            bindAddress: "192.168.1.100",
            port: 445,
            status: "degraded",
            connectionCount: 1,
            credentialTripCount: 0,
            createdAt: "2026-01-17T12:10:00Z",
            updatedAt: "2026-02-22T15:30:00Z"
        ),
    ]

    // MARK: - System

    static let health = HealthResponse(
        version: "1.0.0",
        sensorId: "sensor-001",
        uptimeSeconds: 86400
    )

    static let status = StatusResponse(
        profile: "standard",
        learningMode: false,
        deviceCount: 8,
        decoyCount: 3,
        alertCount: 5
    )

    static let learningStatus = LearningStatusResponse(
        enabled: false,
        hoursElapsed: 48.0,
        hoursTotal: 48,
        phase: "complete"
    )

    // MARK: - Fingerprints

    /// Two fingerprint entries for the same device showing fingerprint evolution.
    static let fingerprints: [FingerprintEntry] = [
        FingerprintEntry(
            id: 1,
            macAddress: "A4:83:E7:2F:1B:04",
            mdnsHostname: "matts-macbook-pro.local",
            signalCount: 12,
            confidence: 0.72,
            firstSeen: "2026-01-15T10:23:00Z",
            lastSeen: "2026-01-20T14:00:00Z"
        ),
        FingerprintEntry(
            id: 2,
            macAddress: "A4:83:E7:2F:1B:04",
            mdnsHostname: "matts-macbook-pro.local",
            signalCount: 48,
            confidence: 0.95,
            firstSeen: "2026-01-20T14:01:00Z",
            lastSeen: "2026-02-23T08:45:12Z"
        ),
    ]

    // MARK: - Populated AppState

    /// Returns an AppState pre-populated with all mock data, suitable for previews.
    @MainActor
    static func populatedAppState() -> AppState {
        let state = AppState()
        state.connectionState = .live
        state.sensorInfo = health
        state.systemStatus = status
        state.devices = devices
        state.alerts = alerts
        state.incidents = incidents
        state.decoys = decoys
        state.pairedSensor = PairingManager.PairedSensor(
            id: 1,
            name: "Home Sensor",
            baseURL: URL(string: "https://192.168.1.100:8443")!,
            certFingerprint: "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        )
        return state
    }
}
