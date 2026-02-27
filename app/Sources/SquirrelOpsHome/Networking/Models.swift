// app/Sources/SquirrelOpsHome/Networking/Models.swift
import Foundation

// MARK: - Enums

public enum TrustStatus: String, Codable, Sendable {
    case approved
    case rejected
    case unknown
}

public enum AlertSeverity: String, Codable, Sendable, Comparable {
    case critical
    case high
    case medium
    case low

    private var rank: Int {
        switch self {
        case .critical: return 3
        case .high: return 2
        case .medium: return 1
        case .low: return 0
        }
    }

    public static func < (lhs: AlertSeverity, rhs: AlertSeverity) -> Bool {
        lhs.rank < rhs.rank
    }
}

public enum AlertType: String, Codable, Sendable {
    case newDevice = "device.new"
    case verificationNeeded = "device.verification_needed"
    case macChanged = "device.mac_changed"
    case decoyTrip = "decoy.trip"
    case credentialTrip = "decoy.credential_trip"
    case sensorOffline = "system.sensor_offline"
    case learningComplete = "system.learning_complete"
    case reviewReminder = "device.review_reminder"
    case behavioralAnomaly = "behavioral.anomaly"
    case securityPortRisk = "security.port_risk"
    case securityVendorAdvisory = "security.vendor_advisory"

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)
        self = AlertType(rawValue: rawValue) ?? .newDevice
    }
}

public enum DecoyType: String, Codable, Sendable {
    case devServer = "dev_server"
    case homeAssistant = "home_assistant"
    case fileShare = "file_share"
}

public enum DecoyStatus: String, Codable, Sendable {
    case active
    case degraded
    case stopped
}

public enum IncidentStatus: String, Codable, Sendable {
    case active
    case closed
}

public enum ResourceProfile: String, Codable, Sendable {
    case lite
    case standard
    case full
}

// MARK: - AnyCodableValue

public enum AnyCodableValue: Sendable, Equatable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
    case null
    case array([AnyCodableValue])
    case object([String: AnyCodableValue])
}

extension AnyCodableValue: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()

        if container.decodeNil() {
            self = .null
            return
        }

        if let boolValue = try? container.decode(Bool.self) {
            self = .bool(boolValue)
            return
        }

        if let intValue = try? container.decode(Int.self) {
            self = .int(intValue)
            return
        }

        if let doubleValue = try? container.decode(Double.self) {
            self = .double(doubleValue)
            return
        }

        if let stringValue = try? container.decode(String.self) {
            self = .string(stringValue)
            return
        }

        if let arrayValue = try? container.decode([AnyCodableValue].self) {
            self = .array(arrayValue)
            return
        }

        if let objectValue = try? container.decode([String: AnyCodableValue].self) {
            self = .object(objectValue)
            return
        }

        throw DecodingError.typeMismatch(
            AnyCodableValue.self,
            DecodingError.Context(
                codingPath: decoder.codingPath,
                debugDescription: "Unable to decode AnyCodableValue"
            )
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value):
            try container.encode(value)
        case .int(let value):
            try container.encode(value)
        case .double(let value):
            try container.encode(value)
        case .bool(let value):
            try container.encode(value)
        case .null:
            try container.encodeNil()
        case .array(let value):
            try container.encode(value)
        case .object(let value):
            try container.encode(value)
        }
    }
}

// MARK: - Response Structs

public struct DeviceSummary: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: Int
    public let ipAddress: String
    public let macAddress: String?
    public let hostname: String?
    public let vendor: String?
    public let deviceType: String
    public let modelName: String?
    public let area: String?
    public let customName: String?
    public let trustStatus: String
    public let isOnline: Bool
    public let firstSeen: String
    public let lastSeen: String

    public init(
        id: Int,
        ipAddress: String,
        macAddress: String?,
        hostname: String?,
        vendor: String?,
        deviceType: String,
        modelName: String? = nil,
        area: String? = nil,
        customName: String?,
        trustStatus: String,
        isOnline: Bool,
        firstSeen: String,
        lastSeen: String
    ) {
        self.id = id
        self.ipAddress = ipAddress
        self.macAddress = macAddress
        self.hostname = hostname
        self.vendor = vendor
        self.deviceType = deviceType
        self.modelName = modelName
        self.area = area
        self.customName = customName
        self.trustStatus = trustStatus
        self.isOnline = isOnline
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }

    enum CodingKeys: String, CodingKey {
        case id
        case ipAddress = "ip_address"
        case macAddress = "mac_address"
        case hostname
        case vendor
        case deviceType = "device_type"
        case modelName = "model_name"
        case area
        case customName = "custom_name"
        case trustStatus = "trust_status"
        case isOnline = "is_online"
        case firstSeen = "first_seen"
        case lastSeen = "last_seen"
    }
}

public struct PaginatedDevices: Codable, Sendable {
    public let items: [DeviceSummary]
    public let total: Int
    public let limit: Int
    public let offset: Int

    public init(items: [DeviceSummary], total: Int, limit: Int, offset: Int) {
        self.items = items
        self.total = total
        self.limit = limit
        self.offset = offset
    }
}

public struct FingerprintEntry: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: Int
    public let macAddress: String?
    public let mdnsHostname: String?
    public let signalCount: Int
    public let confidence: Double?
    public let firstSeen: String
    public let lastSeen: String

    public init(
        id: Int,
        macAddress: String?,
        mdnsHostname: String?,
        signalCount: Int,
        confidence: Double?,
        firstSeen: String,
        lastSeen: String
    ) {
        self.id = id
        self.macAddress = macAddress
        self.mdnsHostname = mdnsHostname
        self.signalCount = signalCount
        self.confidence = confidence
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }

    enum CodingKeys: String, CodingKey {
        case id
        case macAddress = "mac_address"
        case mdnsHostname = "mdns_hostname"
        case signalCount = "signal_count"
        case confidence
        case firstSeen = "first_seen"
        case lastSeen = "last_seen"
    }
}

public struct DeviceDetail: Codable, Sendable {
    public let id: Int
    public let ipAddress: String
    public let macAddress: String?
    public let hostname: String?
    public let vendor: String?
    public let deviceType: String
    public let modelName: String?
    public let area: String?
    public let customName: String?
    public let notes: String?
    public let trustStatus: String
    public let trustUpdatedAt: String?
    public let isOnline: Bool
    public let firstSeen: String
    public let lastSeen: String
    public let latestFingerprint: FingerprintEntry?

    public init(
        id: Int,
        ipAddress: String,
        macAddress: String?,
        hostname: String?,
        vendor: String?,
        deviceType: String,
        modelName: String? = nil,
        area: String? = nil,
        customName: String?,
        notes: String?,
        trustStatus: String,
        trustUpdatedAt: String?,
        isOnline: Bool,
        firstSeen: String,
        lastSeen: String,
        latestFingerprint: FingerprintEntry?
    ) {
        self.id = id
        self.ipAddress = ipAddress
        self.macAddress = macAddress
        self.hostname = hostname
        self.vendor = vendor
        self.deviceType = deviceType
        self.modelName = modelName
        self.area = area
        self.customName = customName
        self.notes = notes
        self.trustStatus = trustStatus
        self.trustUpdatedAt = trustUpdatedAt
        self.isOnline = isOnline
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.latestFingerprint = latestFingerprint
    }

    enum CodingKeys: String, CodingKey {
        case id
        case ipAddress = "ip_address"
        case macAddress = "mac_address"
        case hostname
        case vendor
        case deviceType = "device_type"
        case modelName = "model_name"
        case area
        case customName = "custom_name"
        case notes
        case trustStatus = "trust_status"
        case trustUpdatedAt = "trust_updated_at"
        case isOnline = "is_online"
        case firstSeen = "first_seen"
        case lastSeen = "last_seen"
        case latestFingerprint = "latest_fingerprint"
    }
}

public struct HAStatusResponse: Codable, Sendable {
    public let connected: Bool
    public let deviceCount: Int

    enum CodingKeys: String, CodingKey {
        case connected
        case deviceCount = "device_count"
    }
}

public struct AlertSummary: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: Int
    public let incidentId: Int?
    public let alertType: String
    public let severity: String
    public let title: String
    public let sourceIp: String?
    public let readAt: String?
    public let actionedAt: String?
    public let createdAt: String
    public let alertCount: Int?

    public init(
        id: Int,
        incidentId: Int? = nil,
        alertType: String,
        severity: String,
        title: String,
        sourceIp: String? = nil,
        readAt: String? = nil,
        actionedAt: String? = nil,
        createdAt: String,
        alertCount: Int? = nil
    ) {
        self.id = id
        self.incidentId = incidentId
        self.alertType = alertType
        self.severity = severity
        self.title = title
        self.sourceIp = sourceIp
        self.readAt = readAt
        self.actionedAt = actionedAt
        self.createdAt = createdAt
        self.alertCount = alertCount
    }

    enum CodingKeys: String, CodingKey {
        case id
        case incidentId = "incident_id"
        case alertType = "alert_type"
        case severity
        case title
        case sourceIp = "source_ip"
        case readAt = "read_at"
        case actionedAt = "actioned_at"
        case createdAt = "created_at"
        case alertCount = "alert_count"
    }
}

public struct PaginatedAlerts: Codable, Sendable {
    public let items: [AlertSummary]
    public let total: Int
    public let limit: Int
    public let offset: Int

    public init(items: [AlertSummary], total: Int, limit: Int, offset: Int) {
        self.items = items
        self.total = total
        self.limit = limit
        self.offset = offset
    }
}

public struct OpenPortEntry: Codable, Sendable, Identifiable, Equatable, Hashable {
    public var id: String { "\(port)-\(protocol_)" }
    public let port: Int
    public let protocol_: String
    public let serviceName: String?
    public let banner: String?
    public let firstSeen: String
    public let lastSeen: String

    public init(
        port: Int,
        protocol_: String,
        serviceName: String? = nil,
        banner: String? = nil,
        firstSeen: String,
        lastSeen: String
    ) {
        self.port = port
        self.protocol_ = protocol_
        self.serviceName = serviceName
        self.banner = banner
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }

    enum CodingKeys: String, CodingKey {
        case port
        case protocol_ = "protocol"
        case serviceName = "service_name"
        case banner
        case firstSeen = "first_seen"
        case lastSeen = "last_seen"
    }
}

public struct DeviceOpenPortsResponse: Codable, Sendable {
    public let items: [OpenPortEntry]

    public init(items: [OpenPortEntry]) {
        self.items = items
    }
}

public struct NetworkPortDevice: Codable, Sendable, Identifiable, Equatable, Hashable {
    public var id: Int { deviceId }
    public let deviceId: Int
    public let ipAddress: String
    public let hostname: String?
    public let customName: String?
    public let deviceType: String
    public let banner: String?

    enum CodingKeys: String, CodingKey {
        case deviceId = "device_id"
        case ipAddress = "ip_address"
        case hostname
        case customName = "custom_name"
        case deviceType = "device_type"
        case banner
    }
}

public struct NetworkPortEntry: Codable, Sendable, Identifiable, Equatable, Hashable {
    public var id: Int { port }
    public let port: Int
    public let protocol_: String
    public let serviceName: String?
    public let deviceCount: Int
    public let devices: [NetworkPortDevice]

    enum CodingKeys: String, CodingKey {
        case port
        case protocol_ = "protocol"
        case serviceName = "service_name"
        case deviceCount = "device_count"
        case devices
    }
}

public struct NetworkPortsResponse: Codable, Sendable {
    public let items: [NetworkPortEntry]
    public let totalPorts: Int
    public let totalDevices: Int

    enum CodingKeys: String, CodingKey {
        case items
        case totalPorts = "total_ports"
        case totalDevices = "total_devices"
    }
}

public struct ProbeRequest: Encodable, Sendable {
    public let ipAddress: String
    public let ports: [Int]

    public init(ipAddress: String, ports: [Int]) {
        self.ipAddress = ipAddress
        self.ports = ports
    }

    enum CodingKeys: String, CodingKey {
        case ipAddress = "ip_address"
        case ports
    }
}

public struct ProbeResult: Codable, Sendable, Identifiable, Equatable, Hashable {
    public var id: Int { port }
    public let ip: String
    public let port: Int
    public let serviceName: String?
    public let banner: String?

    enum CodingKeys: String, CodingKey {
        case ip
        case port
        case serviceName = "service_name"
        case banner
    }
}

public struct PaginatedFingerprints: Codable, Sendable {
    public let items: [FingerprintEntry]

    public init(items: [FingerprintEntry]) {
        self.items = items
    }
}

public protocol PaginatedResponse {
    associatedtype Item
    var pageItems: [Item] { get }
    var pageTotal: Int { get }
}

extension PaginatedDevices: PaginatedResponse {
    public var pageItems: [DeviceSummary] { items }
    public var pageTotal: Int { total }
}

extension PaginatedAlerts: PaginatedResponse {
    public var pageItems: [AlertSummary] { items }
    public var pageTotal: Int { total }
}

public struct AlertDetail: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: Int
    public let incidentId: Int?
    public let alertType: String
    public let severity: String
    public let title: String
    public let detail: AnyCodableValue
    public let sourceIp: String?
    public let sourceMac: String?
    public let deviceId: Int?
    public let decoyId: Int?
    public let readAt: String?
    public let actionedAt: String?
    public let actionNote: String?
    public let createdAt: String

    public init(
        id: Int,
        incidentId: Int?,
        alertType: String,
        severity: String,
        title: String,
        detail: AnyCodableValue,
        sourceIp: String?,
        sourceMac: String?,
        deviceId: Int?,
        decoyId: Int?,
        readAt: String?,
        actionedAt: String?,
        actionNote: String?,
        createdAt: String
    ) {
        self.id = id
        self.incidentId = incidentId
        self.alertType = alertType
        self.severity = severity
        self.title = title
        self.detail = detail
        self.sourceIp = sourceIp
        self.sourceMac = sourceMac
        self.deviceId = deviceId
        self.decoyId = decoyId
        self.readAt = readAt
        self.actionedAt = actionedAt
        self.actionNote = actionNote
        self.createdAt = createdAt
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }

    enum CodingKeys: String, CodingKey {
        case id
        case incidentId = "incident_id"
        case alertType = "alert_type"
        case severity
        case title
        case detail
        case sourceIp = "source_ip"
        case sourceMac = "source_mac"
        case deviceId = "device_id"
        case decoyId = "decoy_id"
        case readAt = "read_at"
        case actionedAt = "actioned_at"
        case actionNote = "action_note"
        case createdAt = "created_at"
    }
}

public struct IncidentDetail: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: Int
    public let sourceIp: String
    public let sourceMac: String?
    public let status: String
    public let severity: String
    public let alertCount: Int
    public let firstAlertAt: String
    public let lastAlertAt: String
    public let closedAt: String?
    public let summary: String?
    public let alerts: [AlertDetail]

    public init(
        id: Int,
        sourceIp: String,
        sourceMac: String?,
        status: String,
        severity: String,
        alertCount: Int,
        firstAlertAt: String,
        lastAlertAt: String,
        closedAt: String?,
        summary: String?,
        alerts: [AlertDetail]
    ) {
        self.id = id
        self.sourceIp = sourceIp
        self.sourceMac = sourceMac
        self.status = status
        self.severity = severity
        self.alertCount = alertCount
        self.firstAlertAt = firstAlertAt
        self.lastAlertAt = lastAlertAt
        self.closedAt = closedAt
        self.summary = summary
        self.alerts = alerts
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }

    enum CodingKeys: String, CodingKey {
        case id
        case sourceIp = "source_ip"
        case sourceMac = "source_mac"
        case status
        case severity
        case alertCount = "alert_count"
        case firstAlertAt = "first_alert_at"
        case lastAlertAt = "last_alert_at"
        case closedAt = "closed_at"
        case summary
        case alerts
    }
}

public struct ExportResponse: Codable, Sendable {
    public let alerts: [AlertDetail]
    public let incidents: [IncidentDetail]
    public let exportedAt: String

    enum CodingKeys: String, CodingKey {
        case alerts
        case incidents
        case exportedAt = "exported_at"
    }
}

public struct DecoySummary: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: Int
    public let name: String
    public let decoyType: String
    public let bindAddress: String
    public let port: Int
    public let status: String
    public let connectionCount: Int
    public let credentialTripCount: Int
    public let createdAt: String
    public let updatedAt: String

    public init(
        id: Int,
        name: String,
        decoyType: String,
        bindAddress: String,
        port: Int,
        status: String,
        connectionCount: Int,
        credentialTripCount: Int,
        createdAt: String,
        updatedAt: String
    ) {
        self.id = id
        self.name = name
        self.decoyType = decoyType
        self.bindAddress = bindAddress
        self.port = port
        self.status = status
        self.connectionCount = connectionCount
        self.credentialTripCount = credentialTripCount
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case decoyType = "decoy_type"
        case bindAddress = "bind_address"
        case port
        case status
        case connectionCount = "connection_count"
        case credentialTripCount = "credential_trip_count"
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }
}

public struct DecoyListResponse: Codable, Sendable {
    public let items: [DecoySummary]

    public init(items: [DecoySummary]) {
        self.items = items
    }
}

public struct DecoyDetail: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: Int
    public let name: String
    public let decoyType: String
    public let bindAddress: String
    public let port: Int
    public let status: String
    public let config: AnyCodableValue
    public let connectionCount: Int
    public let credentialTripCount: Int
    public let failureCount: Int
    public let lastFailureAt: String?
    public let createdAt: String
    public let updatedAt: String

    public init(
        id: Int,
        name: String,
        decoyType: String,
        bindAddress: String,
        port: Int,
        status: String,
        config: AnyCodableValue,
        connectionCount: Int,
        credentialTripCount: Int,
        failureCount: Int,
        lastFailureAt: String?,
        createdAt: String,
        updatedAt: String
    ) {
        self.id = id
        self.name = name
        self.decoyType = decoyType
        self.bindAddress = bindAddress
        self.port = port
        self.status = status
        self.config = config
        self.connectionCount = connectionCount
        self.credentialTripCount = credentialTripCount
        self.failureCount = failureCount
        self.lastFailureAt = lastFailureAt
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case decoyType = "decoy_type"
        case bindAddress = "bind_address"
        case port
        case status
        case config
        case connectionCount = "connection_count"
        case credentialTripCount = "credential_trip_count"
        case failureCount = "failure_count"
        case lastFailureAt = "last_failure_at"
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }
}

public struct DecoyConnectionEntry: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: Int
    public let decoyId: Int
    public let sourceIp: String
    public let sourceMac: String?
    public let port: Int
    public let `protocol`: String?
    public let requestPath: String?
    public let credentialUsed: String?
    public let timestamp: String

    public init(
        id: Int,
        decoyId: Int,
        sourceIp: String,
        sourceMac: String?,
        port: Int,
        protocol: String?,
        requestPath: String?,
        credentialUsed: String?,
        timestamp: String
    ) {
        self.id = id
        self.decoyId = decoyId
        self.sourceIp = sourceIp
        self.sourceMac = sourceMac
        self.port = port
        self.protocol = `protocol`
        self.requestPath = requestPath
        self.credentialUsed = credentialUsed
        self.timestamp = timestamp
    }

    enum CodingKeys: String, CodingKey {
        case id
        case decoyId = "decoy_id"
        case sourceIp = "source_ip"
        case sourceMac = "source_mac"
        case port
        case `protocol`
        case requestPath = "request_path"
        case credentialUsed = "credential_used"
        case timestamp
    }
}

public struct PaginatedDecoyConnections: Codable, Sendable {
    public let items: [DecoyConnectionEntry]
    public let total: Int
    public let limit: Int
    public let offset: Int

    public init(items: [DecoyConnectionEntry], total: Int, limit: Int, offset: Int) {
        self.items = items
        self.total = total
        self.limit = limit
        self.offset = offset
    }
}

public struct DecoyCredentialEntry: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: Int
    public let credentialType: String
    public let plantedLocation: String
    public let tripped: Bool
    public let firstTrippedAt: String?
    public let createdAt: String

    public init(
        id: Int,
        credentialType: String,
        plantedLocation: String,
        tripped: Bool,
        firstTrippedAt: String?,
        createdAt: String
    ) {
        self.id = id
        self.credentialType = credentialType
        self.plantedLocation = plantedLocation
        self.tripped = tripped
        self.firstTrippedAt = firstTrippedAt
        self.createdAt = createdAt
    }

    enum CodingKeys: String, CodingKey {
        case id
        case credentialType = "credential_type"
        case plantedLocation = "planted_location"
        case tripped
        case firstTrippedAt = "first_tripped_at"
        case createdAt = "created_at"
    }
}

public struct HealthResponse: Codable, Sendable {
    public let version: String
    public let sensorId: String
    public let uptimeSeconds: Double

    public init(version: String, sensorId: String, uptimeSeconds: Double) {
        self.version = version
        self.sensorId = sensorId
        self.uptimeSeconds = uptimeSeconds
    }

    enum CodingKeys: String, CodingKey {
        case version
        case sensorId = "sensor_id"
        case uptimeSeconds = "uptime_seconds"
    }
}

public struct StatusResponse: Codable, Sendable {
    public let profile: String
    public let learningMode: Bool
    public let deviceCount: Int
    public let decoyCount: Int
    public let alertCount: Int

    public init(profile: String, learningMode: Bool, deviceCount: Int, decoyCount: Int, alertCount: Int) {
        self.profile = profile
        self.learningMode = learningMode
        self.deviceCount = deviceCount
        self.decoyCount = decoyCount
        self.alertCount = alertCount
    }

    enum CodingKeys: String, CodingKey {
        case profile
        case learningMode = "learning_mode"
        case deviceCount = "device_count"
        case decoyCount = "decoy_count"
        case alertCount = "alert_count"
    }
}

public struct LearningStatusResponse: Codable, Sendable {
    public let enabled: Bool
    public let hoursElapsed: Double
    public let hoursTotal: Int
    public let phase: String

    public init(enabled: Bool, hoursElapsed: Double, hoursTotal: Int, phase: String) {
        self.enabled = enabled
        self.hoursElapsed = hoursElapsed
        self.hoursTotal = hoursTotal
        self.phase = phase
    }

    enum CodingKeys: String, CodingKey {
        case enabled
        case hoursElapsed = "hours_elapsed"
        case hoursTotal = "hours_total"
        case phase
    }
}

public struct ConfigResponse: Codable, Sendable {
    public let profile: String
    public let alertMethods: [String: Bool]
    public let llmEndpoint: String?
    public let llmApiKey: String?

    public init(profile: String, alertMethods: [String: Bool], llmEndpoint: String?, llmApiKey: String?) {
        self.profile = profile
        self.alertMethods = alertMethods
        self.llmEndpoint = llmEndpoint
        self.llmApiKey = llmApiKey
    }

    enum CodingKeys: String, CodingKey {
        case profile
        case alertMethods = "alert_methods"
        case llmEndpoint = "llm_endpoint"
        case llmApiKey = "llm_api_key"
    }
}

public struct ChallengeResponse: Codable, Sendable {
    public let challenge: String
    public let sensorId: String
    public let sensorName: String

    public init(challenge: String, sensorId: String, sensorName: String) {
        self.challenge = challenge
        self.sensorId = sensorId
        self.sensorName = sensorName
    }

    enum CodingKeys: String, CodingKey {
        case challenge
        case sensorId = "sensor_id"
        case sensorName = "sensor_name"
    }
}

public struct VerifyRequest: Encodable, Sendable {
    public let response: String
    public let clientNonce: String
    public let clientName: String

    public init(response: String, clientNonce: String, clientName: String) {
        self.response = response
        self.clientNonce = clientNonce
        self.clientName = clientName
    }

    enum CodingKeys: String, CodingKey {
        case response
        case clientNonce = "client_nonce"
        case clientName = "client_name"
    }
}

public struct VerifyResponse: Codable, Sendable {
    public let encryptedCaCert: String
    public let serverNonce: String

    public init(encryptedCaCert: String, serverNonce: String) {
        self.encryptedCaCert = encryptedCaCert
        self.serverNonce = serverNonce
    }

    enum CodingKeys: String, CodingKey {
        case encryptedCaCert = "encrypted_ca_cert"
        case serverNonce = "server_nonce"
    }
}

public struct CompleteRequest: Encodable, Sendable {
    public let encryptedCsr: String

    public init(encryptedCsr: String) {
        self.encryptedCsr = encryptedCsr
    }

    enum CodingKeys: String, CodingKey {
        case encryptedCsr = "encrypted_csr"
    }
}

public struct CompleteResponse: Codable, Sendable {
    public let encryptedClientCert: String

    public init(encryptedClientCert: String) {
        self.encryptedClientCert = encryptedClientCert
    }

    enum CodingKeys: String, CodingKey {
        case encryptedClientCert = "encrypted_client_cert"
    }
}

public struct UpdateCheckResponse: Codable, Sendable {
    public let currentVersion: String
    public let latestVersion: String?
    public let updateAvailable: Bool
    public let message: String

    enum CodingKeys: String, CodingKey {
        case currentVersion = "current_version"
        case latestVersion = "latest_version"
        case updateAvailable = "update_available"
        case message
    }
}

// MARK: - Squirrel Scouts

public struct ScoutStatusResponse: Codable, Sendable {
    public let enabled: Bool
    public let isRunning: Bool
    public let lastScoutAt: String?
    public let lastScoutDurationMs: Int?
    public let totalProfiles: Int
    public let intervalMinutes: Int
    public let activeMimics: Int
    public let maxMimics: Int

    enum CodingKeys: String, CodingKey {
        case enabled
        case isRunning = "is_running"
        case lastScoutAt = "last_scout_at"
        case lastScoutDurationMs = "last_scout_duration_ms"
        case totalProfiles = "total_profiles"
        case intervalMinutes = "interval_minutes"
        case activeMimics = "active_mimics"
        case maxMimics = "max_mimics"
    }
}

public struct ServiceProfileSummary: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: Int
    public let deviceId: Int
    public let ipAddress: String
    public let port: Int
    public let protocol_: String
    public let serviceName: String?
    public let httpStatus: Int?
    public let httpServerHeader: String?
    public let tlsCn: String?
    public let protocolVersion: String?
    public let scoutedAt: String

    enum CodingKeys: String, CodingKey {
        case id
        case deviceId = "device_id"
        case ipAddress = "ip_address"
        case port
        case protocol_ = "protocol"
        case serviceName = "service_name"
        case httpStatus = "http_status"
        case httpServerHeader = "http_server_header"
        case tlsCn = "tls_cn"
        case protocolVersion = "protocol_version"
        case scoutedAt = "scouted_at"
    }
}

public struct MimicDecoySummary: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: Int
    public let name: String
    public let bindAddress: String
    public let port: Int
    public let status: String
    public let sourceDeviceId: Int?
    public let deviceCategory: String?
    public let connectionCount: Int
    public let createdAt: String
    public let mdnsHostname: String?

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case bindAddress = "bind_address"
        case port
        case status
        case sourceDeviceId = "source_device_id"
        case deviceCategory = "device_category"
        case connectionCount = "connection_count"
        case createdAt = "created_at"
        case mdnsHostname = "mdns_hostname"
    }
}

public struct ScoutRunResponse: Codable, Sendable {
    public let profilesCreated: Int

    enum CodingKeys: String, CodingKey {
        case profilesCreated = "profiles_created"
    }
}

public struct MimicDeployResponse: Codable, Sendable {
    public let deployed: Int
}
