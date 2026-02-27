// app/Sources/SquirrelOpsHome/Networking/Endpoint.swift
import Foundation

// MARK: - Request body types

public struct DeviceUpdateRequest: Encodable, Sendable {
    public let customName: String?
    public let notes: String?
    public let deviceType: String?

    public init(customName: String? = nil, notes: String? = nil, deviceType: String? = nil) {
        self.customName = customName
        self.notes = notes
        self.deviceType = deviceType
    }

    enum CodingKeys: String, CodingKey {
        case customName = "custom_name"
        case notes
        case deviceType = "device_type"
    }
}

// MARK: - Endpoint

public enum Endpoint: Sendable {
    // System
    case health
    case status
    case profile
    case learning
    case checkUpdates
    case updateProfile(profile: String)

    // Devices
    case devices(limit: Int = 50, offset: Int = 0)
    case device(id: Int)
    case updateDevice(id: Int, body: DeviceUpdateRequest)
    case approveDevice(id: Int)
    case rejectDevice(id: Int)
    case ignoreDevice(id: Int)
    case verifyDevice(id: Int)
    case deviceFingerprints(id: Int)
    case devicePorts(id: Int)

    // Ports (network-wide)
    case networkPorts
    case probePorts(body: ProbeRequest)

    // Alerts
    case alerts(limit: Int = 50, offset: Int = 0, severity: String? = nil)
    case alert(id: Int)
    case readAlert(id: Int)
    case actionAlert(id: Int, note: String?)
    case incident(id: Int)
    case readIncident(id: Int)
    case exportAlerts(dateFrom: String? = nil, dateTo: String? = nil)

    // Decoys
    case decoys
    case decoy(id: Int)
    case restartDecoy(id: Int)
    case updateDecoyConfig(id: Int, config: [String: AnyCodableValue])
    case decoyCredentials(id: Int)
    case decoyConnections(id: Int, limit: Int = 50, offset: Int = 0)
    case enableDecoy(id: Int)
    case disableDecoy(id: Int)

    // Config
    case config
    case updateConfig(body: [String: AnyCodableValue])
    case alertMethods
    case updateAlertMethods(body: [String: AnyCodableValue])
    case haStatus

    // Pairing
    case pairingChallenge
    case pairingVerify(body: VerifyRequest)
    case pairingComplete(body: CompleteRequest)
    case unpair(id: Int)

    // Scouts
    case scoutStatus
    case runScout
    case scoutProfiles
    case scoutProfile(id: Int)
    case mimicDecoys
    case deployMimics
    case restartMimic(id: Int)
    case removeMimic(id: Int)

    // MARK: - Computed Properties

    public var path: String {
        switch self {
        case .health:
            return "/system/health"
        case .status:
            return "/system/status"
        case .profile, .updateProfile:
            return "/system/profile"
        case .learning:
            return "/system/learning"
        case .checkUpdates:
            return "/system/updates"
        case .devices:
            return "/devices"
        case .device(let id):
            return "/devices/\(id)"
        case .updateDevice(let id, _):
            return "/devices/\(id)"
        case .approveDevice(let id):
            return "/devices/\(id)/approve"
        case .rejectDevice(let id):
            return "/devices/\(id)/reject"
        case .ignoreDevice(let id):
            return "/devices/\(id)/ignore"
        case .verifyDevice(let id):
            return "/devices/\(id)/verify"
        case .deviceFingerprints(let id):
            return "/devices/\(id)/fingerprints"
        case .devicePorts(let id):
            return "/devices/\(id)/ports"
        case .networkPorts:
            return "/ports/network"
        case .probePorts:
            return "/ports/probe"
        case .alerts:
            return "/alerts"
        case .alert(let id):
            return "/alerts/\(id)"
        case .readAlert(let id):
            return "/alerts/\(id)/read"
        case .actionAlert(let id, _):
            return "/alerts/\(id)/action"
        case .incident(let id):
            return "/incidents/\(id)"
        case .readIncident(let id):
            return "/incidents/\(id)/read"
        case .exportAlerts:
            return "/alerts/export"
        case .decoys:
            return "/decoys"
        case .decoy(let id):
            return "/decoys/\(id)"
        case .restartDecoy(let id):
            return "/decoys/\(id)/restart"
        case .updateDecoyConfig(let id, _):
            return "/decoys/\(id)/config"
        case .decoyCredentials(let id):
            return "/decoys/\(id)/credentials"
        case .decoyConnections(let id, _, _):
            return "/decoys/\(id)/connections"
        case .enableDecoy(let id):
            return "/decoys/\(id)/enable"
        case .disableDecoy(let id):
            return "/decoys/\(id)/disable"
        case .config, .updateConfig:
            return "/config"
        case .alertMethods, .updateAlertMethods:
            return "/config/alert-methods"
        case .haStatus:
            return "/config/ha-status"
        case .pairingChallenge:
            return "/pairing/code/challenge"
        case .pairingVerify:
            return "/pairing/verify"
        case .pairingComplete:
            return "/pairing/complete"
        case .unpair(let id):
            return "/pairing/\(id)"
        case .scoutStatus:
            return "/scouts/status"
        case .runScout:
            return "/scouts/run"
        case .scoutProfiles:
            return "/scouts/profiles"
        case .scoutProfile(let id):
            return "/scouts/profiles/\(id)"
        case .mimicDecoys:
            return "/scouts/mimics"
        case .deployMimics:
            return "/scouts/mimics/deploy"
        case .restartMimic(let id):
            return "/scouts/mimics/\(id)/restart"
        case .removeMimic(let id):
            return "/scouts/mimics/\(id)"
        }
    }

    public var method: String {
        switch self {
        case .health, .status, .profile, .learning, .checkUpdates,
             .devices, .device, .deviceFingerprints, .devicePorts,
             .alerts, .alert, .incident,
             .exportAlerts,
             .decoys, .decoy, .decoyCredentials, .decoyConnections,
             .config, .alertMethods, .haStatus,
             .networkPorts,
             .pairingChallenge,
             .scoutStatus, .scoutProfiles, .scoutProfile, .mimicDecoys:
            return "GET"
        case .approveDevice, .rejectDevice, .ignoreDevice, .verifyDevice,
             .restartDecoy, .enableDecoy, .disableDecoy,
             .probePorts,
             .pairingVerify, .pairingComplete,
             .runScout, .deployMimics, .restartMimic:
            return "POST"
        case .updateProfile, .updateDevice, .readAlert, .actionAlert,
             .readIncident,
             .updateDecoyConfig,
             .updateConfig, .updateAlertMethods:
            return "PUT"
        case .unpair, .removeMimic:
            return "DELETE"
        }
    }

    public var body: Data? {
        let encoder = JSONEncoder()
        switch self {
        case .updateProfile(let profile):
            return try? encoder.encode(["profile": profile])
        case .updateDevice(_, let body):
            return try? encoder.encode(body)
        case .actionAlert(_, let note):
            return try? encoder.encode(["note": note])
        case .updateDecoyConfig(_, let config):
            return try? encoder.encode(config)
        case .updateConfig(let body):
            return try? encoder.encode(body)
        case .updateAlertMethods(let body):
            return try? encoder.encode(body)
        case .pairingVerify(let body):
            return try? encoder.encode(body)
        case .pairingComplete(let body):
            return try? encoder.encode(body)
        case .probePorts(let body):
            return try? encoder.encode(body)
        default:
            return nil
        }
    }

    public var queryItems: [URLQueryItem]? {
        switch self {
        case .devices(let limit, let offset):
            return [
                URLQueryItem(name: "limit", value: String(limit)),
                URLQueryItem(name: "offset", value: String(offset)),
            ]
        case .alerts(let limit, let offset, let severity):
            var items = [
                URLQueryItem(name: "limit", value: String(limit)),
                URLQueryItem(name: "offset", value: String(offset)),
            ]
            if let severity {
                items.append(URLQueryItem(name: "severity", value: severity))
            }
            return items
        case .decoyConnections(_, let limit, let offset):
            return [
                URLQueryItem(name: "limit", value: String(limit)),
                URLQueryItem(name: "offset", value: String(offset)),
            ]
        case .exportAlerts(let dateFrom, let dateTo):
            var items: [URLQueryItem] = []
            if let dateFrom {
                items.append(URLQueryItem(name: "date_from", value: dateFrom))
            }
            if let dateTo {
                items.append(URLQueryItem(name: "date_to", value: dateTo))
            }
            return items.isEmpty ? nil : items
        default:
            return nil
        }
    }

    public func urlRequest(baseURL: URL) -> URLRequest {
        var components = URLComponents(url: baseURL.appendingPathComponent(path), resolvingAgainstBaseURL: false)!
        components.queryItems = queryItems

        var request = URLRequest(url: components.url!)
        request.httpMethod = method
        request.httpBody = body

        if body != nil {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }

        return request
    }
}
