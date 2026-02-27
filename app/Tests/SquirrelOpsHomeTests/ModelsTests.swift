// app/Tests/SquirrelOpsHomeTests/ModelsTests.swift
import Foundation
import Testing

@testable import SquirrelOpsHome

@Suite("Codable Models")
struct ModelsTests {

    // MARK: - DeviceSummary decoding

    @Test("Decode DeviceSummary from snake_case JSON")
    func decodeDeviceSummary() throws {
        let json = """
        {
            "id": 42,
            "ip_address": "192.168.1.101",
            "mac_address": "AA:BB:CC:DD:EE:01",
            "hostname": "living-room-hub",
            "vendor": "Apple Inc.",
            "device_type": "smart_speaker",
            "custom_name": "Living Room Hub",
            "trust_status": "approved",
            "is_online": true,
            "first_seen": "2026-02-20T00:00:00Z",
            "last_seen": "2026-02-22T12:30:00Z"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let device = try decoder.decode(DeviceSummary.self, from: json)

        #expect(device.id == 42)
        #expect(device.ipAddress == "192.168.1.101")
        #expect(device.macAddress == "AA:BB:CC:DD:EE:01")
        #expect(device.hostname == "living-room-hub")
        #expect(device.vendor == "Apple Inc.")
        #expect(device.deviceType == "smart_speaker")
        #expect(device.customName == "Living Room Hub")
        #expect(device.trustStatus == "approved")
        #expect(device.isOnline == true)
        #expect(device.firstSeen == "2026-02-20T00:00:00Z")
        #expect(device.lastSeen == "2026-02-22T12:30:00Z")
    }

    @Test("Decode DeviceSummary with null optional fields")
    func decodeDeviceSummaryNullOptionals() throws {
        let json = """
        {
            "id": 1,
            "ip_address": "10.0.0.5",
            "mac_address": null,
            "hostname": null,
            "vendor": null,
            "device_type": "unknown",
            "custom_name": null,
            "trust_status": "unknown",
            "is_online": false,
            "first_seen": "2026-02-22T00:00:00Z",
            "last_seen": "2026-02-22T00:00:00Z"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let device = try decoder.decode(DeviceSummary.self, from: json)

        #expect(device.macAddress == nil)
        #expect(device.hostname == nil)
        #expect(device.vendor == nil)
        #expect(device.customName == nil)
        #expect(device.isOnline == false)
    }

    // MARK: - PaginatedDevices decoding

    @Test("Decode PaginatedDevices with items array")
    func decodePaginatedDevices() throws {
        let json = """
        {
            "items": [
                {
                    "id": 1,
                    "ip_address": "192.168.1.100",
                    "mac_address": "AA:BB:CC:DD:EE:01",
                    "hostname": "device-1",
                    "vendor": "Vendor-1",
                    "device_type": "unknown",
                    "custom_name": null,
                    "trust_status": "unknown",
                    "is_online": true,
                    "first_seen": "2026-02-20T00:00:00Z",
                    "last_seen": "2026-02-22T00:00:00Z"
                },
                {
                    "id": 2,
                    "ip_address": "192.168.1.101",
                    "mac_address": "AA:BB:CC:DD:EE:02",
                    "hostname": "device-2",
                    "vendor": "Vendor-2",
                    "device_type": "laptop",
                    "custom_name": "My Laptop",
                    "trust_status": "approved",
                    "is_online": true,
                    "first_seen": "2026-02-20T00:00:00Z",
                    "last_seen": "2026-02-22T00:00:00Z"
                }
            ],
            "total": 15,
            "limit": 2,
            "offset": 0
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let paginated = try decoder.decode(PaginatedDevices.self, from: json)

        #expect(paginated.items.count == 2)
        #expect(paginated.total == 15)
        #expect(paginated.limit == 2)
        #expect(paginated.offset == 0)
        #expect(paginated.items[0].ipAddress == "192.168.1.100")
        #expect(paginated.items[1].customName == "My Laptop")
    }

    // MARK: - AlertSeverity comparison

    @Test("AlertSeverity ordering: critical > high > medium > low")
    func alertSeverityComparison() {
        #expect(AlertSeverity.critical > AlertSeverity.high)
        #expect(AlertSeverity.high > AlertSeverity.medium)
        #expect(AlertSeverity.medium > AlertSeverity.low)
        #expect(AlertSeverity.critical > AlertSeverity.low)

        let sorted: [AlertSeverity] = [.low, .critical, .medium, .high].sorted()
        #expect(sorted == [.low, .medium, .high, .critical])
    }

    @Test("AlertSeverity raw values are strings")
    func alertSeverityRawValues() {
        #expect(AlertSeverity.critical.rawValue == "critical")
        #expect(AlertSeverity.high.rawValue == "high")
        #expect(AlertSeverity.medium.rawValue == "medium")
        #expect(AlertSeverity.low.rawValue == "low")
    }

    // MARK: - AlertType raw values

    @Test("AlertType raw values match sensor API event names")
    func alertTypeRawValues() {
        #expect(AlertType.newDevice.rawValue == "device.new")
        #expect(AlertType.verificationNeeded.rawValue == "device.verification_needed")
        #expect(AlertType.macChanged.rawValue == "device.mac_changed")
        #expect(AlertType.decoyTrip.rawValue == "decoy.trip")
        #expect(AlertType.credentialTrip.rawValue == "decoy.credential_trip")
        #expect(AlertType.sensorOffline.rawValue == "system.sensor_offline")
        #expect(AlertType.learningComplete.rawValue == "system.learning_complete")
    }

    // MARK: - Enum raw values

    @Test("TrustStatus raw values")
    func trustStatusRawValues() {
        #expect(TrustStatus.approved.rawValue == "approved")
        #expect(TrustStatus.rejected.rawValue == "rejected")
        #expect(TrustStatus.unknown.rawValue == "unknown")
    }

    @Test("DecoyType raw values match sensor API")
    func decoyTypeRawValues() {
        #expect(DecoyType.devServer.rawValue == "dev_server")
        #expect(DecoyType.homeAssistant.rawValue == "home_assistant")
        #expect(DecoyType.fileShare.rawValue == "file_share")
    }

    @Test("DecoyStatus raw values")
    func decoyStatusRawValues() {
        #expect(DecoyStatus.active.rawValue == "active")
        #expect(DecoyStatus.degraded.rawValue == "degraded")
        #expect(DecoyStatus.stopped.rawValue == "stopped")
    }

    @Test("IncidentStatus raw values")
    func incidentStatusRawValues() {
        #expect(IncidentStatus.active.rawValue == "active")
        #expect(IncidentStatus.closed.rawValue == "closed")
    }

    @Test("ResourceProfile raw values")
    func resourceProfileRawValues() {
        #expect(ResourceProfile.lite.rawValue == "lite")
        #expect(ResourceProfile.standard.rawValue == "standard")
        #expect(ResourceProfile.full.rawValue == "full")
    }

    // MARK: - AnyCodableValue

    @Test("Decode AnyCodableValue nested JSON")
    func decodeAnyCodableValueNested() throws {
        let json = """
        {
            "name": "test",
            "count": 42,
            "rate": 3.14,
            "active": true,
            "tags": ["alpha", "beta"],
            "meta": {
                "nested_key": "nested_value",
                "nested_count": 7
            },
            "empty": null
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let value = try decoder.decode([String: AnyCodableValue].self, from: json)

        #expect(value["name"] == .string("test"))
        #expect(value["count"] == .int(42))
        #expect(value["rate"] == .double(3.14))
        #expect(value["active"] == .bool(true))
        #expect(value["empty"] == .null)

        if case let .array(tags) = value["tags"] {
            #expect(tags.count == 2)
            #expect(tags[0] == .string("alpha"))
            #expect(tags[1] == .string("beta"))
        } else {
            Issue.record("Expected .array for tags")
        }

        if case let .object(meta) = value["meta"] {
            #expect(meta["nested_key"] == .string("nested_value"))
            #expect(meta["nested_count"] == .int(7))
        } else {
            Issue.record("Expected .object for meta")
        }
    }

    @Test("Encode AnyCodableValue round-trips")
    func encodeAnyCodableValueRoundTrip() throws {
        let original: [String: AnyCodableValue] = [
            "name": .string("test"),
            "count": .int(42),
            "active": .bool(true),
            "nothing": .null,
        ]

        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let data = try encoder.encode(original)
        let decoder = JSONDecoder()
        let decoded = try decoder.decode([String: AnyCodableValue].self, from: data)

        #expect(decoded["name"] == .string("test"))
        #expect(decoded["count"] == .int(42))
        #expect(decoded["active"] == .bool(true))
        #expect(decoded["nothing"] == .null)
    }

    // MARK: - VerifyRequest encoding

    @Test("Encode VerifyRequest produces snake_case keys")
    func encodeVerifyRequestSnakeCase() throws {
        let request = VerifyRequest(
            response: "hmac_response_hex",
            clientNonce: "abc123nonce",
            clientName: "Matt's MacBook Pro"
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(request)
        let jsonObject = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        #expect(jsonObject["response"] as? String == "hmac_response_hex")
        #expect(jsonObject["client_nonce"] as? String == "abc123nonce")
        #expect(jsonObject["client_name"] as? String == "Matt's MacBook Pro")

        // Ensure camelCase keys are NOT present
        #expect(jsonObject["clientNonce"] == nil)
        #expect(jsonObject["clientName"] == nil)
    }

    // MARK: - CompleteRequest encoding

    @Test("Encode CompleteRequest produces snake_case keys")
    func encodeCompleteRequestSnakeCase() throws {
        let request = CompleteRequest(encryptedCsr: "base64-encrypted-csr-data")

        let encoder = JSONEncoder()
        let data = try encoder.encode(request)
        let jsonObject = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        #expect(jsonObject["encrypted_csr"] as? String == "base64-encrypted-csr-data")
        #expect(jsonObject["encryptedCsr"] == nil)
    }

    // MARK: - HealthResponse decoding

    @Test("Decode HealthResponse from snake_case JSON")
    func decodeHealthResponse() throws {
        let json = """
        {
            "version": "0.1.0",
            "sensor_id": "sensor-abc-123",
            "uptime_seconds": 3661.5
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let health = try decoder.decode(HealthResponse.self, from: json)

        #expect(health.version == "0.1.0")
        #expect(health.sensorId == "sensor-abc-123")
        #expect(health.uptimeSeconds == 3661.5)
    }

    // MARK: - StatusResponse decoding

    @Test("Decode StatusResponse from snake_case JSON")
    func decodeStatusResponse() throws {
        let json = """
        {
            "profile": "standard",
            "learning_mode": true,
            "device_count": 12,
            "decoy_count": 4,
            "alert_count": 7
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let status = try decoder.decode(StatusResponse.self, from: json)

        #expect(status.profile == "standard")
        #expect(status.learningMode == true)
        #expect(status.deviceCount == 12)
        #expect(status.decoyCount == 4)
        #expect(status.alertCount == 7)
    }

    // MARK: - AlertDetail decoding with AnyCodableValue detail field

    @Test("Decode AlertDetail with nested detail JSON")
    func decodeAlertDetail() throws {
        let json = """
        {
            "id": 5,
            "incident_id": 2,
            "alert_type": "decoy.trip",
            "severity": "critical",
            "title": "Decoy connection detected",
            "detail": {
                "decoy_name": "fake-nas",
                "protocol": "HTTP",
                "request_path": "/admin"
            },
            "source_ip": "192.168.1.55",
            "source_mac": "FF:FF:FF:FF:FF:01",
            "device_id": 10,
            "decoy_id": 3,
            "read_at": null,
            "actioned_at": null,
            "action_note": null,
            "created_at": "2026-02-22T10:15:00Z"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let alert = try decoder.decode(AlertDetail.self, from: json)

        #expect(alert.id == 5)
        #expect(alert.incidentId == 2)
        #expect(alert.alertType == "decoy.trip")
        #expect(alert.severity == "critical")
        #expect(alert.sourceIp == "192.168.1.55")
        #expect(alert.readAt == nil)

        if case let .object(detail) = alert.detail {
            #expect(detail["decoy_name"] == .string("fake-nas"))
            #expect(detail["protocol"] == .string("HTTP"))
        } else {
            Issue.record("Expected .object for alert detail")
        }
    }

    // MARK: - DeviceDetail with nested FingerprintEntry

    @Test("Decode DeviceDetail with latest fingerprint")
    func decodeDeviceDetailWithFingerprint() throws {
        let json = """
        {
            "id": 42,
            "ip_address": "192.168.1.101",
            "mac_address": "AA:BB:CC:DD:EE:01",
            "hostname": "living-room-hub",
            "vendor": "Apple Inc.",
            "device_type": "smart_speaker",
            "custom_name": "Living Room Hub",
            "notes": "Main smart home device",
            "trust_status": "approved",
            "trust_updated_at": "2026-02-21T14:00:00Z",
            "is_online": true,
            "first_seen": "2026-02-20T00:00:00Z",
            "last_seen": "2026-02-22T12:30:00Z",
            "latest_fingerprint": {
                "id": 7,
                "mac_address": "AA:BB:CC:DD:EE:01",
                "mdns_hostname": "living-room-hub.local",
                "signal_count": 4,
                "confidence": 0.92,
                "first_seen": "2026-02-20T00:00:00Z",
                "last_seen": "2026-02-22T12:30:00Z"
            }
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let device = try decoder.decode(DeviceDetail.self, from: json)

        #expect(device.id == 42)
        #expect(device.notes == "Main smart home device")
        #expect(device.trustUpdatedAt == "2026-02-21T14:00:00Z")
        #expect(device.latestFingerprint != nil)
        #expect(device.latestFingerprint?.signalCount == 4)
        #expect(device.latestFingerprint?.confidence == 0.92)
        #expect(device.latestFingerprint?.mdnsHostname == "living-room-hub.local")
    }

    // MARK: - IncidentDetail decoding

    @Test("Decode IncidentDetail with child alerts")
    func decodeIncidentDetail() throws {
        let json = """
        {
            "id": 1,
            "source_ip": "192.168.1.99",
            "source_mac": "FF:FF:FF:FF:FF:01",
            "status": "active",
            "severity": "high",
            "alert_count": 2,
            "first_alert_at": "2026-02-22T01:00:00Z",
            "last_alert_at": "2026-02-22T01:10:00Z",
            "closed_at": null,
            "summary": "2 events from 192.168.1.99",
            "alerts": [
                {
                    "id": 10,
                    "incident_id": 1,
                    "alert_type": "decoy.trip",
                    "severity": "high",
                    "title": "Decoy connection",
                    "detail": {"info": "first"},
                    "source_ip": "192.168.1.99",
                    "source_mac": "FF:FF:FF:FF:FF:01",
                    "device_id": null,
                    "decoy_id": 2,
                    "read_at": null,
                    "actioned_at": null,
                    "action_note": null,
                    "created_at": "2026-02-22T01:00:00Z"
                },
                {
                    "id": 11,
                    "incident_id": 1,
                    "alert_type": "decoy.credential_trip",
                    "severity": "critical",
                    "title": "Credential used",
                    "detail": {"credential_type": "aws_key"},
                    "source_ip": "192.168.1.99",
                    "source_mac": "FF:FF:FF:FF:FF:01",
                    "device_id": null,
                    "decoy_id": 2,
                    "read_at": null,
                    "actioned_at": null,
                    "action_note": null,
                    "created_at": "2026-02-22T01:10:00Z"
                }
            ]
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let incident = try decoder.decode(IncidentDetail.self, from: json)

        #expect(incident.id == 1)
        #expect(incident.sourceIp == "192.168.1.99")
        #expect(incident.status == "active")
        #expect(incident.alertCount == 2)
        #expect(incident.alerts.count == 2)
        #expect(incident.alerts[0].alertType == "decoy.trip")
        #expect(incident.alerts[1].alertType == "decoy.credential_trip")
        #expect(incident.closedAt == nil)
        #expect(incident.summary == "2 events from 192.168.1.99")
    }

    // MARK: - ChallengeResponse decoding

    @Test("Decode ChallengeResponse")
    func decodeChallengeResponse() throws {
        let json = """
        {
            "challenge": "a1b2c3d4e5f6",
            "sensor_id": "sensor-001",
            "sensor_name": "SquirrelOps-Kitchen"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let challenge = try decoder.decode(ChallengeResponse.self, from: json)

        #expect(challenge.challenge == "a1b2c3d4e5f6")
        #expect(challenge.sensorId == "sensor-001")
        #expect(challenge.sensorName == "SquirrelOps-Kitchen")
    }

    // MARK: - VerifyResponse decoding

    @Test("Decode VerifyResponse")
    func decodeVerifyResponse() throws {
        let json = """
        {
            "encrypted_ca_cert": "base64-encrypted-ca-cert",
            "server_nonce": "server-nonce-hex"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let verify = try decoder.decode(VerifyResponse.self, from: json)

        #expect(verify.encryptedCaCert == "base64-encrypted-ca-cert")
        #expect(verify.serverNonce == "server-nonce-hex")
    }

    // MARK: - CompleteResponse decoding

    @Test("Decode CompleteResponse")
    func decodeCompleteResponse() throws {
        let json = """
        {
            "encrypted_client_cert": "base64-encrypted-client-cert"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let complete = try decoder.decode(CompleteResponse.self, from: json)

        #expect(complete.encryptedClientCert == "base64-encrypted-client-cert")
    }

    // MARK: - DecoySummary decoding

    @Test("Decode DecoySummary from snake_case JSON")
    func decodeDecoySummary() throws {
        let json = """
        {
            "id": 3,
            "name": "fake-nas",
            "decoy_type": "file_share",
            "bind_address": "192.168.1.200",
            "port": 8080,
            "status": "active",
            "connection_count": 15,
            "credential_trip_count": 2,
            "created_at": "2026-02-20T00:00:00Z",
            "updated_at": "2026-02-22T08:00:00Z"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let decoy = try decoder.decode(DecoySummary.self, from: json)

        #expect(decoy.id == 3)
        #expect(decoy.name == "fake-nas")
        #expect(decoy.decoyType == "file_share")
        #expect(decoy.port == 8080)
        #expect(decoy.connectionCount == 15)
        #expect(decoy.credentialTripCount == 2)
    }

    // MARK: - LearningStatusResponse decoding

    @Test("LearningStatusResponse decodes from JSON")
    func learningStatusDecodes() throws {
        let json = """
        {"enabled": true, "hours_elapsed": 12.5, "hours_total": 48, "phase": "learning"}
        """.data(using: .utf8)!
        let status = try JSONDecoder().decode(LearningStatusResponse.self, from: json)
        #expect(status.enabled == true)
        #expect(status.hoursElapsed == 12.5)
        #expect(status.hoursTotal == 48)
        #expect(status.phase == "learning")
    }

    // MARK: - ConfigResponse decoding

    @Test("ConfigResponse decodes from JSON")
    func configResponseDecodes() throws {
        let json = """
        {"profile": "standard", "alert_methods": {"push": true, "slack": false}, "llm_endpoint": null, "llm_api_key": null}
        """.data(using: .utf8)!
        let config = try JSONDecoder().decode(ConfigResponse.self, from: json)
        #expect(config.profile == "standard")
        #expect(config.alertMethods["push"] == true)
        #expect(config.alertMethods["slack"] == false)
        #expect(config.llmEndpoint == nil)
        #expect(config.llmApiKey == nil)
    }

    // MARK: - DecoyDetail decoding

    @Test("Decode DecoyDetail with config as AnyCodableValue")
    func decodeDecoyDetail() throws {
        let json = """
        {
            "id": 3,
            "name": "fake-nas",
            "decoy_type": "file_share",
            "bind_address": "192.168.1.200",
            "port": 8080,
            "status": "active",
            "config": {"banner": "FreeNAS", "directory_listing": true},
            "connection_count": 15,
            "credential_trip_count": 2,
            "failure_count": 0,
            "last_failure_at": null,
            "created_at": "2026-02-20T00:00:00Z",
            "updated_at": "2026-02-22T08:00:00Z"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let decoy = try decoder.decode(DecoyDetail.self, from: json)

        #expect(decoy.id == 3)
        #expect(decoy.failureCount == 0)
        #expect(decoy.lastFailureAt == nil)

        if case let .object(config) = decoy.config {
            #expect(config["banner"] == .string("FreeNAS"))
            #expect(config["directory_listing"] == .bool(true))
        } else {
            Issue.record("Expected .object for decoy config")
        }
    }
}
