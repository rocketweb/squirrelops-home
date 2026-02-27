// app/Tests/SquirrelOpsHomeTests/EndpointTests.swift
import Foundation
import Testing

@testable import SquirrelOpsHome

@Suite("Endpoint Enum")
struct EndpointTests {

    let baseURL = URL(string: "https://192.168.1.50:8443")!

    // MARK: - Health endpoint

    @Test("Health produces GET /health with no body")
    func healthEndpoint() {
        let endpoint = Endpoint.health
        let request = endpoint.urlRequest(baseURL: baseURL)

        #expect(endpoint.path == "/system/health")
        #expect(endpoint.method == "GET")
        #expect(endpoint.body == nil)
        #expect(endpoint.queryItems == nil)
        #expect(request.httpMethod == "GET")
        #expect(request.url?.path == "/system/health")
        #expect(request.httpBody == nil)
    }

    // MARK: - Devices with query parameters

    @Test("Devices with limit and offset produces correct query string")
    func devicesWithPagination() {
        let endpoint = Endpoint.devices(limit: 10, offset: 20)
        let request = endpoint.urlRequest(baseURL: baseURL)

        #expect(endpoint.path == "/devices")
        #expect(endpoint.method == "GET")
        #expect(endpoint.body == nil)

        let url = request.url!
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        let queryItems = components.queryItems ?? []
        let queryDict = Dictionary(uniqueKeysWithValues: queryItems.map { ($0.name, $0.value) })

        #expect(queryDict["limit"] == "10")
        #expect(queryDict["offset"] == "20")
    }

    @Test("Devices with defaults uses limit=50, offset=0")
    func devicesWithDefaults() {
        let endpoint = Endpoint.devices()
        let request = endpoint.urlRequest(baseURL: baseURL)

        let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!
        let queryItems = components.queryItems ?? []
        let queryDict = Dictionary(uniqueKeysWithValues: queryItems.map { ($0.name, $0.value) })

        #expect(queryDict["limit"] == "50")
        #expect(queryDict["offset"] == "0")
    }

    // MARK: - Device by ID

    @Test("Device by ID produces GET /devices/{id}")
    func deviceById() {
        let endpoint = Endpoint.device(id: 42)
        let request = endpoint.urlRequest(baseURL: baseURL)

        #expect(endpoint.path == "/devices/42")
        #expect(endpoint.method == "GET")
        #expect(request.url?.path == "/devices/42")
    }

    // MARK: - Update device (PUT with JSON body)

    @Test("UpdateDevice produces PUT with JSON body and snake_case keys")
    func updateDevice() throws {
        let body = DeviceUpdateRequest(
            customName: "Living Room Hub",
            notes: "Primary smart speaker",
            deviceType: "smart_speaker"
        )
        let endpoint = Endpoint.updateDevice(id: 42, body: body)
        let request = endpoint.urlRequest(baseURL: baseURL)

        #expect(endpoint.path == "/devices/42")
        #expect(endpoint.method == "PUT")
        #expect(request.httpMethod == "PUT")
        #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")

        let bodyData = endpoint.body!
        let json = try JSONSerialization.jsonObject(with: bodyData) as! [String: Any]

        #expect(json["custom_name"] as? String == "Living Room Hub")
        #expect(json["notes"] as? String == "Primary smart speaker")
        #expect(json["device_type"] as? String == "smart_speaker")

        // Ensure camelCase keys are NOT present
        #expect(json["customName"] == nil)
        #expect(json["deviceType"] == nil)
    }

    // MARK: - Approve / Reject device

    @Test("ApproveDevice produces POST /devices/{id}/approve")
    func approveDevice() {
        let endpoint = Endpoint.approveDevice(id: 7)
        let request = endpoint.urlRequest(baseURL: baseURL)

        #expect(endpoint.path == "/devices/7/approve")
        #expect(endpoint.method == "POST")
        #expect(request.httpMethod == "POST")
    }

    @Test("RejectDevice produces POST /devices/{id}/reject")
    func rejectDevice() {
        let endpoint = Endpoint.rejectDevice(id: 7)

        #expect(endpoint.path == "/devices/7/reject")
        #expect(endpoint.method == "POST")
    }

    // MARK: - Device fingerprints

    @Test("DeviceFingerprints produces GET /devices/{id}/fingerprints")
    func deviceFingerprints() {
        let endpoint = Endpoint.deviceFingerprints(id: 42)

        #expect(endpoint.path == "/devices/42/fingerprints")
        #expect(endpoint.method == "GET")
    }

    // MARK: - Alerts with filters

    @Test("Alerts with severity filter produces correct query string")
    func alertsWithSeverityFilter() {
        let endpoint = Endpoint.alerts(limit: 25, offset: 0, severity: "critical")
        let request = endpoint.urlRequest(baseURL: baseURL)

        let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!
        let queryItems = components.queryItems ?? []
        let queryDict = Dictionary(uniqueKeysWithValues: queryItems.map { ($0.name, $0.value) })

        #expect(queryDict["limit"] == "25")
        #expect(queryDict["severity"] == "critical")
    }

    @Test("Alerts without severity filter omits severity param")
    func alertsWithoutSeverityFilter() {
        let endpoint = Endpoint.alerts()
        let request = endpoint.urlRequest(baseURL: baseURL)

        let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!
        let queryItems = components.queryItems ?? []
        let names = queryItems.map(\.name)

        #expect(!names.contains("severity"))
        #expect(names.contains("limit"))
        #expect(names.contains("offset"))
    }

    // MARK: - Alert by ID

    @Test("Alert by ID produces GET /alerts/{id}")
    func alertById() {
        let endpoint = Endpoint.alert(id: 99)

        #expect(endpoint.path == "/alerts/99")
        #expect(endpoint.method == "GET")
    }

    // MARK: - Read and action alerts

    @Test("ReadAlert produces PUT /alerts/{id}/read")
    func readAlert() {
        let endpoint = Endpoint.readAlert(id: 5)

        #expect(endpoint.path == "/alerts/5/read")
        #expect(endpoint.method == "PUT")
    }

    @Test("ActionAlert produces PUT /alerts/{id}/action with optional note")
    func actionAlertWithNote() throws {
        let endpoint = Endpoint.actionAlert(id: 5, note: "Investigated, false positive")

        #expect(endpoint.path == "/alerts/5/action")
        #expect(endpoint.method == "PUT")

        let bodyData = endpoint.body!
        let json = try JSONSerialization.jsonObject(with: bodyData) as! [String: Any]
        #expect(json["note"] as? String == "Investigated, false positive")
    }

    @Test("ActionAlert with nil note encodes null")
    func actionAlertWithoutNote() throws {
        let endpoint = Endpoint.actionAlert(id: 5, note: nil)

        #expect(endpoint.body != nil)
    }

    // MARK: - Incidents

    @Test("Incident produces GET /incidents/{id}")
    func incident() {
        let endpoint = Endpoint.incident(id: 3)

        #expect(endpoint.path == "/incidents/3")
        #expect(endpoint.method == "GET")
    }

    @Test("ReadIncident produces PUT /incidents/{id}/read")
    func readIncident() {
        let endpoint = Endpoint.readIncident(id: 3)

        #expect(endpoint.path == "/incidents/3/read")
        #expect(endpoint.method == "PUT")
    }

    // MARK: - Export alerts

    @Test("ExportAlerts produces GET /alerts/export with no date params")
    func exportAlertsNoParams() {
        let endpoint = Endpoint.exportAlerts()

        #expect(endpoint.path == "/alerts/export")
        #expect(endpoint.method == "GET")
        #expect(endpoint.queryItems == nil)
    }

    @Test("ExportAlerts includes date_from and date_to query params")
    func exportAlertsWithDates() {
        let endpoint = Endpoint.exportAlerts(
            dateFrom: "2026-02-01T00:00:00Z",
            dateTo: "2026-02-24T23:59:59Z"
        )

        #expect(endpoint.path == "/alerts/export")
        #expect(endpoint.method == "GET")
        let items = endpoint.queryItems!
        #expect(items.count == 2)
        #expect(items[0] == URLQueryItem(name: "date_from", value: "2026-02-01T00:00:00Z"))
        #expect(items[1] == URLQueryItem(name: "date_to", value: "2026-02-24T23:59:59Z"))
    }

    @Test("ExportAlerts includes only date_from when dateTo is nil")
    func exportAlertsDateFromOnly() {
        let endpoint = Endpoint.exportAlerts(dateFrom: "2026-02-01T00:00:00Z")

        let items = endpoint.queryItems!
        #expect(items.count == 1)
        #expect(items[0] == URLQueryItem(name: "date_from", value: "2026-02-01T00:00:00Z"))
    }

    // MARK: - Decoys

    @Test("Decoys produces GET /decoys")
    func decoys() {
        let endpoint = Endpoint.decoys

        #expect(endpoint.path == "/decoys")
        #expect(endpoint.method == "GET")
    }

    @Test("Decoy by ID produces GET /decoys/{id}")
    func decoyById() {
        let endpoint = Endpoint.decoy(id: 2)

        #expect(endpoint.path == "/decoys/2")
        #expect(endpoint.method == "GET")
    }

    @Test("RestartDecoy produces POST /decoys/{id}/restart")
    func restartDecoy() {
        let endpoint = Endpoint.restartDecoy(id: 2)

        #expect(endpoint.path == "/decoys/2/restart")
        #expect(endpoint.method == "POST")
    }

    @Test("UpdateDecoyConfig produces PUT /decoys/{id}/config with JSON body")
    func updateDecoyConfig() throws {
        let config: [String: AnyCodableValue] = [
            "banner": .string("FakeNAS v2"),
            "port_override": .int(9090),
        ]
        let endpoint = Endpoint.updateDecoyConfig(id: 2, config: config)

        #expect(endpoint.path == "/decoys/2/config")
        #expect(endpoint.method == "PUT")
        #expect(endpoint.body != nil)

        let bodyData = endpoint.body!
        let json = try JSONSerialization.jsonObject(with: bodyData) as! [String: Any]
        #expect(json["banner"] as? String == "FakeNAS v2")
        #expect(json["port_override"] as? Int == 9090)
    }

    @Test("DecoyConnections produces GET /decoys/{id}/connections with pagination")
    func decoyConnections() {
        let endpoint = Endpoint.decoyConnections(id: 2, limit: 10, offset: 5)
        let request = endpoint.urlRequest(baseURL: baseURL)

        #expect(endpoint.path == "/decoys/2/connections")
        #expect(endpoint.method == "GET")

        let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!
        let queryItems = components.queryItems ?? []
        let queryDict = Dictionary(uniqueKeysWithValues: queryItems.map { ($0.name, $0.value) })

        #expect(queryDict["limit"] == "10")
        #expect(queryDict["offset"] == "5")
    }

    // MARK: - Config

    @Test("Config produces GET /config")
    func config() {
        let endpoint = Endpoint.config

        #expect(endpoint.path == "/config")
        #expect(endpoint.method == "GET")
    }

    @Test("UpdateConfig produces PUT /config with JSON body")
    func updateConfig() throws {
        let body: [String: AnyCodableValue] = [
            "scan_interval": .int(60),
            "subnet": .string("10.0.0.0/24"),
        ]
        let endpoint = Endpoint.updateConfig(body: body)

        #expect(endpoint.path == "/config")
        #expect(endpoint.method == "PUT")

        let bodyData = endpoint.body!
        let json = try JSONSerialization.jsonObject(with: bodyData) as! [String: Any]
        #expect(json["scan_interval"] as? Int == 60)
        #expect(json["subnet"] as? String == "10.0.0.0/24")
    }

    // MARK: - System routes

    @Test("Status produces GET /system/status")
    func status() {
        let endpoint = Endpoint.status

        #expect(endpoint.path == "/system/status")
        #expect(endpoint.method == "GET")
    }

    @Test("Profile produces GET /system/profile")
    func profile() {
        let endpoint = Endpoint.profile

        #expect(endpoint.path == "/system/profile")
        #expect(endpoint.method == "GET")
    }

    @Test("Learning produces GET /system/learning")
    func learning() {
        let endpoint = Endpoint.learning

        #expect(endpoint.path == "/system/learning")
        #expect(endpoint.method == "GET")
    }

    @Test("UpdateProfile produces PUT /system/profile with JSON body")
    func updateProfile() throws {
        let endpoint = Endpoint.updateProfile(profile: "lite")

        #expect(endpoint.path == "/system/profile")
        #expect(endpoint.method == "PUT")

        let bodyData = endpoint.body!
        let json = try JSONSerialization.jsonObject(with: bodyData) as! [String: Any]
        #expect(json["profile"] as? String == "lite")
    }

    // MARK: - Pairing

    @Test("PairingChallenge produces GET /pairing/code/challenge")
    func pairingChallenge() {
        let endpoint = Endpoint.pairingChallenge

        #expect(endpoint.path == "/pairing/code/challenge")
        #expect(endpoint.method == "GET")
    }

    @Test("PairingVerify produces POST with correct path and body")
    func pairingVerify() throws {
        let body = VerifyRequest(
            response: "hmac_hex_value",
            clientNonce: "nonce123",
            clientName: "Matt's Mac"
        )
        let endpoint = Endpoint.pairingVerify(body: body)
        let request = endpoint.urlRequest(baseURL: baseURL)

        #expect(endpoint.path == "/pairing/verify")
        #expect(endpoint.method == "POST")
        #expect(request.httpMethod == "POST")
        #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")

        let bodyData = endpoint.body!
        let json = try JSONSerialization.jsonObject(with: bodyData) as! [String: Any]

        #expect(json["response"] as? String == "hmac_hex_value")
        #expect(json["client_nonce"] as? String == "nonce123")
        #expect(json["client_name"] as? String == "Matt's Mac")
    }

    @Test("PairingComplete produces POST /pairing/complete with body")
    func pairingComplete() throws {
        let body = CompleteRequest(encryptedCsr: "base64-csr-data")
        let endpoint = Endpoint.pairingComplete(body: body)

        #expect(endpoint.path == "/pairing/complete")
        #expect(endpoint.method == "POST")

        let bodyData = endpoint.body!
        let json = try JSONSerialization.jsonObject(with: bodyData) as! [String: Any]
        #expect(json["encrypted_csr"] as? String == "base64-csr-data")
    }

    @Test("Unpair produces DELETE /pairing/{id}")
    func unpair() {
        let endpoint = Endpoint.unpair(id: 5)

        #expect(endpoint.path == "/pairing/5")
        #expect(endpoint.method == "DELETE")
        #expect(endpoint.body == nil)
    }

    // MARK: - URLRequest construction

    @Test("urlRequest builds complete URL from baseURL + path")
    func urlRequestBuildsCompleteURL() {
        let endpoint = Endpoint.device(id: 42)
        let request = endpoint.urlRequest(baseURL: baseURL)

        #expect(request.url?.absoluteString == "https://192.168.1.50:8443/devices/42")
    }

    @Test("urlRequest includes Content-Type header for POST/PUT with body")
    func urlRequestSetsContentType() {
        let endpoint = Endpoint.approveDevice(id: 1)
        let request = endpoint.urlRequest(baseURL: baseURL)

        // POST without body should not have Content-Type
        #expect(endpoint.body == nil)

        let putEndpoint = Endpoint.updateProfile(profile: "full")
        let putRequest = putEndpoint.urlRequest(baseURL: baseURL)
        #expect(putRequest.value(forHTTPHeaderField: "Content-Type") == "application/json")
    }
}
