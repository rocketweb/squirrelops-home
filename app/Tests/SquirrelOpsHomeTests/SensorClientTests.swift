import Foundation
import Testing

@testable import SquirrelOpsHome

/// Thread-safe box for capturing values in @Sendable closures.
final class CapturedValue<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: T?

    var value: T? {
        get { lock.withLock { _value } }
        set { lock.withLock { _value = newValue } }
    }
}

@Suite("SensorClient", .serialized)
struct SensorClientTests {

    let baseURL = URL(string: "https://192.168.1.50:8443")!

    /// Create a URLSession configured to use MockURLProtocol.
    private func mockSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return URLSession(configuration: config)
    }

    /// Helper to set the mock handler.
    private func setMockHandler(
        _ handler: @Sendable @escaping (URLRequest) throws -> (HTTPURLResponse, Data)
    ) async {
        await MockURLProtocol.store.setHandler(handler)
    }

    /// Helper to create a successful JSON response.
    private func jsonResponse(
        for url: URL,
        json: String,
        statusCode: Int = 200
    ) -> (HTTPURLResponse, Data) {
        let response = HTTPURLResponse(
            url: url,
            statusCode: statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        let data = json.data(using: .utf8)!
        return (response, data)
    }

    // MARK: - Decode HealthResponse

    @Test("Fetch health endpoint returns decoded HealthResponse")
    func fetchHealth() async throws {
        let session = mockSession()
        let client = SensorClient(baseURL: baseURL, session: session)

        await setMockHandler { request in
            let json = """
            {
                "version": "0.1.0",
                "sensor_id": "sensor-test-001",
                "uptime_seconds": 1234.5
            }
            """
            return self.jsonResponse(for: request.url!, json: json)
        }

        let health: HealthResponse = try await client.request(.health)

        #expect(health.version == "0.1.0")
        #expect(health.sensorId == "sensor-test-001")
        #expect(health.uptimeSeconds == 1234.5)
    }

    // MARK: - Decode PaginatedDevices

    @Test("Fetch devices endpoint returns decoded PaginatedDevices")
    func fetchDevices() async throws {
        let session = mockSession()
        let client = SensorClient(baseURL: baseURL, session: session)

        await setMockHandler { request in
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
                    }
                ],
                "total": 1,
                "limit": 50,
                "offset": 0
            }
            """
            return self.jsonResponse(for: request.url!, json: json)
        }

        let result: PaginatedDevices = try await client.request(.devices())

        #expect(result.items.count == 1)
        #expect(result.total == 1)
        #expect(result.items[0].ipAddress == "192.168.1.100")
        #expect(result.items[0].macAddress == "AA:BB:CC:DD:EE:01")
    }

    // MARK: - HTTP error responses

    @Test("401 response throws badResponse with statusCode 401")
    func unauthorizedThrowsBadResponse() async throws {
        let session = mockSession()
        let client = SensorClient(baseURL: baseURL, session: session)

        await setMockHandler { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 401,
                httpVersion: "HTTP/1.1",
                headerFields: nil
            )!
            return (response, Data())
        }

        await #expect(throws: SensorClientError.self) {
            let _: HealthResponse = try await client.request(.health)
        }

        do {
            let _: HealthResponse = try await client.request(.health)
            Issue.record("Expected SensorClientError.badResponse")
        } catch let error as SensorClientError {
            if case .badResponse(let statusCode) = error {
                #expect(statusCode == 401)
            } else {
                Issue.record("Expected badResponse, got \(error)")
            }
        }
    }

    @Test("500 response throws badResponse with statusCode 500")
    func serverErrorThrowsBadResponse() async throws {
        let session = mockSession()
        let client = SensorClient(baseURL: baseURL, session: session)

        await setMockHandler { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 500,
                httpVersion: "HTTP/1.1",
                headerFields: nil
            )!
            return (response, Data())
        }

        do {
            let _: HealthResponse = try await client.request(.health)
            Issue.record("Expected SensorClientError.badResponse")
        } catch let error as SensorClientError {
            if case .badResponse(let statusCode) = error {
                #expect(statusCode == 500)
            } else {
                Issue.record("Expected badResponse, got \(error)")
            }
        }
    }

    // MARK: - Malformed JSON

    @Test("Malformed JSON throws decodingFailed")
    func malformedJsonThrowsDecodingFailed() async throws {
        let session = mockSession()
        let client = SensorClient(baseURL: baseURL, session: session)

        await setMockHandler { request in
            let json = "{ this is not valid json }"
            return self.jsonResponse(for: request.url!, json: json)
        }

        do {
            let _: HealthResponse = try await client.request(.health)
            Issue.record("Expected SensorClientError.decodingFailed")
        } catch let error as SensorClientError {
            if case .decodingFailed = error {
                // Expected
            } else {
                Issue.record("Expected decodingFailed, got \(error)")
            }
        }
    }

    // MARK: - URL construction

    @Test("Request builds correct URL from baseURL + endpoint")
    func requestBuildsCorrectURL() async throws {
        let session = mockSession()
        let client = SensorClient(baseURL: baseURL, session: session)

        let capturedURL = CapturedValue<URL>()

        await setMockHandler { request in
            capturedURL.value = request.url
            let json = """
            {
                "id": 42,
                "ip_address": "192.168.1.101",
                "mac_address": "AA:BB:CC:DD:EE:01",
                "hostname": "test",
                "vendor": "Test",
                "device_type": "unknown",
                "custom_name": null,
                "notes": null,
                "trust_status": "unknown",
                "trust_updated_at": null,
                "is_online": true,
                "first_seen": "2026-02-22T00:00:00Z",
                "last_seen": "2026-02-22T00:00:00Z",
                "latest_fingerprint": null
            }
            """
            return self.jsonResponse(for: request.url!, json: json)
        }

        let _: DeviceDetail = try await client.request(.device(id: 42))

        #expect(capturedURL.value?.absoluteString == "https://192.168.1.50:8443/devices/42")
    }

    // MARK: - Void response

    @Test("Void request succeeds on 200 without decoding")
    func voidRequestSucceeds() async throws {
        let session = mockSession()
        let client = SensorClient(baseURL: baseURL, session: session)

        await setMockHandler { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: nil
            )!
            return (response, Data())
        }

        try await client.request(.approveDevice(id: 1))
        // If we get here without throwing, the test passes
    }

    @Test("Void request throws on non-2xx status")
    func voidRequestThrowsOnError() async throws {
        let session = mockSession()
        let client = SensorClient(baseURL: baseURL, session: session)

        await setMockHandler { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 403,
                httpVersion: "HTTP/1.1",
                headerFields: nil
            )!
            return (response, Data())
        }

        do {
            try await client.request(.readAlert(id: 1))
            Issue.record("Expected SensorClientError.badResponse")
        } catch let error as SensorClientError {
            if case .badResponse(let statusCode) = error {
                #expect(statusCode == 403)
            } else {
                Issue.record("Expected badResponse, got \(error)")
            }
        }
    }

    // MARK: - Request method verification

    @Test("POST endpoint sends POST request")
    func postEndpointSendsPostMethod() async throws {
        let session = mockSession()
        let client = SensorClient(baseURL: baseURL, session: session)

        let capturedMethod = CapturedValue<String>()

        await setMockHandler { request in
            capturedMethod.value = request.httpMethod
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: nil
            )!
            return (response, Data())
        }

        try await client.request(.approveDevice(id: 1))

        #expect(capturedMethod.value == "POST")
    }

    // MARK: - Auth header

    @Test("Requests include x-client-cert-fingerprint header when fingerprint set")
    func requestsIncludeAuthHeader() async throws {
        let session = mockSession()
        let client = SensorClient(
            baseURL: baseURL, certFingerprint: "sha256:abc123", session: session
        )

        let capturedHeaders = CapturedValue<[String: String]>()

        await setMockHandler { request in
            capturedHeaders.value = request.allHTTPHeaderFields ?? [:]
            return self.jsonResponse(for: request.url!, json: """
                {"version":"0.1.0","sensor_id":"s1","uptime_seconds":0}
            """)
        }

        let _: HealthResponse = try await client.request(.health)

        #expect(capturedHeaders.value?["x-client-cert-fingerprint"] == "sha256:abc123")
    }

    @Test("Requests omit auth header when no fingerprint")
    func requestsOmitAuthHeaderWhenNil() async throws {
        let session = mockSession()
        let client = SensorClient(baseURL: baseURL, session: session)

        let capturedHeaders = CapturedValue<[String: String]>()

        await setMockHandler { request in
            capturedHeaders.value = request.allHTTPHeaderFields ?? [:]
            return self.jsonResponse(for: request.url!, json: """
                {"version":"0.1.0","sensor_id":"s1","uptime_seconds":0}
            """)
        }

        let _: HealthResponse = try await client.request(.health)

        #expect(capturedHeaders.value?["x-client-cert-fingerprint"] == nil)
    }
}
