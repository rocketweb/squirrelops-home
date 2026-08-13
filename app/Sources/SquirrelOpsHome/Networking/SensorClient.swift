import Foundation
import Security

// MARK: - Errors

public enum SensorClientError: Error, Sendable, Equatable {
    case badResponse(statusCode: Int, detail: String? = nil)
    case decodingFailed
    case connectionFailed(String)

    public static func == (lhs: SensorClientError, rhs: SensorClientError) -> Bool {
        switch (lhs, rhs) {
        case (.badResponse(let a, let ad), .badResponse(let b, let bd)):
            return a == b && ad == bd
        case (.decodingFailed, .decodingFailed):
            return true
        case (.connectionFailed(let a), .connectionFailed(let b)):
            return a == b
        default:
            return false
        }
    }

    public var httpStatusCode: Int? {
        if case .badResponse(let statusCode, _) = self {
            return statusCode
        }
        return nil
    }
}

extension SensorClientError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .badResponse(let statusCode, let detail):
            if let detail, !detail.isEmpty {
                return detail
            }
            return "Sensor returned HTTP \(statusCode)"
        case .decodingFailed:
            return "Sensor returned an unexpected response"
        case .connectionFailed(let message):
            return message
        }
    }
}

// MARK: - SensorClient

public final class SensorClient: Sendable {

    /// A session configuration that never writes a response to disk.
    ///
    /// Sensor responses carry credentials. `URLSessionConfiguration.default`
    /// shares an on-disk `URLCache`, so a cached `/config` body outlives the
    /// process in a file readable by any process running as the paired user.
    /// The sensor now sends `Cache-Control: no-store`, but the client must not
    /// depend on a header to keep secrets off the disk, and the same headers
    /// were absent from every release before 2.0.2.
    ///
    /// Ephemeral also keeps cookies and credentials in memory. Neither is used
    /// here: the client identity arrives through the TLS delegate.
    static func nonPersistentConfiguration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        return configuration
    }

    let baseURL: URL
    let session: URLSession
    let certFingerprint: String?
    private let decoder: JSONDecoder

    public init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
        self.certFingerprint = nil

        let decoder = JSONDecoder()
        self.decoder = decoder
    }

    /// Pairing-only client with an explicit TOFU trust mode. The authenticated
    /// setup-key transcript establishes the sensor identity before persistence.
    public init(pairingBaseURL: URL) {
        self.baseURL = pairingBaseURL
        self.certFingerprint = nil
        let delegate = TLSPinningDelegate(serverTrustMode: .pairingTOFU)
        self.session = URLSession(
            configuration: Self.nonPersistentConfiguration(),
            delegate: delegate,
            delegateQueue: nil
        )

        let decoder = JSONDecoder()
        self.decoder = decoder
    }

    /// Create a client with TLS pinning and paired client certificate support.
    public init(
        baseURL: URL,
        certFingerprint: String,
        caCertData: Data,
        clientIdentity: SecIdentity? = nil
    ) {
        self.baseURL = baseURL
        self.certFingerprint = certFingerprint
        let delegate = TLSPinningDelegate(
            serverTrustMode: .pinnedCA(caCertData),
            clientIdentity: clientIdentity
        )
        let config = Self.nonPersistentConfiguration()
        self.session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)

        let decoder = JSONDecoder()
        self.decoder = decoder
    }

    /// Test-only initializer with explicit fingerprint and session.
    init(baseURL: URL, certFingerprint: String?, session: URLSession) {
        self.baseURL = baseURL
        self.certFingerprint = certFingerprint
        self.session = session

        let decoder = JSONDecoder()
        self.decoder = decoder
    }

    /// Perform a request and decode the response as `T`.
    public func request<T: Decodable>(_ endpoint: Endpoint) async throws -> T {
        let urlRequest = endpoint.urlRequest(baseURL: baseURL)

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: urlRequest)
        } catch {
            throw SensorClientError.connectionFailed(error.localizedDescription)
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            throw SensorClientError.connectionFailed("Invalid response type")
        }

        guard (200..<300).contains(httpResponse.statusCode) else {
            throw Self.serverError(
                statusCode: httpResponse.statusCode,
                data: data
            )
        }

        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw SensorClientError.decodingFailed
        }
    }

    /// Perform a request that expects no response body (void).
    public func request(_ endpoint: Endpoint) async throws {
        let urlRequest = endpoint.urlRequest(baseURL: baseURL)

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: urlRequest)
        } catch {
            throw SensorClientError.connectionFailed(error.localizedDescription)
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            throw SensorClientError.connectionFailed("Invalid response type")
        }

        guard (200..<300).contains(httpResponse.statusCode) else {
            throw Self.serverError(
                statusCode: httpResponse.statusCode,
                data: data
            )
        }
    }

    private static func serverError(
        statusCode: Int,
        data: Data
    ) -> SensorClientError {
        let detail: String?
        if let object = try? JSONSerialization.jsonObject(with: data),
           let dictionary = object as? [String: Any],
           let message = dictionary["detail"] as? String {
            let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
            detail = trimmed.isEmpty ? nil : String(trimmed.prefix(512))
        } else {
            detail = nil
        }
        return .badResponse(statusCode: statusCode, detail: detail)
    }
}
