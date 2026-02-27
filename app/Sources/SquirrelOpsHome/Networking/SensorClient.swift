import Foundation

// MARK: - Errors

public enum SensorClientError: Error, Sendable, Equatable {
    case badResponse(statusCode: Int)
    case decodingFailed
    case connectionFailed(String)

    public static func == (lhs: SensorClientError, rhs: SensorClientError) -> Bool {
        switch (lhs, rhs) {
        case (.badResponse(let a), .badResponse(let b)):
            return a == b
        case (.decodingFailed, .decodingFailed):
            return true
        case (.connectionFailed(let a), .connectionFailed(let b)):
            return a == b
        default:
            return false
        }
    }
}

// MARK: - SensorClient

public final class SensorClient: Sendable {

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

    /// Create a client with TLS pinning and auth header support.
    public init(baseURL: URL, certFingerprint: String, caCertData: Data?) {
        self.baseURL = baseURL
        self.certFingerprint = certFingerprint
        let delegate = TLSPinningDelegate(caCertData: caCertData)
        let config = URLSessionConfiguration.default
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
        var urlRequest = endpoint.urlRequest(baseURL: baseURL)
        if let fingerprint = certFingerprint {
            urlRequest.setValue(fingerprint, forHTTPHeaderField: "x-client-cert-fingerprint")
        }

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
            throw SensorClientError.badResponse(statusCode: httpResponse.statusCode)
        }

        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw SensorClientError.decodingFailed
        }
    }

    /// Perform a request that expects no response body (void).
    public func request(_ endpoint: Endpoint) async throws {
        var urlRequest = endpoint.urlRequest(baseURL: baseURL)
        if let fingerprint = certFingerprint {
            urlRequest.setValue(fingerprint, forHTTPHeaderField: "x-client-cert-fingerprint")
        }

        let response: URLResponse
        do {
            (_, response) = try await session.data(for: urlRequest)
        } catch {
            throw SensorClientError.connectionFailed(error.localizedDescription)
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            throw SensorClientError.connectionFailed("Invalid response type")
        }

        guard (200..<300).contains(httpResponse.statusCode) else {
            throw SensorClientError.badResponse(statusCode: httpResponse.statusCode)
        }
    }
}
