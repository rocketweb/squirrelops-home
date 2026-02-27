import CryptoKit
import Foundation
import Network

// MARK: - ServiceResolver

/// Resolves a Bonjour service name to a host and port using NetService.
@MainActor
private final class ServiceResolver: NSObject, NetServiceDelegate {
    private let service: NetService
    private var continuation: CheckedContinuation<(String?, UInt16?), Never>?

    init(name: String, type: String, domain: String) {
        self.service = NetService(domain: domain, type: type, name: name)
        super.init()
        self.service.delegate = self
    }

    func resolve() async -> (String?, UInt16?) {
        await withCheckedContinuation { cont in
            self.continuation = cont
            self.service.schedule(in: .main, forMode: .common)
            self.service.resolve(withTimeout: 5.0)
        }
    }

    nonisolated func netServiceDidResolveAddress(_ sender: NetService) {
        var host: String?
        let port = UInt16(sender.port)

        // Extract the IPv4 address from the resolved addresses
        if let addresses = sender.addresses {
            for data in addresses {
                if data.count >= MemoryLayout<sockaddr_in>.size {
                    let family = data.withUnsafeBytes { $0.load(fromByteOffset: 1, as: UInt8.self) }
                    if family == UInt8(AF_INET) {
                        // IPv4
                        data.withUnsafeBytes { ptr in
                            let sa = ptr.baseAddress!.assumingMemoryBound(to: sockaddr_in.self).pointee
                            var addr = sa.sin_addr
                            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                            if inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                                host = String(cString: buf)
                            }
                        }
                        if host != nil { break }
                    }
                }
            }
        }

        // Fallback to hostName (may include trailing dot)
        if host == nil {
            host = sender.hostName?.trimmingCharacters(in: CharacterSet(charactersIn: "."))
        }

        sender.stop()
        Task { @MainActor in
            continuation?.resume(returning: (host, port))
            continuation = nil
        }
    }

    nonisolated func netService(_ sender: NetService, didNotResolve errorDict: [String: NSNumber]) {
        sender.stop()
        Task { @MainActor in
            continuation?.resume(returning: (nil, nil))
            continuation = nil
        }
    }
}

// MARK: - PairingClientProtocol

/// Abstracts the REST calls needed by PairingManager for testability.
public protocol PairingClientProtocol: Sendable {
    func fetchChallenge(baseURL: URL) async throws -> ChallengeResponse
    func postVerify(baseURL: URL, body: VerifyRequest) async throws -> VerifyResponse
    func postComplete(baseURL: URL, body: CompleteRequest) async throws -> CompleteResponse
    func deleteUnpair(baseURL: URL, id: Int) async throws
}

// MARK: - SensorClient + PairingClientProtocol

extension SensorClient: PairingClientProtocol {

    /// Perform a pairing request with a specific base URL (sensor discovered via mDNS).
    /// Uses the SensorClient's session to honor TLS configuration.
    private func pairingRequest<T: Decodable>(baseURL: URL, endpoint: Endpoint) async throws -> T {
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
            throw SensorClientError.badResponse(statusCode: httpResponse.statusCode)
        }
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw SensorClientError.decodingFailed
        }
    }

    private func pairingRequestVoid(baseURL: URL, endpoint: Endpoint) async throws {
        let urlRequest = endpoint.urlRequest(baseURL: baseURL)
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

    public func fetchChallenge(baseURL: URL) async throws -> ChallengeResponse {
        try await pairingRequest(baseURL: baseURL, endpoint: .pairingChallenge)
    }

    public func postVerify(baseURL: URL, body: VerifyRequest) async throws -> VerifyResponse {
        try await pairingRequest(baseURL: baseURL, endpoint: .pairingVerify(body: body))
    }

    public func postComplete(baseURL: URL, body: CompleteRequest) async throws -> CompleteResponse {
        try await pairingRequest(baseURL: baseURL, endpoint: .pairingComplete(body: body))
    }

    public func deleteUnpair(baseURL: URL, id: Int) async throws {
        try await pairingRequestVoid(baseURL: baseURL, endpoint: .unpair(id: id))
    }
}

// MARK: - PairingError

public enum PairingError: Error, LocalizedError, Sendable {
    case noHostResolved
    case decryptionFailed(String)
    case invalidCertificateData
    case keychainStoreFailed(String)

    public var errorDescription: String? {
        switch self {
        case .noHostResolved:
            return "Could not resolve host and port from discovered sensor"
        case .decryptionFailed(let detail):
            return "Decryption failed: \(detail)"
        case .invalidCertificateData:
            return "Invalid certificate data received from sensor"
        case .keychainStoreFailed(let detail):
            return "Failed to store credentials in Keychain: \(detail)"
        }
    }
}

// MARK: - PairingManager

/// All public methods must be called from the main actor.
/// Full @MainActor isolation deferred to Phase 3 (NWBrowser callbacks require careful actor hopping).
@Observable
public final class PairingManager: @unchecked Sendable {

    // MARK: - Nested Types

    public struct DiscoveredSensor: Sendable, Identifiable {
        public let id: UUID
        public let name: String
        public let endpoint: NWEndpoint
        public let host: String?
        public let port: UInt16?

        public init(
            id: UUID = UUID(),
            name: String,
            endpoint: NWEndpoint,
            host: String? = nil,
            port: UInt16? = nil
        ) {
            self.id = id
            self.name = name
            self.endpoint = endpoint
            self.host = host
            self.port = port
        }
    }

    public struct PairedSensor: Sendable, Codable {
        public let id: Int
        public let name: String
        public let baseURL: URL
        public let certFingerprint: String

        public init(id: Int, name: String, baseURL: URL, certFingerprint: String) {
            self.id = id
            self.name = name
            self.baseURL = baseURL
            self.certFingerprint = certFingerprint
        }
    }

    public enum PairingState: Sendable {
        case idle
        case discovering
        case found([DiscoveredSensor])
        case pairing
        case paired(PairedSensor)
        case error(String)
    }

    // MARK: - Public Properties

    public private(set) var state: PairingState = .idle
    public private(set) var discoveredSensors: [DiscoveredSensor] = []

    // MARK: - Private Properties

    private let client: any PairingClientProtocol
    private var browser: NWBrowser?
    private var browserStateHandler: ((NWBrowser.State) -> Void)?

    // MARK: - Init

    public init(client: any PairingClientProtocol) {
        self.client = client
    }

    // MARK: - Discovery

    /// Start mDNS discovery for SquirrelOps sensors on the local network.
    public func startDiscovery() {
        stopDiscovery()
        state = .discovering
        discoveredSensors = []

        let parameters = NWParameters()
        parameters.includePeerToPeer = true

        let browser = NWBrowser(
            for: .bonjour(type: "_squirrelops._tcp", domain: nil),
            using: parameters
        )

        browser.stateUpdateHandler = { [weak self] newState in
            guard let self else { return }
            switch newState {
            case .failed:
                self.state = .error("mDNS browser failed")
            case .cancelled:
                break
            default:
                break
            }
        }

        browser.browseResultsChangedHandler = { [weak self] results, _ in
            guard let self else { return }
            var sensors: [DiscoveredSensor] = []
            for result in results {
                let name: String
                if case .service(let n, _, _, _) = result.endpoint {
                    name = n
                } else {
                    name = "Unknown Sensor"
                }

                var host: String?
                var port: UInt16?
                if case .hostPort(let h, let p) = result.endpoint {
                    host = "\(h)"
                    port = p.rawValue
                }

                sensors.append(DiscoveredSensor(
                    name: name,
                    endpoint: result.endpoint,
                    host: host,
                    port: port
                ))
            }
            self.discoveredSensors = sensors
            if sensors.isEmpty {
                self.state = .discovering
            } else {
                self.state = .found(sensors)
            }
        }

        browser.start(queue: .main)
        self.browser = browser
    }

    /// Stop mDNS discovery.
    public func stopDiscovery() {
        browser?.cancel()
        browser = nil
    }

    // MARK: - Pairing

    /// Execute the full pairing challenge-response protocol with a discovered sensor.
    ///
    /// Flow:
    /// 1. Resolve host:port from DiscoveredSensor
    /// 2. GET challenge
    /// 3. HMAC(challenge, code)
    /// 4. Generate 32-byte client nonce
    /// 5. POST verify with HMAC hex + client nonce hex + client name
    /// 6. Derive shared key via HKDF
    /// 7. Decrypt CA cert from verify response
    /// 8. Generate Ed25519 key pair, encrypt public key as CSR
    /// 9. POST complete with encrypted CSR
    /// 10. Decrypt client cert
    /// 11. Store CA + client cert + private key in Keychain
    /// 12. Return PairedSensor
    public func pair(sensor: DiscoveredSensor, code: String) async throws -> PairedSensor {
        state = .pairing

        do {
            let result = try await executePairing(sensor: sensor, code: code)
            state = .paired(result)
            try? PairingManager.savePairedSensor(result)
            return result
        } catch {
            state = .error(error.localizedDescription)
            throw error
        }
    }

    private func executePairing(sensor: DiscoveredSensor, code: String) async throws -> PairedSensor {
        // Step 1: Resolve host and port
        let (host, port) = await resolveHostPort(sensor: sensor)
        guard let host, let port else {
            throw PairingError.noHostResolved
        }
        guard let baseURL = URL(string: "https://\(host):\(port)") else {
            throw PairingError.noHostResolved
        }

        // Step 2: GET challenge
        let challengeResponse = try await client.fetchChallenge(baseURL: baseURL)

        // Step 3: Compute HMAC(challenge, code)
        let challengeData = try PairingCrypto.hexDecode(challengeResponse.challenge)
        let hmac = PairingCrypto.computeHMAC(challenge: challengeData, code: code)
        let hmacHex = PairingCrypto.hexEncode(hmac)

        // Step 4: Generate 32-byte client nonce
        var clientNonce = Data(count: 32)
        clientNonce.withUnsafeMutableBytes { buffer in
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, buffer.baseAddress!)
        }
        let clientNonceHex = PairingCrypto.hexEncode(clientNonce)

        // Step 5: POST verify
        let clientName = Host.current().localizedName ?? "SquirrelOps Mac"
        let verifyBody = VerifyRequest(
            response: hmacHex,
            clientNonce: clientNonceHex,
            clientName: clientName
        )
        let verifyResponse = try await client.postVerify(baseURL: baseURL, body: verifyBody)

        // Step 6: Derive shared key via HKDF (must match sensor parameters)
        let sharedKey = PairingCrypto.deriveSharedKey(
            code: code,
            challenge: challengeData,
            clientNonce: clientNonce,
            sensorId: challengeResponse.sensorId
        )

        // Step 7: Decrypt CA cert (sensor sends hex-encoded nonce + ciphertext)
        let encryptedCaCertData: Data
        do {
            encryptedCaCertData = try PairingCrypto.hexDecode(verifyResponse.encryptedCaCert)
        } catch {
            throw PairingError.invalidCertificateData
        }
        let caCertData: Data
        do {
            caCertData = try PairingCrypto.decrypt(data: encryptedCaCertData, key: sharedKey)
        } catch {
            throw PairingError.decryptionFailed("CA certificate: \(error.localizedDescription)")
        }

        // Step 8: Generate P-256 key pair and create a PEM CSR
        let privateKey = P256.Signing.PrivateKey()
        let csrPem = PairingCrypto.generateCSR(privateKey: privateKey, commonName: clientName)

        let encryptedCsr: Data
        do {
            encryptedCsr = try PairingCrypto.encrypt(data: Data(csrPem.utf8), key: sharedKey)
        } catch {
            throw PairingError.decryptionFailed("CSR encryption: \(error.localizedDescription)")
        }
        let encryptedCsrHex = PairingCrypto.hexEncode(encryptedCsr)

        // Step 9: POST complete
        let completeBody = CompleteRequest(encryptedCsr: encryptedCsrHex)
        let completeResponse = try await client.postComplete(baseURL: baseURL, body: completeBody)

        // Step 10: Decrypt client cert (sensor sends hex-encoded nonce + ciphertext)
        let encryptedClientCertData: Data
        do {
            encryptedClientCertData = try PairingCrypto.hexDecode(completeResponse.encryptedClientCert)
        } catch {
            throw PairingError.invalidCertificateData
        }
        let clientCertData: Data
        do {
            clientCertData = try PairingCrypto.decrypt(data: encryptedClientCertData, key: sharedKey)
        } catch {
            throw PairingError.decryptionFailed("Client certificate: \(error.localizedDescription)")
        }

        // Step 11: Store CA + client cert + private key in Keychain
        let sensorIdInt = Int(challengeResponse.sensorId) ?? challengeResponse.sensorId.hashValue
        let caLabel = "io.squirrelops.home.ca.\(sensorIdInt)"
        let clientLabel = "io.squirrelops.home.client.\(sensorIdInt)"
        let privateKeyAccount = "io.squirrelops.home.key.\(sensorIdInt)"

        do {
            try KeychainStore.storeCertificate(caCertData, label: caLabel)
            try KeychainStore.storeCertificate(clientCertData, label: clientLabel)
            try KeychainStore.storePassword(
                PairingCrypto.hexEncode(privateKey.x963Representation),
                account: privateKeyAccount
            )
        } catch {
            throw PairingError.keychainStoreFailed(error.localizedDescription)
        }

        // Compute cert fingerprint (SHA-256 of DER-encoded certificate)
        // clientCertData is PEM — strip headers and base64-decode to get DER
        let pemString = String(data: clientCertData, encoding: .utf8) ?? ""
        let base64Only = pemString
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
        let derData = Data(base64Encoded: base64Only) ?? clientCertData
        let fingerprint = SHA256.hash(data: derData)
        let fingerprintHex = fingerprint.map { String(format: "%02x", $0) }.joined()
        let certFingerprint = "sha256:\(fingerprintHex)"

        // Step 12: Return PairedSensor
        return PairedSensor(
            id: sensorIdInt,
            name: challengeResponse.sensorName,
            baseURL: baseURL,
            certFingerprint: certFingerprint
        )
    }

    // MARK: - Unpair

    /// Unpair from a sensor: DELETE on the sensor API, then clean up Keychain entries.
    public func unpair(sensor: PairedSensor) async throws {
        try await client.deleteUnpair(baseURL: sensor.baseURL, id: sensor.id)

        // Clean up Keychain entries
        let caLabel = "io.squirrelops.home.ca.\(sensor.id)"
        let clientLabel = "io.squirrelops.home.client.\(sensor.id)"
        let privateKeyAccount = "io.squirrelops.home.key.\(sensor.id)"

        try KeychainStore.deleteCertificate(label: caLabel)
        try KeychainStore.deleteCertificate(label: clientLabel)
        try KeychainStore.deletePassword(account: privateKeyAccount)

        try? PairingManager.deletePairedSensor()
        state = .idle
    }

    // MARK: - Persistence

    private static let pairedSensorAccount = "io.squirrelops.home.paired-sensor"

    /// Save a paired sensor to the Keychain for persistence across launches.
    public static func savePairedSensor(_ sensor: PairedSensor) throws {
        let data = try JSONEncoder().encode(sensor)
        let json = String(data: data, encoding: .utf8)!
        try KeychainStore.storePassword(json, account: pairedSensorAccount)
    }

    /// Load the paired sensor from the Keychain. Returns nil if not found.
    public static func loadPairedSensor() -> PairedSensor? {
        guard let json = try? KeychainStore.loadPassword(account: pairedSensorAccount) else {
            return nil
        }
        guard let data = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(PairedSensor.self, from: data)
    }

    /// Delete the paired sensor from the Keychain.
    public static func deletePairedSensor() throws {
        try KeychainStore.deletePassword(account: pairedSensorAccount)
    }

    // MARK: - Helpers

    private func resolveHostPort(sensor: DiscoveredSensor) async -> (String?, UInt16?) {
        // Prefer explicit host/port if available
        if let host = sensor.host, let port = sensor.port {
            return (host, port)
        }

        // Try extracting from NWEndpoint
        if case .hostPort(let h, let p) = sensor.endpoint {
            return ("\(h)", p.rawValue)
        }

        // Resolve .service endpoints via NetService
        if case .service(let name, let type, let domain, _) = sensor.endpoint {
            return await MainActor.run {
                let resolver = ServiceResolver(name: name, type: type, domain: domain)
                return resolver
            }.resolve()
        }

        return (nil, nil)
    }
}
