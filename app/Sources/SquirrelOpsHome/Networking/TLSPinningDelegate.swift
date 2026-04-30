import Foundation
import Security

/// URLSession delegate that pins TLS against a CA certificate stored in Keychain.
///
/// During pairing (no CA stored yet), accepts any server certificate (TOFU).
/// After pairing, validates the server certificate chain against the pinned CA.
public final class TLSPinningDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {

    private let caCertData: Data?
    private let clientIdentity: SecIdentity?

    /// Initialize with optional CA cert DER data for pinning.
    /// Pass `nil` to accept any server cert (TOFU mode for pairing).
    public init(caCertData: Data? = nil, clientIdentity: SecIdentity? = nil) {
        self.caCertData = caCertData
        self.clientIdentity = clientIdentity
    }

    static func certificateDERData(from data: Data) -> Data? {
        guard let pem = String(data: data, encoding: .utf8),
              pem.contains("-----BEGIN CERTIFICATE-----") else {
            return data
        }
        let base64 = pem
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: " ", with: "")
        return Data(base64Encoded: base64)
    }

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
            guard let clientIdentity else {
                completionHandler(.performDefaultHandling, nil)
                return
            }
            let credential = URLCredential(
                identity: clientIdentity,
                certificates: nil,
                persistence: .forSession
            )
            completionHandler(.useCredential, credential)
            return
        }

        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        guard let caCertData else {
            // TOFU mode: accept any server cert during pairing
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
            return
        }

        // Pin against stored CA cert. Sensor certificates are generated on
        // local networks where users may connect by mDNS name, LAN IP, or
        // localhost, so this validates the CA chain without hostname binding.
        guard let caDERData = Self.certificateDERData(from: caCertData),
              let caCert = SecCertificateCreateWithData(nil, caDERData as CFData) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        SecTrustSetPolicies(serverTrust, SecPolicyCreateBasicX509())
        SecTrustSetAnchorCertificates(serverTrust, [caCert] as CFArray)
        SecTrustSetAnchorCertificatesOnly(serverTrust, true)

        var error: CFError?
        if SecTrustEvaluateWithError(serverTrust, &error) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
