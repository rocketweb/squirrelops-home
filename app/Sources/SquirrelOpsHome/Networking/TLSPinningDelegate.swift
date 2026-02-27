import Foundation
import Security

/// URLSession delegate that pins TLS against a CA certificate stored in Keychain.
///
/// During pairing (no CA stored yet), accepts any server certificate (TOFU).
/// After pairing, validates the server certificate chain against the pinned CA.
public final class TLSPinningDelegate: NSObject, URLSessionDelegate, Sendable {

    private let caCertData: Data?

    /// Initialize with optional CA cert DER data for pinning.
    /// Pass `nil` to accept any server cert (TOFU mode for pairing).
    public init(caCertData: Data? = nil) {
        self.caCertData = caCertData
    }

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
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

        // Pin against stored CA cert
        guard let caCert = SecCertificateCreateWithData(nil, caCertData as CFData) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

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
