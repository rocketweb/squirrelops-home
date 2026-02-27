import CryptoKit
import Foundation
import Security

// MARK: - PairingCryptoError

public enum PairingCryptoError: Error, LocalizedError {
    case invalidHexString
    case decryptionFailed
    case dataTooShort

    public var errorDescription: String? {
        switch self {
        case .invalidHexString:
            return "Invalid hexadecimal string"
        case .decryptionFailed:
            return "AES-GCM decryption failed"
        case .dataTooShort:
            return "Encrypted data is too short to contain nonce and ciphertext"
        }
    }
}

// MARK: - PairingCrypto

public enum PairingCrypto {

    /// Compute HMAC-SHA256 of the challenge using the pairing code as the key.
    public static func computeHMAC(challenge: Data, code: String) -> Data {
        let key = SymmetricKey(data: Data(code.utf8))
        let mac = HMAC<SHA256>.authenticationCode(for: challenge, using: key)
        return Data(mac)
    }

    /// Derive a shared symmetric key using HKDF-SHA256.
    /// Must match sensor: IKM = code + challenge + clientNonce, salt = sensorId, info = "squirrelops-pairing-v1"
    public static func deriveSharedKey(
        code: String,
        challenge: Data,
        clientNonce: Data,
        sensorId: String
    ) -> SymmetricKey {
        let ikm = Data(code.utf8) + challenge + clientNonce
        let inputKeyMaterial = SymmetricKey(data: ikm)
        let salt = Data(sensorId.utf8)
        let info = Data("squirrelops-pairing-v1".utf8)

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: info,
            outputByteCount: 32
        )
    }

    /// Encrypt data using AES-GCM.
    /// Returns: nonce (12 bytes) + ciphertext + tag (16 bytes).
    public static func encrypt(data: Data, key: SymmetricKey) throws -> Data {
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(data, using: key, nonce: nonce)
        guard let combined = sealedBox.combined else {
            throw PairingCryptoError.decryptionFailed
        }
        return combined
    }

    /// Decrypt AES-GCM encrypted data (nonce + ciphertext + tag).
    public static func decrypt(data: Data, key: SymmetricKey) throws -> Data {
        guard data.count >= 28 else { // 12 nonce + 16 tag minimum
            throw PairingCryptoError.dataTooShort
        }
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }

    /// Encode data as a lowercase hexadecimal string.
    public static func hexEncode(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    /// Generate a minimal DER-encoded PKCS#10 CSR signed with P-256/SHA-256.
    public static func generateCSR(privateKey: P256.Signing.PrivateKey, commonName: String) -> String {
        // Build the Subject DN (CN only)
        let cnOID: [UInt8] = [0x55, 0x04, 0x03] // 2.5.4.3
        let cnValue = derUTF8String(Array(commonName.utf8))
        let atv = derSequence(derOID(cnOID) + cnValue)
        let rdn = derSet(atv)
        let subject = derSequence(rdn)

        // SubjectPublicKeyInfo for P-256
        let ecOID: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01] // 1.2.840.10045.2.1
        let p256OID: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07] // 1.2.840.10045.3.1.7
        let algId = derSequence(derOID(ecOID) + derOID(p256OID))
        let pubKeyBytes = [UInt8](privateKey.publicKey.x963Representation)
        let pubKeyBitString = derBitString(pubKeyBytes)
        let spki = derSequence(algId + pubKeyBitString)

        // CertificationRequestInfo
        // CertificationRequestInfo: version 0, subject, SPKI, empty attributes
        let certReqInfo = derSequence([0x02, 0x01, 0x00] + subject + spki + [0xA0, 0x00])

        // Sign with SHA-256
        let signature = try! privateKey.signature(for: certReqInfo)
        let sigBytes = [UInt8](signature.derRepresentation)

        // Signature algorithm: ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
        let sigAlgOID: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
        let sigAlg = derSequence(derOID(sigAlgOID))
        let sigBitString = derBitString(sigBytes)

        let csr = derSequence(certReqInfo + sigAlg + sigBitString)

        // PEM encode
        let b64 = Data(csr).base64EncodedString(options: .lineLength64Characters)
        return "-----BEGIN CERTIFICATE REQUEST-----\n\(b64)\n-----END CERTIFICATE REQUEST-----\n"
    }

    // MARK: - DER Encoding Helpers

    private static func derLength(_ length: Int) -> [UInt8] {
        if length < 0x80 { return [UInt8(length)] }
        if length < 0x100 { return [0x81, UInt8(length)] }
        return [0x82, UInt8(length >> 8), UInt8(length & 0xFF)]
    }

    private static func derSequence(_ content: [UInt8]) -> [UInt8] {
        [0x30] + derLength(content.count) + content
    }

    private static func derSet(_ content: [UInt8]) -> [UInt8] {
        [0x31] + derLength(content.count) + content
    }

    private static func derOID(_ oid: [UInt8]) -> [UInt8] {
        [0x06, UInt8(oid.count)] + oid
    }

    private static func derUTF8String(_ content: [UInt8]) -> [UInt8] {
        [0x0C] + derLength(content.count) + content
    }

    private static func derBitString(_ content: [UInt8]) -> [UInt8] {
        // Prepend 0x00 (no unused bits)
        let wrapped = [UInt8(0)] + content
        return [0x03] + derLength(wrapped.count) + wrapped
    }

    private static func derExplicit(tag: UInt8, content: [UInt8]) -> [UInt8] {
        [0xA0 | tag] + derLength(content.count) + content
    }

    /// Decode a hexadecimal string to Data.
    public static func hexDecode(_ hex: String) throws -> Data {
        guard hex.count % 2 == 0 else {
            throw PairingCryptoError.invalidHexString
        }
        if hex.isEmpty { return Data() }

        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex

        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else {
                throw PairingCryptoError.invalidHexString
            }
            data.append(byte)
            index = nextIndex
        }
        return data
    }
}
