import Foundation
import Security

// MARK: - KeychainError

public enum KeychainError: Error, LocalizedError {
    case duplicateItem
    case itemNotFound
    case unexpectedStatus(OSStatus)
    case invalidData
    case certificateCreationFailed
    case identityCreationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .duplicateItem:
            return "Keychain item already exists"
        case .itemNotFound:
            return "Keychain item not found"
        case .unexpectedStatus(let status):
            return "Unexpected Keychain status: \(status)"
        case .invalidData:
            return "Invalid data retrieved from Keychain"
        case .certificateCreationFailed:
            return "Failed to create certificate from stored data"
        case .identityCreationFailed(let reason):
            return "Failed to create client certificate identity: \(reason)"
        }
    }
}

// MARK: - KeychainStore

public struct KeychainStore {
    private static let service = "io.squirrelops.home"

    private static func certificateDERData(from data: Data) -> Data? {
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

    private static func keyApplicationTag(_ label: String) -> Data {
        Data("io.squirrelops.home.identity.\(label)".utf8)
    }

    // MARK: - Certificate Data Operations (stored as generic password for reliability)

    /// Store DER-encoded certificate data in the Keychain as a generic password item.
    /// On duplicate, updates the existing item.
    public static func storeCertificate(_ derData: Data, label: String) throws {
        // Store as generic password for reliability in testing/CI
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service + ".cert",
            kSecAttrAccount as String: label,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: derData,
        ]

        var status = SecItemAdd(query as CFDictionary, nil)

        if status == errSecDuplicateItem {
            let searchQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service + ".cert",
                kSecAttrAccount as String: label,
            ]
            let updateAttrs: [String: Any] = [
                kSecValueData as String: derData,
            ]
            status = SecItemUpdate(searchQuery as CFDictionary, updateAttrs as CFDictionary)
        }

        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    /// Load certificate DER data from the Keychain by label.
    public static func loadCertificateData(label: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service + ".cert",
            kSecAttrAccount as String: label,
            kSecReturnData as String: true,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw KeychainError.itemNotFound
            }
            throw KeychainError.unexpectedStatus(status)
        }

        guard let data = result as? Data else {
            throw KeychainError.invalidData
        }

        return data
    }

    /// Delete a certificate from the Keychain by label.
    /// Silently ignores itemNotFound errors.
    public static func deleteCertificate(label: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service + ".cert",
            kSecAttrAccount as String: label,
        ]

        let status = SecItemDelete(query as CFDictionary)

        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    // MARK: - Client Certificate Identity Operations

    /// Generate and store a P-256 client private key that can later be paired
    /// with the signed client certificate as a SecIdentity.
    public static func createClientPrivateKey(privateKeyLabel: String) throws -> SecKey {
        let keyTag = keyApplicationTag(privateKeyLabel)
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
        ]
        let deleteStatus = SecItemDelete(keyQuery as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(deleteStatus)
        }

        let keyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrLabel as String: privateKeyLabel,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        var keyError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(keyAttributes as CFDictionary, &keyError) else {
            let reason = keyError?.takeRetainedValue().localizedDescription ?? "unknown key generation error"
            throw KeychainError.identityCreationFailed(reason)
        }
        return privateKey
    }

    /// Store a paired client certificate and return the Keychain identity that
    /// combines it with an existing permanent private key.
    @discardableResult
    public static func storeClientIdentity(
        certificateData: Data,
        certificateLabel: String,
        privateKeyLabel: String
    ) throws -> SecIdentity {
        let keyLookupQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyApplicationTag(privateKeyLabel),
            kSecReturnRef as String: true,
        ]
        var keyResult: AnyObject?
        let keyLookupStatus = SecItemCopyMatching(keyLookupQuery as CFDictionary, &keyResult)
        guard keyLookupStatus == errSecSuccess else {
            throw KeychainError.unexpectedStatus(keyLookupStatus)
        }

        guard let derData = certificateDERData(from: certificateData),
              let certificate = SecCertificateCreateWithData(nil, derData as CFData) else {
            throw KeychainError.certificateCreationFailed
        }

        let certificateQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: certificateLabel,
        ]
        let certificateDeleteStatus = SecItemDelete(certificateQuery as CFDictionary)
        guard certificateDeleteStatus == errSecSuccess || certificateDeleteStatus == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(certificateDeleteStatus)
        }

        let certificateAddQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: certificateLabel,
            kSecValueRef as String: certificate,
        ]
        let certificateAddStatus = SecItemAdd(certificateAddQuery as CFDictionary, nil)
        guard certificateAddStatus == errSecSuccess || certificateAddStatus == errSecDuplicateItem else {
            throw KeychainError.unexpectedStatus(certificateAddStatus)
        }

        var identity: SecIdentity?
        let identityStatus = SecIdentityCreateWithCertificate(nil, certificate, &identity)
        guard identityStatus == errSecSuccess, let identity else {
            throw KeychainError.unexpectedStatus(identityStatus)
        }
        return identity
    }

    /// Load a paired client certificate identity for URLSession mTLS.
    public static func loadClientIdentity(
        certificateLabel: String,
        privateKeyLabel: String
    ) throws -> SecIdentity {
        let certificateData = try loadCertificateData(label: certificateLabel)
        return try storeClientIdentity(
            certificateData: certificateData,
            certificateLabel: certificateLabel,
            privateKeyLabel: privateKeyLabel
        )
    }

    /// Delete Keychain certificate/key material used for a client identity.
    public static func deleteClientIdentity(
        certificateLabel: String,
        privateKeyLabel: String
    ) throws {
        let certificateQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: certificateLabel,
        ]
        let certificateStatus = SecItemDelete(certificateQuery as CFDictionary)
        if certificateStatus != errSecSuccess && certificateStatus != errSecItemNotFound {
            throw KeychainError.unexpectedStatus(certificateStatus)
        }

        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyApplicationTag(privateKeyLabel),
        ]
        let keyStatus = SecItemDelete(keyQuery as CFDictionary)
        if keyStatus != errSecSuccess && keyStatus != errSecItemNotFound {
            throw KeychainError.unexpectedStatus(keyStatus)
        }
    }

    // MARK: - Password Operations

    /// Store a generic password in the Keychain.
    /// On duplicate, updates the existing item.
    public static func storePassword(_ password: String, account: String) throws {
        guard let passwordData = password.data(using: .utf8) else {
            throw KeychainError.invalidData
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: passwordData,
        ]

        var status = SecItemAdd(query as CFDictionary, nil)

        if status == errSecDuplicateItem {
            let searchQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
            ]
            let updateAttrs: [String: Any] = [
                kSecValueData as String: passwordData,
            ]
            status = SecItemUpdate(searchQuery as CFDictionary, updateAttrs as CFDictionary)
        }

        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    /// Load a generic password from the Keychain.
    public static func loadPassword(account: String) throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw KeychainError.itemNotFound
            }
            throw KeychainError.unexpectedStatus(status)
        }

        guard let data = result as? Data,
              let password = String(data: data, encoding: .utf8) else {
            throw KeychainError.invalidData
        }

        return password
    }

    /// Delete a generic password from the Keychain.
    /// Silently ignores itemNotFound errors.
    public static func deletePassword(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]

        let status = SecItemDelete(query as CFDictionary)

        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeychainError.unexpectedStatus(status)
        }
    }
}
