import Foundation
import Security

// MARK: - KeychainError

public enum KeychainError: Error, LocalizedError {
    case duplicateItem
    case itemNotFound
    case unexpectedStatus(OSStatus)
    case invalidData
    case certificateCreationFailed

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
        }
    }
}

// MARK: - KeychainStore

public struct KeychainStore {
    private static let service = "io.squirrelops.home"

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
