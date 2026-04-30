import Foundation
import Security
import Testing

@testable import SquirrelOpsHome

@Suite("KeychainStore", .serialized)
struct KeychainStoreTests {

    /// Unique prefix per test run to avoid Keychain collisions.
    private let testID = UUID().uuidString

    private var passwordAccount: String { "test-password-\(testID)" }
    private var certLabel: String { "test-cert-\(testID)" }

    // MARK: - Password Tests

    @Test("Store and load password round-trip")
    func storeAndLoadPassword() throws {
        let account = passwordAccount
        defer { try? KeychainStore.deletePassword(account: account) }

        let original = "s3cret-p@ssw0rd-\(testID)"
        try KeychainStore.storePassword(original, account: account)
        let loaded = try KeychainStore.loadPassword(account: account)

        #expect(loaded == original)
    }

    @Test("Load nonexistent password throws itemNotFound")
    func loadNonexistentPasswordThrows() {
        let account = "nonexistent-\(testID)"

        do {
            _ = try KeychainStore.loadPassword(account: account)
            Issue.record("Expected KeychainError.itemNotFound")
        } catch let error as KeychainError {
            if case .itemNotFound = error {
                // Expected
            } else {
                Issue.record("Expected .itemNotFound, got \(error)")
            }
        } catch {
            Issue.record("Expected KeychainError, got \(error)")
        }
    }

    @Test("Delete removes password item")
    func deleteRemovesPassword() throws {
        let account = passwordAccount
        let original = "delete-me-\(testID)"
        try KeychainStore.storePassword(original, account: account)

        let loaded = try KeychainStore.loadPassword(account: account)
        #expect(loaded == original)

        try KeychainStore.deletePassword(account: account)

        do {
            _ = try KeychainStore.loadPassword(account: account)
            Issue.record("Expected KeychainError.itemNotFound after delete")
        } catch let error as KeychainError {
            if case .itemNotFound = error {
                // Expected
            } else {
                Issue.record("Expected .itemNotFound, got \(error)")
            }
        } catch {
            Issue.record("Expected KeychainError, got \(error)")
        }
    }

    @Test("Store duplicate password updates value")
    func storeDuplicatePasswordUpdates() throws {
        let account = passwordAccount
        defer { try? KeychainStore.deletePassword(account: account) }

        try KeychainStore.storePassword("first-value", account: account)
        try KeychainStore.storePassword("updated-value", account: account)

        let loaded = try KeychainStore.loadPassword(account: account)
        #expect(loaded == "updated-value")
    }

    // MARK: - Certificate Tests

    @Test("Store and load certificate DER data round-trip")
    func storeAndLoadCertificateData() throws {
        let label = certLabel
        defer { try? KeychainStore.deleteCertificate(label: label) }

        let testData = Data("test-certificate-der-data-\(testID)".utf8)
        try KeychainStore.storeCertificate(testData, label: label)

        let loaded = try KeychainStore.loadCertificateData(label: label)
        #expect(loaded == testData)
    }

    @Test("Delete certificate ignores itemNotFound")
    func deleteCertificateIgnoresNotFound() throws {
        try KeychainStore.deleteCertificate(label: "nonexistent-cert-\(testID)")
    }

    // MARK: - Client Identity Key Tests

    @Test("Create client private key stores discoverable Keychain key")
    func createClientPrivateKeyStoresDiscoverableKey() throws {
        let privateKeyLabel = "test-client-key-\(testID)"
        defer {
            try? KeychainStore.deleteClientIdentity(
                certificateLabel: "test-client-cert-\(testID)",
                privateKeyLabel: privateKeyLabel
            )
        }

        let privateKey = try KeychainStore.createClientPrivateKey(privateKeyLabel: privateKeyLabel)
        #expect(SecKeyCopyPublicKey(privateKey) != nil)

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrLabel as String: privateKeyLabel,
            kSecReturnRef as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        #expect(status == errSecSuccess)
        #expect(result != nil)
    }
}
