import Foundation
import Security
import Testing

@testable import SquirrelOpsHome

@Suite("KeychainStore", .serialized)
struct KeychainStoreTests {
    private func uniqueLabel(_ prefix: String) -> String {
        "\(prefix)-\(UUID().uuidString)"
    }

    @Test("Local test builds isolate credentials by build identifier")
    func localTestBuildUsesIsolatedService() {
        let buildID = "d6507fce-0d20-4d23-94ad-2ce17dd80130"

        #expect(
            KeychainStore.serviceName(localTestMarker: buildID)
                == "io.squirrelops.home.local-test.d6507fce0d204d2394ad2ce17dd80130"
        )
        #expect(
            KeychainStore.serviceName(localTestMarker: nil)
                == "io.squirrelops.home"
        )
        #expect(
            KeychainStore.serviceName(localTestMarker: "not-a-uuid")
                == "io.squirrelops.home"
        )
    }

    // MARK: - Password Tests

    @Test("Store and load password round-trip")
    func storeAndLoadPassword() throws {
        let account = uniqueLabel("test-password-round-trip")
        defer { try? KeychainStore.deletePassword(account: account) }

        let original = "s3cret-p@ssw0rd-\(account)"
        try KeychainStore.storePassword(original, account: account)
        let loaded = try KeychainStore.loadPassword(account: account)

        #expect(loaded == original)
    }

    @Test("Load nonexistent password throws itemNotFound")
    func loadNonexistentPasswordThrows() {
        let account = uniqueLabel("nonexistent-password")

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
        let account = uniqueLabel("test-password-delete")
        let original = "delete-me-\(account)"
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
        let account = uniqueLabel("test-password-update")
        defer { try? KeychainStore.deletePassword(account: account) }

        try KeychainStore.storePassword("first-value", account: account)
        try KeychainStore.storePassword("updated-value", account: account)

        let loaded = try KeychainStore.loadPassword(account: account)
        #expect(loaded == "updated-value")
    }

    // MARK: - Certificate Tests

    @Test("Store and load certificate DER data round-trip")
    func storeAndLoadCertificateData() throws {
        let label = uniqueLabel("test-certificate-round-trip")
        defer { try? KeychainStore.deleteCertificate(label: label) }

        let testData = Data("test-certificate-der-data-\(label)".utf8)
        try KeychainStore.storeCertificate(testData, label: label)

        let loaded = try KeychainStore.loadCertificateData(label: label)
        #expect(loaded == testData)
    }

    @Test("Delete certificate ignores itemNotFound")
    func deleteCertificateIgnoresNotFound() throws {
        try KeychainStore.deleteCertificate(
            label: uniqueLabel("nonexistent-certificate")
        )
    }

    // MARK: - Client Identity Key Tests

    @Test("Create client private key stores discoverable Keychain key")
    func createClientPrivateKeyStoresDiscoverableKey() throws {
        let privateKeyLabel = uniqueLabel("test-client-key")
        let certificateLabel = uniqueLabel("test-client-cert")
        defer {
            try? KeychainStore.deleteClientIdentity(
                certificateLabel: certificateLabel,
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
