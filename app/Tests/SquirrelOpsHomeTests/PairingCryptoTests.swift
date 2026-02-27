import CryptoKit
import Foundation
import Testing

@testable import SquirrelOpsHome

@Suite("PairingCrypto")
struct PairingCryptoTests {

    // MARK: - HMAC

    @Test("HMAC produces deterministic output for same inputs")
    func hmacDeterministic() {
        let challenge = Data("test-challenge-123".utf8)
        let code = "482910"
        let result1 = PairingCrypto.computeHMAC(challenge: challenge, code: code)
        let result2 = PairingCrypto.computeHMAC(challenge: challenge, code: code)
        #expect(result1 == result2)
        #expect(result1.count == 32)
    }

    @Test("HMAC produces different output for different codes")
    func hmacDifferentCodes() {
        let challenge = Data("same-challenge".utf8)
        let result1 = PairingCrypto.computeHMAC(challenge: challenge, code: "111111")
        let result2 = PairingCrypto.computeHMAC(challenge: challenge, code: "222222")
        #expect(result1 != result2)
    }

    @Test("HMAC produces different output for different challenges")
    func hmacDifferentChallenges() {
        let code = "482910"
        let result1 = PairingCrypto.computeHMAC(challenge: Data("challenge-a".utf8), code: code)
        let result2 = PairingCrypto.computeHMAC(challenge: Data("challenge-b".utf8), code: code)
        #expect(result1 != result2)
    }

    // MARK: - HKDF

    @Test("HKDF produces deterministic key for same inputs")
    func hkdfDeterministic() {
        let code = "482910"
        let challenge = Data(repeating: 0xCC, count: 32)
        let clientNonce = Data(repeating: 0xAA, count: 32)
        let sensorId = "test-sensor-1"
        let key1 = PairingCrypto.deriveSharedKey(code: code, challenge: challenge, clientNonce: clientNonce, sensorId: sensorId)
        let key2 = PairingCrypto.deriveSharedKey(code: code, challenge: challenge, clientNonce: clientNonce, sensorId: sensorId)
        let key1Data = key1.withUnsafeBytes { Data($0) }
        let key2Data = key2.withUnsafeBytes { Data($0) }
        #expect(key1Data == key2Data)
        #expect(key1Data.count == 32)
    }

    @Test("HKDF produces different keys for different codes")
    func hkdfDifferentCodes() {
        let challenge = Data(repeating: 0xCC, count: 32)
        let clientNonce = Data(repeating: 0xAA, count: 32)
        let sensorId = "test-sensor-1"
        let key1 = PairingCrypto.deriveSharedKey(code: "111111", challenge: challenge, clientNonce: clientNonce, sensorId: sensorId)
        let key2 = PairingCrypto.deriveSharedKey(code: "222222", challenge: challenge, clientNonce: clientNonce, sensorId: sensorId)
        let key1Data = key1.withUnsafeBytes { Data($0) }
        let key2Data = key2.withUnsafeBytes { Data($0) }
        #expect(key1Data != key2Data)
    }

    // MARK: - Encrypt / Decrypt

    @Test("Encrypt and decrypt round-trip")
    func encryptDecryptRoundTrip() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data("Hello, SquirrelOps!".utf8)
        let encrypted = try PairingCrypto.encrypt(data: plaintext, key: key)
        let decrypted = try PairingCrypto.decrypt(data: encrypted, key: key)
        #expect(decrypted == plaintext)
    }

    @Test("Encrypted output contains nonce + ciphertext + tag")
    func encryptedOutputStructure() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data("test".utf8)
        let encrypted = try PairingCrypto.encrypt(data: plaintext, key: key)
        #expect(encrypted.count == 12 + plaintext.count + 16)
    }

    @Test("Encrypt produces different output each time")
    func encryptProducesDifferentOutput() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data("same-plaintext".utf8)
        let encrypted1 = try PairingCrypto.encrypt(data: plaintext, key: key)
        let encrypted2 = try PairingCrypto.encrypt(data: plaintext, key: key)
        #expect(encrypted1 != encrypted2)
    }

    @Test("Decrypt with wrong key throws")
    func decryptWithWrongKeyThrows() throws {
        let correctKey = SymmetricKey(size: .bits256)
        let wrongKey = SymmetricKey(size: .bits256)
        let plaintext = Data("secret data".utf8)
        let encrypted = try PairingCrypto.encrypt(data: plaintext, key: correctKey)
        #expect(throws: (any Error).self) {
            _ = try PairingCrypto.decrypt(data: encrypted, key: wrongKey)
        }
    }

    @Test("Decrypt with truncated data throws")
    func decryptWithTruncatedDataThrows() {
        let key = SymmetricKey(size: .bits256)
        let tooShort = Data(repeating: 0x00, count: 10)
        #expect(throws: (any Error).self) {
            _ = try PairingCrypto.decrypt(data: tooShort, key: key)
        }
    }

    // MARK: - Hex Encode / Decode

    @Test("hexEncode and hexDecode round-trip")
    func hexRoundTrip() throws {
        let original = Data([0x00, 0x0A, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF])
        let hex = PairingCrypto.hexEncode(original)
        let decoded = try PairingCrypto.hexDecode(hex)
        #expect(decoded == original)
    }

    @Test("hexEncode produces lowercase hex string")
    func hexEncodeLowercase() {
        let data = Data([0xAB, 0xCD, 0xEF])
        #expect(PairingCrypto.hexEncode(data) == "abcdef")
    }

    @Test("hexDecode handles uppercase input")
    func hexDecodeUppercase() throws {
        #expect(try PairingCrypto.hexDecode("ABCDEF") == Data([0xAB, 0xCD, 0xEF]))
    }

    @Test("hexDecode throws on odd-length string")
    func hexDecodeOddLengthThrows() {
        #expect(throws: (any Error).self) { _ = try PairingCrypto.hexDecode("abc") }
    }

    @Test("hexDecode throws on invalid characters")
    func hexDecodeInvalidCharsThrows() {
        #expect(throws: (any Error).self) { _ = try PairingCrypto.hexDecode("xyz123") }
    }

    @Test("hexEncode of empty data returns empty string")
    func hexEncodeEmptyData() {
        #expect(PairingCrypto.hexEncode(Data()) == "")
    }

    @Test("hexDecode of empty string returns empty data")
    func hexDecodeEmptyString() throws {
        #expect(try PairingCrypto.hexDecode("") == Data())
    }
}
