import Foundation
import Testing

@testable import SquirrelOpsHome

@Suite("TLS Pinning Delegate")
struct TLSPinningDelegateTests {
    @Test("Certificate data accepts DER bytes unchanged")
    func certificateDataAcceptsDER() {
        let der = Data([0x30, 0x03, 0x01, 0x02, 0x03])

        #expect(TLSPinningDelegate.certificateDERData(from: der) == der)
    }

    @Test("Certificate data converts PEM to DER")
    func certificateDataConvertsPEM() throws {
        let pem = """
        -----BEGIN CERTIFICATE-----
        AQIDBA==
        -----END CERTIFICATE-----
        """
        let data = try #require(pem.data(using: .utf8))

        #expect(TLSPinningDelegate.certificateDERData(from: data) == Data([1, 2, 3, 4]))
    }
}
