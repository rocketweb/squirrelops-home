import Testing
@testable import SquirrelOpsHelper

@Suite("SquirrelOpsHelper")
struct HelperTests {
    @Test("Module imports successfully")
    func moduleImports() {
        #expect(true, "SquirrelOpsHelper module imported successfully")
    }

    @Test("Privileged RPC allows only root and the sensor service account")
    func privilegedPeerAuthorization() {
        #expect(isAuthorizedPeer(0, serviceUID: 499))
        #expect(isAuthorizedPeer(499, serviceUID: 499))
        #expect(!isAuthorizedPeer(501, serviceUID: 499))
        #expect(!isAuthorizedPeer(501, serviceUID: nil))
    }
}
