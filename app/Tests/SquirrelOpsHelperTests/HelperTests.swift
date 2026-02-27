import Testing
@testable import SquirrelOpsHelper

@Suite("SquirrelOpsHelper")
struct HelperTests {
    @Test("Module imports successfully")
    func moduleImports() {
        #expect(true, "SquirrelOpsHelper module imported successfully")
    }
}
