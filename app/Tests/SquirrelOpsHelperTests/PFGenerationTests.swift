import Foundation
import Testing

@testable import SquirrelOpsHelper

@Suite("PF load generation")
struct PFGenerationTests {
    @Test("An absent generation parses as nil")
    func absentGeneration() throws {
        #expect(try PortForwardGeneration.parse(nil) == nil)
        #expect(try PortForwardGeneration.parse(NSNull()) == nil)
    }

    @Test("A well-formed generation parses")
    func wellFormedGeneration() throws {
        let parsed = try PortForwardGeneration.parse(
            ["nonce": "4f1a9c0b2e7d6a53", "sequence": 12]
        )
        #expect(parsed == PortForwardGeneration(nonce: "4f1a9c0b2e7d6a53", sequence: 12))
        #expect(parsed?.payload["nonce"] as? String == "4f1a9c0b2e7d6a53")
        #expect(parsed?.payload["sequence"] as? Int == 12)
    }

    @Test("Malformed generations are rejected before any mutation")
    func malformedGenerations() {
        let malformed: [Any] = [
            "4f1a9c0b2e7d6a53",
            ["nonce": "4f1a9c0b2e7d6a53"],
            ["sequence": 1],
            ["nonce": "", "sequence": 1],
            ["nonce": String(repeating: "a", count: 65), "sequence": 1],
            ["nonce": "has space", "sequence": 1],
            ["nonce": "ok", "sequence": -1],
            ["nonce": "ok", "sequence": true],
            ["nonce": "ok", "sequence": "7"],
        ]
        for raw in malformed {
            #expect(throws: RPCError.self) {
                try PortForwardGeneration.parse(raw)
            }
        }
    }

    @Test("The ledger reflects only loads the helper applied")
    func ledgerRecordsAppliedLoads() {
        let ledger = PortForwardGenerationLedger()
        #expect(ledger.applied == nil)

        let first = PortForwardGeneration(nonce: "n", sequence: 1)
        ledger.recordApplied(first)
        #expect(ledger.applied == first)

        // A load from a sensor that named no generation leaves live state
        // that matches no named generation.
        ledger.recordApplied(nil)
        #expect(ledger.applied == nil)
    }

    @Test("The router answers the generation query and advertises it")
    func routerAnswersGenerationQuery() throws {
        let router = RPCRouter()
        registerMethods(router: router)

        let ping = try RPCRequest(
            from: Data(#"{"jsonrpc":"2.0","method":"ping","id":1}"#.utf8)
        )
        let pingResponse = try #require(
            JSONSerialization.jsonObject(with: router.dispatch(ping)) as? [String: Any]
        )
        let pingResult = try #require(pingResponse["result"] as? [String: Any])
        let capabilities = try #require(pingResult["capabilities"] as? [String])
        #expect(capabilities.contains("port_forward_generation"))

        let query = try RPCRequest(
            from: Data(#"{"jsonrpc":"2.0","method":"getPortForwardGeneration","id":2}"#.utf8)
        )
        let queryResponse = try #require(
            JSONSerialization.jsonObject(with: router.dispatch(query)) as? [String: Any]
        )
        let queryResult = try #require(queryResponse["result"] as? [String: Any])
        #expect(queryResult["generation"] is NSNull)
    }
}
