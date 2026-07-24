import Foundation
import Testing
#if canImport(Darwin)
import Darwin
#endif

@testable import SquirrelOpsHelper

@Suite("Helper readiness")
struct HelperReadinessTests {
    @Test("Ping reports the protocol and required network capabilities")
    func pingCapabilities() throws {
        let router = RPCRouter()
        registerMethods(router: router)
        let request = try RPCRequest(
            from: Data(
                """
                {"jsonrpc":"2.0","method":"ping","id":1}
                """.utf8
            )
        )

        let responseData = router.dispatch(request)
        let response = try #require(
            JSONSerialization.jsonObject(with: responseData)
                as? [String: Any]
        )
        let result = try #require(response["result"] as? [String: Any])
        let capabilities = try #require(result["capabilities"] as? [String])

        #expect(result["status"] as? String == "ok")
        #expect(result["protocol_version"] as? Int == 1)
        #expect(capabilities.contains("arp_scan"))
        #expect(capabilities.contains("virtual_ip"))
        #expect(capabilities.contains("port_forward_isolation"))
        #expect(!capabilities.contains("service_scan"))
        #expect(!capabilities.contains("dns_sniff"))
        #expect(!capabilities.contains("bind_listener"))
    }

    @Test("Helper does not expose non-privileged or unimplemented RPCs")
    func falseCapabilityRPCsAreUnavailable() throws {
        let router = RPCRouter()
        registerMethods(router: router)

        for (id, method) in [
            (2, "runServiceScan"),
            (3, "startDNSSniff"),
            (4, "stopDNSSniff"),
            (5, "getDNSQueries"),
        ] {
            let request = try RPCRequest(
                from: Data(
                    """
                    {"jsonrpc":"2.0","method":"\(method)","id":\(id)}
                    """.utf8
                )
            )
            let responseData = router.dispatch(request)
            let response = try #require(
                JSONSerialization.jsonObject(with: responseData)
                    as? [String: Any]
            )
            let error = try #require(response["error"] as? [String: Any])
            #expect(error["code"] as? Int == -32601)
        }
    }

    @Test("Helper does not expose a socket bind RPC without descriptor passing")
    func bindListenerRPCIsUnavailable() throws {
        let router = RPCRouter()
        registerMethods(router: router)
        let request = try RPCRequest(
            from: Data(
                """
                {"jsonrpc":"2.0","method":"bindListener","id":2}
                """.utf8
            )
        )

        let responseData = router.dispatch(request)
        let response = try #require(
            JSONSerialization.jsonObject(with: responseData)
                as? [String: Any]
        )
        let error = try #require(response["error"] as? [String: Any])

        #expect(error["code"] as? Int == -32601)
    }

    @Test("Closed RPC peers cannot terminate the helper with SIGPIPE")
    func closedPeerDoesNotRaiseSIGPIPE() throws {
        var sockets = [Int32](repeating: -1, count: 2)
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
        defer {
            if sockets[0] >= 0 { close(sockets[0]) }
            if sockets[1] >= 0 { close(sockets[1]) }
        }

        #expect(configureNoSigPipe(fd: sockets[0]))
        close(sockets[1])
        sockets[1] = -1

        sendAll(fd: sockets[0], data: Data("response\n".utf8))
    }
}
