import Foundation
import Testing

@testable import SquirrelOpsHelper

@Suite("RPC Server")
struct RPCServerTests {

    // MARK: - Request Parsing

    @Test("Parse valid JSON-RPC request with params")
    func parseValidRequest() throws {
        let json = """
        {"jsonrpc": "2.0", "method": "runARPScan", "params": {"subnet": "192.168.1.0/24"}, "id": 1}
        """.data(using: .utf8)!

        let request = try RPCRequest(from: json)
        #expect(request.id == 1)
        #expect(request.method == "runARPScan")
        #expect(request.params["subnet"] as? String == "192.168.1.0/24")
    }

    @Test("Parse valid request without params")
    func parseRequestNoParams() throws {
        let json = """
        {"jsonrpc": "2.0", "method": "stopDNSSniff", "id": 2}
        """.data(using: .utf8)!

        let request = try RPCRequest(from: json)
        #expect(request.id == 2)
        #expect(request.method == "stopDNSSniff")
        #expect(request.params.isEmpty)
    }

    @Test("Parse request with missing method throws")
    func parseMissingMethodThrows() {
        let json = """
        {"jsonrpc": "2.0", "id": 1}
        """.data(using: .utf8)!

        #expect(throws: RPCError.self) {
            try RPCRequest(from: json)
        }
    }

    @Test("Parse request with missing id throws")
    func parseMissingIdThrows() {
        let json = """
        {"jsonrpc": "2.0", "method": "test"}
        """.data(using: .utf8)!

        #expect(throws: RPCError.self) {
            try RPCRequest(from: json)
        }
    }

    // MARK: - Response Formatting

    @Test("Success response formats correctly")
    func successResponse() throws {
        let data = rpcSuccessResponse(id: 1, result: [["ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF"]])
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        #expect(json["jsonrpc"] as? String == "2.0")
        #expect(json["id"] as? Int == 1)
        #expect(json["result"] != nil)
    }

    @Test("Error response formats correctly")
    func errorResponse() throws {
        let data = rpcErrorResponse(id: 1, error: .methodNotFound("badMethod"))
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let error = json["error"] as! [String: Any]
        #expect(error["code"] as? Int == -32601)
        #expect((error["message"] as? String)?.contains("badMethod") == true)
    }

    // MARK: - Router Dispatch

    @Test("Router dispatches to registered handler")
    func routerDispatches() {
        let router = RPCRouter()
        router.handlers["echo"] = { params in
            return params
        }

        let json = """
        {"jsonrpc": "2.0", "method": "echo", "params": {"msg": "hello"}, "id": 1}
        """.data(using: .utf8)!
        let request = try! RPCRequest(from: json)

        let responseData = router.dispatch(request)
        let response = try! JSONSerialization.jsonObject(with: responseData) as! [String: Any]
        let result = response["result"] as! [String: Any]
        #expect(result["msg"] as? String == "hello")
    }

    @Test("Router returns error for unknown method")
    func routerUnknownMethod() {
        let router = RPCRouter()

        let json = """
        {"jsonrpc": "2.0", "method": "doesNotExist", "id": 1}
        """.data(using: .utf8)!
        let request = try! RPCRequest(from: json)

        let responseData = router.dispatch(request)
        let response = try! JSONSerialization.jsonObject(with: responseData) as! [String: Any]
        #expect(response["error"] != nil)
    }

    @Test("Router returns error when handler throws")
    func routerHandlerThrows() {
        let router = RPCRouter()
        router.handlers["fail"] = { _ in
            throw NSError(domain: "test", code: 1, userInfo: [NSLocalizedDescriptionKey: "boom"])
        }

        let json = """
        {"jsonrpc": "2.0", "method": "fail", "id": 1}
        """.data(using: .utf8)!
        let request = try! RPCRequest(from: json)

        let responseData = router.dispatch(request)
        let response = try! JSONSerialization.jsonObject(with: responseData) as! [String: Any]
        let error = response["error"] as! [String: Any]
        #expect(error["code"] as? Int == -32603)
    }
}
