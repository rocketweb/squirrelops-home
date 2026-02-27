import Foundation

/// JSON-RPC 2.0 request parsed from a line of JSON.
/// Note: @unchecked because [String: Any] is not Sendable, but RPCRequest
/// is immutable (all lets) and only constructed/consumed on the same connection.
struct RPCRequest: @unchecked Sendable {
    let id: Int
    let method: String
    let params: [String: Any]

    init(from data: Data) throws {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let id = json["id"] as? Int,
              let method = json["method"] as? String else {
            throw RPCError.invalidRequest
        }
        self.id = id
        self.method = method
        self.params = (json["params"] as? [String: Any]) ?? [:]
    }
}

/// JSON-RPC 2.0 error codes.
enum RPCError: Error, Equatable {
    case invalidRequest
    case methodNotFound(String)
    case internalError(String)

    var code: Int {
        switch self {
        case .invalidRequest: return -32600
        case .methodNotFound: return -32601
        case .internalError: return -32603
        }
    }

    var message: String {
        switch self {
        case .invalidRequest: return "Invalid Request"
        case .methodNotFound(let method): return "Method not found: \(method)"
        case .internalError(let msg): return msg
        }
    }
}

/// Formats a JSON-RPC 2.0 success response.
func rpcSuccessResponse(id: Int, result: Any) -> Data {
    let response: [String: Any] = [
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    ]
    do {
        var data = try JSONSerialization.data(withJSONObject: response)
        data.append(contentsOf: [0x0A]) // newline
        return data
    } catch {
        return rpcErrorResponse(id: id, error: .internalError("Failed to serialize result: \(error.localizedDescription)"))
    }
}

/// Formats a JSON-RPC 2.0 error response.
func rpcErrorResponse(id: Int?, error: RPCError) -> Data {
    let response: [String: Any] = [
        "jsonrpc": "2.0",
        "id": id as Any,
        "error": [
            "code": error.code,
            "message": error.message,
        ],
    ]
    var data = try! JSONSerialization.data(withJSONObject: response)
    data.append(contentsOf: [0x0A]) // newline
    return data
}

/// A method handler that takes params and returns a result.
typealias RPCMethodHandler = ([String: Any]) throws -> Any

/// RPC method router — maps method names to handlers.
final class RPCRouter: Sendable {
    // Note: handlers are set once at startup, never mutated after
    nonisolated(unsafe) var handlers: [String: RPCMethodHandler] = [:]

    func dispatch(_ request: RPCRequest) -> Data {
        guard let handler = handlers[request.method] else {
            return rpcErrorResponse(id: request.id, error: .methodNotFound(request.method))
        }
        do {
            let result = try handler(request.params)
            return rpcSuccessResponse(id: request.id, result: result)
        } catch {
            return rpcErrorResponse(id: request.id, error: .internalError(error.localizedDescription))
        }
    }
}
