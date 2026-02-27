import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Binds a listening socket on the given address and port.
enum SocketBinder {

    /// Bind a TCP listening socket.
    /// - Parameters:
    ///   - address: Bind address (e.g., "0.0.0.0").
    ///   - port: Port number.
    /// - Returns: Dictionary with fd and status keys.
    static func bind(address: String, port: Int) throws -> [String: Any] {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else {
            throw RPCError.internalError("socket() failed: \(String(cString: strerror(errno)))")
        }

        var reuse: Int32 = 1
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        addr.sin_addr.s_addr = inet_addr(address)

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.bind(sock, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        guard bindResult == 0 else {
            close(sock)
            throw RPCError.internalError("bind() failed on \(address):\(port): \(String(cString: strerror(errno)))")
        }

        guard listen(sock, 128) == 0 else {
            close(sock)
            throw RPCError.internalError("listen() failed: \(String(cString: strerror(errno)))")
        }

        // Close the socket — fd passing via SCM_RIGHTS is a future optimization.
        // For now, the helper confirms the bind succeeded and the Python client
        // falls back to direct binding (see xpc.py bind_listener fallback).
        close(sock)
        return ["status": "ok"]
    }
}
