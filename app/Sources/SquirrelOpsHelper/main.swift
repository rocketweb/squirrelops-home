import Foundation
#if canImport(Darwin)
import Darwin
#endif
import os

let logger = Logger(subsystem: "com.squirrelops.helper", category: "main")

let socketPath = "/var/run/squirrelops-helper.sock"

// Set up router
let router = RPCRouter()
let dnsSniffer = DNSSniffer()
registerMethods(router: router, dnsSniffer: dnsSniffer)

// Remove stale socket file
unlink(socketPath)

// Create Unix domain socket
let serverFd = socket(AF_UNIX, SOCK_STREAM, 0)
guard serverFd >= 0 else {
    logger.error("Failed to create socket: \(String(cString: strerror(errno)))")
    exit(1)
}

var addr = sockaddr_un()
addr.sun_family = sa_family_t(AF_UNIX)
withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
    let pathPtr = UnsafeMutableRawPointer(ptr).bindMemory(to: CChar.self, capacity: 104)
    socketPath.withCString { src in
        _ = strlcpy(pathPtr, src, 104)
    }
}

let bindResult = withUnsafePointer(to: &addr) { ptr in
    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
        Darwin.bind(serverFd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
    }
}

guard bindResult == 0 else {
    logger.error("Failed to bind socket: \(String(cString: strerror(errno)))")
    exit(1)
}

// Allow sensor process to connect (owner + group read/write)
chmod(socketPath, 0o666)

guard listen(serverFd, 5) == 0 else {
    logger.error("Failed to listen: \(String(cString: strerror(errno)))")
    exit(1)
}

logger.info("com.squirrelops.helper listening on \(socketPath)")

// Handle SIGTERM for graceful shutdown
signal(SIGTERM) { _ in
    unlink(socketPath)
    exit(0)
}

// Accept loop
while true {
    let clientFd = accept(serverFd, nil, nil)
    guard clientFd >= 0 else {
        logger.warning("accept() failed: \(String(cString: strerror(errno)))")
        continue
    }

    // Read one line
    let fileHandle = FileHandle(fileDescriptor: clientFd, closeOnDealloc: true)
    guard let data = readLine(from: fileHandle) else {
        close(clientFd)
        continue
    }

    // Parse and dispatch
    let response: Data
    do {
        let request = try RPCRequest(from: data)
        logger.info("RPC: \(request.method) (id=\(request.id))")
        response = router.dispatch(request)
    } catch {
        response = rpcErrorResponse(id: nil, error: .invalidRequest)
    }

    // Write response
    fileHandle.write(response)
}

/// Read bytes until newline from a file handle (max 64 KB).
func readLine(from handle: FileHandle) -> Data? {
    let maxLineLength = 65536
    var buffer = Data()
    while true {
        let chunk = handle.readData(ofLength: 1)
        if chunk.isEmpty { return buffer.isEmpty ? nil : buffer }
        if chunk[0] == 0x0A { return buffer } // newline
        buffer.append(chunk)
        if buffer.count > maxLineLength { return nil }
    }
}
