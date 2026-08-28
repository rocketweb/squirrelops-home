import Foundation
#if canImport(Darwin)
import Darwin
#endif
import os

let logger = Logger(subsystem: "com.squirrelops.helper", category: "main")

let socketPath = "/var/run/squirrelops-helper.sock"

// Set up router
let router = RPCRouter()
registerMethods(router: router)

// This narrowly scoped Mach service is the only desktop-app entry point. It
// validates the immutable XPC audit token against the release app signature
// and forwards only a bounded certificate request, never setup keys or network
// privileges.
let localEnrollmentAppRequirement: String
do {
    localEnrollmentAppRequirement = try LocalEnrollmentCodeRequirementResolver()
        .resolve()
} catch {
    logger.fault(
        "Cannot establish the local enrollment app requirement: \(String(describing: error))"
    )
    exit(1)
}
let localEnrollmentXPCService = LocalEnrollmentXPCService(
    appCodeRequirement: localEnrollmentAppRequirement
)
localEnrollmentXPCService.resume()

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

// Fail closed if the dedicated service group is unavailable. A normal package
// install creates _squirrelops and restarts this helper before the sensor runs.
if let group = getgrnam(sensorServiceAccount) {
    let serviceGID = group.pointee.gr_gid
    guard chown(socketPath, 0, serviceGID) == 0, chmod(socketPath, 0o660) == 0 else {
        logger.error("Failed to secure helper socket: \(String(cString: strerror(errno)))")
        unlink(socketPath)
        exit(1)
    }
} else {
    logger.error("Service group _squirrelops is unavailable; helper socket is root-only")
    guard chown(socketPath, 0, 0) == 0, chmod(socketPath, 0o600) == 0 else {
        unlink(socketPath)
        exit(1)
    }
}

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
    guard configureNoSigPipe(fd: clientFd) else {
        logger.warning(
            "Failed to protect client fd \(clientFd) from SIGPIPE: \(String(cString: strerror(errno)))"
        )
        close(clientFd)
        continue
    }

    // Only root and the dedicated sensor account may drive privileged network
    // operations. Desktop users are deliberately excluded because any process
    // in their login session could otherwise obtain the same authority.
    var peerUID: uid_t = 0
    var peerGID: gid_t = 0
    guard getpeereid(clientFd, &peerUID, &peerGID) == 0 else {
        logger.warning("getpeereid() failed for client fd \(clientFd): \(String(cString: strerror(errno)))")
        close(clientFd)
        continue
    }
    guard isAuthorizedPeer(peerUID) else {
        logger.warning("Rejected RPC connection from unauthorized UID \(peerUID)")
        close(clientFd)
        continue
    }

    // Bound both directions before handling the synchronous connection. The
    // absolute deadlines in readLineFromSocket/sendAll also stop a slow-drip
    // peer from extending this per-system-call timeout indefinitely.
    guard configureClientSocketTimeouts(
        fd: clientFd,
        timeoutSeconds: clientSocketTimeoutSeconds
    ) else {
        logger.warning(
            "Failed to configure client socket timeouts for fd \(clientFd): \(String(cString: strerror(errno)))"
        )
        close(clientFd)
        continue
    }

    // Read one line directly from the fd (recv), so a read timeout surfaces as
    // a clean nil rather than a FileHandle exception.
    guard let data = readLineFromSocket(
        fd: clientFd,
        timeoutSeconds: TimeInterval(clientSocketTimeoutSeconds)
    ) else {
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

    // Write response and close.
    if !sendAll(
        fd: clientFd,
        data: response,
        timeoutSeconds: TimeInterval(clientSocketTimeoutSeconds)
    ) {
        logger.warning("Timed out or failed writing response to client fd \(clientFd)")
    }
    close(clientFd)
}
