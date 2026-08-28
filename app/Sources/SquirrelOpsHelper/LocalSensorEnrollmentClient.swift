import Foundation
#if canImport(Darwin)
import Darwin
#endif

import SquirrelOpsLocalEnrollment

enum LocalSensorEnrollmentError: Error, Equatable {
    case invalidRequest
    case sensorUnavailable
    case invalidResponse
}

private struct LocalEnrollmentWireRequest: Encodable {
    let action = "enroll"
    let requestID: String
    let clientName: String
    let csrPEM: String

    enum CodingKeys: String, CodingKey {
        case action
        case requestID = "request_id"
        case clientName = "client_name"
        case csrPEM = "csr_pem"
    }
}

struct LocalSensorEnrollmentClient {
    let socketPath: String

    init(
        socketPath: String = "/Library/SquirrelOps/sensor/run/enrollment.sock"
    ) {
        self.socketPath = socketPath
    }

    func enroll(requestData: Data) throws -> Data {
        guard requestData.count <= 16_384,
              let request = try? JSONDecoder().decode(
                LocalEnrollmentRequest.self,
                from: requestData
              ),
              UUID(uuidString: request.requestID)?.uuidString.lowercased()
                == request.requestID.lowercased(),
              !request.clientName.isEmpty,
              request.clientName.count <= 128,
              request.csrPEM.utf8.count <= 8_192 else {
            throw LocalSensorEnrollmentError.invalidRequest
        }

        let wireRequest = LocalEnrollmentWireRequest(
            requestID: request.requestID.lowercased(),
            clientName: request.clientName,
            csrPEM: request.csrPEM
        )
        var encoded = try JSONEncoder().encode(wireRequest)
        encoded.append(0x0A)

        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw LocalSensorEnrollmentError.sensorUnavailable
        }
        defer { close(descriptor) }
        guard configureNoSigPipe(fd: descriptor) else {
            throw LocalSensorEnrollmentError.sensorUnavailable
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathFits = socketPath.withCString { source -> Bool in
            guard strlen(source) < 104 else { return false }
            return withUnsafeMutablePointer(to: &address.sun_path) { pointer in
                let destination = UnsafeMutableRawPointer(pointer)
                    .bindMemory(to: CChar.self, capacity: 104)
                _ = strlcpy(destination, source, 104)
                return true
            }
        }
        guard pathFits else { throw LocalSensorEnrollmentError.sensorUnavailable }

        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(
                    descriptor,
                    $0,
                    socklen_t(MemoryLayout<sockaddr_un>.size)
                )
            }
        }
        guard connected == 0 else {
            throw LocalSensorEnrollmentError.sensorUnavailable
        }
        guard configureClientSocketTimeouts(fd: descriptor, timeoutSeconds: 10),
              sendAll(fd: descriptor, data: encoded),
              let response = readLineFromSocket(fd: descriptor),
              response.count <= 65_536,
              (try? JSONDecoder().decode(
                LocalEnrollmentResponse.self,
                from: response
              )) != nil else {
            throw LocalSensorEnrollmentError.invalidResponse
        }
        return response
    }
}
