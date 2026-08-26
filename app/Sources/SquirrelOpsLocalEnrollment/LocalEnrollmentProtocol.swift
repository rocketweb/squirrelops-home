import Foundation

public enum LocalEnrollmentXPC {
    public static let machServiceName = "com.squirrelops.helper.enrollment"
    public static let appCodeRequirement =
        "identifier \"com.squirrelops.home\" and anchor apple generic and "
        + "certificate leaf[subject.OU] = \"PSQ5HK5U65\""
}

@objc public protocol LocalEnrollmentXPCProtocol {
    func enrollLocalApp(
        request: Data,
        withReply reply: @escaping (Data?, NSError?) -> Void
    )
}

public struct LocalEnrollmentRequest: Codable, Equatable, Sendable {
    public let requestID: String
    public let clientName: String
    public let csrPEM: String

    public init(requestID: String, clientName: String, csrPEM: String) {
        self.requestID = requestID
        self.clientName = clientName
        self.csrPEM = csrPEM
    }

    enum CodingKeys: String, CodingKey {
        case requestID = "request_id"
        case clientName = "client_name"
        case csrPEM = "csr_pem"
    }
}

public struct LocalEnrollmentResponse: Codable, Equatable, Sendable {
    public let requestID: String
    public let pairingID: Int
    public let sensorID: String
    public let sensorName: String
    public let caCertPEM: String
    public let clientCertPEM: String
    public let certFingerprint: String

    public init(
        requestID: String,
        pairingID: Int,
        sensorID: String,
        sensorName: String,
        caCertPEM: String,
        clientCertPEM: String,
        certFingerprint: String
    ) {
        self.requestID = requestID
        self.pairingID = pairingID
        self.sensorID = sensorID
        self.sensorName = sensorName
        self.caCertPEM = caCertPEM
        self.clientCertPEM = clientCertPEM
        self.certFingerprint = certFingerprint
    }

    enum CodingKeys: String, CodingKey {
        case requestID = "request_id"
        case pairingID = "pairing_id"
        case sensorID = "sensor_id"
        case sensorName = "sensor_name"
        case caCertPEM = "ca_cert_pem"
        case clientCertPEM = "client_cert_pem"
        case certFingerprint = "cert_fingerprint"
    }
}
