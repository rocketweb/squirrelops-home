import Foundation

// MARK: - Incoming WebSocket Frames

/// Represents any frame received from the sensor's WebSocket endpoint.
/// Uses a custom Decodable init that switches on the "type" field.
public enum WSFrame: Sendable, Equatable {
    case authOk
    case authError(reason: String)
    case event(seq: Int, eventType: String, payload: [String: AnyCodableValue])
    case replayComplete(lastSeq: Int)
    case ping

    private enum CodingKeys: String, CodingKey {
        case type
        case reason
        case seq
        case eventType = "event_type"
        case payload
        case lastSeq = "last_seq"
    }
}

extension WSFrame: Decodable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)

        switch type {
        case "auth_ok":
            self = .authOk

        case "auth_error":
            let reason = try container.decode(String.self, forKey: .reason)
            self = .authError(reason: reason)

        case "event":
            let seq = try container.decode(Int.self, forKey: .seq)
            let eventType = try container.decode(String.self, forKey: .eventType)
            let payload = try container.decode([String: AnyCodableValue].self, forKey: .payload)
            self = .event(seq: seq, eventType: eventType, payload: payload)

        case "replay_complete":
            let lastSeq = try container.decode(Int.self, forKey: .lastSeq)
            self = .replayComplete(lastSeq: lastSeq)

        case "ping":
            self = .ping

        default:
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: container.codingPath,
                    debugDescription: "Unknown WebSocket frame type: \(type)"
                )
            )
        }
    }
}

// MARK: - Outgoing WebSocket Frames

/// Represents frames sent by the client to the sensor's WebSocket endpoint.
/// Uses a custom Encodable with a "type" discriminator field and snake_case keys.
public enum WSOutgoing: Sendable, Equatable {
    case auth(certFingerprint: String?, token: String?)
    case replay(sinceSeq: Int)
    case pong
}

extension WSOutgoing: Encodable {
    private enum CodingKeys: String, CodingKey {
        case type
        case certFingerprint = "cert_fingerprint"
        case token
        case sinceSeq = "since_seq"
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        switch self {
        case .auth(let certFingerprint, let token):
            try container.encode("auth", forKey: .type)
            try container.encode(certFingerprint, forKey: .certFingerprint)
            try container.encode(token, forKey: .token)

        case .replay(let sinceSeq):
            try container.encode("replay", forKey: .type)
            try container.encode(sinceSeq, forKey: .sinceSeq)

        case .pong:
            try container.encode("pong", forKey: .type)
        }
    }
}
