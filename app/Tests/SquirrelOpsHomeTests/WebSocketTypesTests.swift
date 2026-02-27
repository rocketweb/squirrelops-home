import Foundation
import Testing

@testable import SquirrelOpsHome

@Suite("WebSocket Frame Types")
struct WebSocketTypesTests {

    // MARK: - WSFrame decoding

    @Test("Decode auth_ok frame")
    func decodeAuthOk() throws {
        let json = """
        {
            "type": "auth_ok"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let frame = try decoder.decode(WSFrame.self, from: json)

        if case .authOk = frame {
            // Expected
        } else {
            Issue.record("Expected .authOk, got \(frame)")
        }
    }

    @Test("Decode auth_error frame with reason")
    func decodeAuthError() throws {
        let json = """
        {
            "type": "auth_error",
            "reason": "Invalid certificate fingerprint"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let frame = try decoder.decode(WSFrame.self, from: json)

        if case .authError(let reason) = frame {
            #expect(reason == "Invalid certificate fingerprint")
        } else {
            Issue.record("Expected .authError, got \(frame)")
        }
    }

    @Test("Decode event frame with payload")
    func decodeEventFrame() throws {
        let json = """
        {
            "type": "event",
            "seq": 4528,
            "event_type": "device.online",
            "payload": {
                "device_id": 42,
                "ip_address": "192.168.1.101",
                "hostname": "living-room-hub"
            }
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let frame = try decoder.decode(WSFrame.self, from: json)

        if case .event(let seq, let eventType, let payload) = frame {
            #expect(seq == 4528)
            #expect(eventType == "device.online")
            #expect(payload["device_id"] == .int(42))
            #expect(payload["ip_address"] == .string("192.168.1.101"))
            #expect(payload["hostname"] == .string("living-room-hub"))
        } else {
            Issue.record("Expected .event, got \(frame)")
        }
    }

    @Test("Decode replay_complete frame")
    func decodeReplayComplete() throws {
        let json = """
        {
            "type": "replay_complete",
            "last_seq": 4583
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let frame = try decoder.decode(WSFrame.self, from: json)

        if case .replayComplete(let lastSeq) = frame {
            #expect(lastSeq == 4583)
        } else {
            Issue.record("Expected .replayComplete, got \(frame)")
        }
    }

    @Test("Decode ping frame")
    func decodePing() throws {
        let json = """
        {
            "type": "ping"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let frame = try decoder.decode(WSFrame.self, from: json)

        if case .ping = frame {
            // Expected
        } else {
            Issue.record("Expected .ping, got \(frame)")
        }
    }

    // MARK: - WSOutgoing encoding

    @Test("Encode auth frame with cert_fingerprint")
    func encodeAuthWithCertFingerprint() throws {
        let outgoing = WSOutgoing.auth(certFingerprint: "sha256:abc123", token: nil)

        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let data = try encoder.encode(outgoing)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        #expect(json["type"] as? String == "auth")
        #expect(json["cert_fingerprint"] as? String == "sha256:abc123")
        #expect(json["token"] == nil || json["token"] is NSNull)
    }

    @Test("Encode auth frame with token")
    func encodeAuthWithToken() throws {
        let outgoing = WSOutgoing.auth(certFingerprint: nil, token: "local-token-abc")

        let encoder = JSONEncoder()
        let data = try encoder.encode(outgoing)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        #expect(json["type"] as? String == "auth")
        #expect(json["token"] as? String == "local-token-abc")
        #expect(json["cert_fingerprint"] == nil || json["cert_fingerprint"] is NSNull)
    }

    @Test("Encode pong frame")
    func encodePong() throws {
        let outgoing = WSOutgoing.pong

        let encoder = JSONEncoder()
        let data = try encoder.encode(outgoing)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        #expect(json["type"] as? String == "pong")
    }

    @Test("Encode replay frame with since_seq")
    func encodeReplay() throws {
        let outgoing = WSOutgoing.replay(sinceSeq: 4527)

        let encoder = JSONEncoder()
        let data = try encoder.encode(outgoing)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        #expect(json["type"] as? String == "replay")
        #expect(json["since_seq"] as? Int == 4527)
    }
}
