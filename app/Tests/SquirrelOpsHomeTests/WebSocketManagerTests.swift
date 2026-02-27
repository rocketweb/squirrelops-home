import Foundation
import Testing

@testable import SquirrelOpsHome

// MARK: - Mock WebSocket Task

/// A mock implementation of WebSocketTaskProtocol for testing.
final class MockWebSocketTask: WebSocketTaskProtocol, @unchecked Sendable {
    private let lock = NSLock()

    private var _resumed = false
    var resumed: Bool {
        lock.withLock { _resumed }
    }

    private var _cancelled = false
    var cancelled: Bool {
        lock.withLock { _cancelled }
    }

    private var _cancelCode: URLSessionWebSocketTask.CloseCode?
    var cancelCode: URLSessionWebSocketTask.CloseCode? {
        lock.withLock { _cancelCode }
    }

    private var _sentMessages: [URLSessionWebSocketTask.Message] = []
    var sentMessages: [URLSessionWebSocketTask.Message] {
        lock.withLock { _sentMessages }
    }

    private var _messagesToReceive: [URLSessionWebSocketTask.Message] = []
    var messagesToReceive: [URLSessionWebSocketTask.Message] {
        get {
            lock.withLock { _messagesToReceive }
        }
        set {
            lock.withLock { _messagesToReceive = newValue }
        }
    }

    private var _receiveIndex = 0

    private func appendSentMessage(_ message: URLSessionWebSocketTask.Message) {
        lock.withLock {
            _sentMessages.append(message)
        }
    }

    private func nextReceivedMessage() -> URLSessionWebSocketTask.Message? {
        lock.withLock {
            if _receiveIndex < _messagesToReceive.count {
                let message = _messagesToReceive[_receiveIndex]
                _receiveIndex += 1
                return message
            }
            return nil
        }
    }

    func send(_ message: URLSessionWebSocketTask.Message) async throws {
        appendSentMessage(message)
    }

    func receive() async throws -> URLSessionWebSocketTask.Message {
        if let message = nextReceivedMessage() {
            return message
        }

        // Block indefinitely to simulate waiting for messages
        try await Task.sleep(for: .seconds(60))
        throw CancellationError()
    }

    func resume() {
        lock.withLock {
            _resumed = true
        }
    }

    func cancel(with closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        lock.withLock {
            _cancelled = true
            _cancelCode = closeCode
        }
    }
}

@Suite("WebSocket Manager")
struct WebSocketManagerTests {

    /// Helper to extract the JSON dictionary from a sent WebSocket message.
    private func jsonFromMessage(_ message: URLSessionWebSocketTask.Message) throws -> [String: Any] {
        switch message {
        case .string(let text):
            let data = text.data(using: .utf8)!
            return try JSONSerialization.jsonObject(with: data) as! [String: Any]
        case .data(let data):
            return try JSONSerialization.jsonObject(with: data) as! [String: Any]
        @unknown default:
            Issue.record("Unknown message type")
            return [:]
        }
    }

    // MARK: - Connect / Disconnect

    @Test("Connect sets isConnected to true")
    func connectSetsIsConnected() async {
        let mockTask = MockWebSocketTask()
        let manager = WebSocketManager(taskFactory: { mockTask })

        manager.connect()

        #expect(manager.isConnected == true)
        #expect(mockTask.resumed == true)
    }

    @Test("Disconnect sets isConnected to false")
    func disconnectSetsIsConnectedFalse() async {
        let mockTask = MockWebSocketTask()
        let manager = WebSocketManager(taskFactory: { mockTask })

        manager.connect()
        #expect(manager.isConnected == true)

        manager.disconnect()

        #expect(manager.isConnected == false)
        #expect(mockTask.cancelled == true)
        #expect(mockTask.cancelCode == .normalClosure)
    }

    // MARK: - Send Auth

    @Test("sendAuth sends correct JSON frame")
    func sendAuthSendsCorrectFrame() async throws {
        let mockTask = MockWebSocketTask()
        let manager = WebSocketManager(taskFactory: { mockTask })

        manager.connect()
        try await manager.sendAuth(certFingerprint: "sha256:test123", token: nil)

        #expect(mockTask.sentMessages.count == 1)

        let json = try jsonFromMessage(mockTask.sentMessages[0])
        #expect(json["type"] as? String == "auth")
        #expect(json["cert_fingerprint"] as? String == "sha256:test123")
    }

    // MARK: - Send Replay

    @Test("requestReplay sends correct JSON frame")
    func requestReplaySendsCorrectFrame() async throws {
        let mockTask = MockWebSocketTask()
        let manager = WebSocketManager(taskFactory: { mockTask })

        manager.connect()
        try await manager.requestReplay(sinceSeq: 4527)

        #expect(mockTask.sentMessages.count == 1)

        let json = try jsonFromMessage(mockTask.sentMessages[0])
        #expect(json["type"] as? String == "replay")
        #expect(json["since_seq"] as? Int == 4527)
    }

    // MARK: - Send Pong

    @Test("sendPong sends correct JSON frame")
    func sendPongSendsCorrectFrame() async throws {
        let mockTask = MockWebSocketTask()
        let manager = WebSocketManager(taskFactory: { mockTask })

        manager.connect()
        try await manager.sendPong()

        #expect(mockTask.sentMessages.count == 1)

        let json = try jsonFromMessage(mockTask.sentMessages[0])
        #expect(json["type"] as? String == "pong")
    }

    // MARK: - Receive Messages

    @Test("receiveMessages decodes event frames and updates lastSeq")
    func receiveMessagesDecodesEvents() async throws {
        let eventJson = """
        {"type":"event","seq":100,"event_type":"device.online","payload":{"device_id":1}}
        """
        let mockTask = MockWebSocketTask()
        mockTask.messagesToReceive = [
            .string(eventJson),
        ]

        let manager = WebSocketManager(taskFactory: { mockTask })
        manager.connect()

        let stream = manager.receiveMessages()
        var receivedFrames: [WSFrame] = []

        for await frame in stream {
            receivedFrames.append(frame)
            if receivedFrames.count >= 1 {
                break
            }
        }

        #expect(receivedFrames.count == 1)
        if case .event(let seq, let eventType, let payload) = receivedFrames[0] {
            #expect(seq == 100)
            #expect(eventType == "device.online")
            #expect(payload["device_id"] == .int(1))
        } else {
            Issue.record("Expected .event frame")
        }
        #expect(manager.lastSeq == 100)
    }

    @Test("Receiving ping auto-sends pong")
    func receivingPingAutoSendsPong() async throws {
        let pingJson = """
        {"type":"ping"}
        """
        let mockTask = MockWebSocketTask()
        mockTask.messagesToReceive = [
            .string(pingJson),
        ]

        let manager = WebSocketManager(taskFactory: { mockTask })
        manager.connect()

        let stream = manager.receiveMessages()
        var receivedFrames: [WSFrame] = []

        for await frame in stream {
            receivedFrames.append(frame)
            if receivedFrames.count >= 1 {
                break
            }
        }

        #expect(receivedFrames.count == 1)
        if case .ping = receivedFrames[0] {
            // Expected
        } else {
            Issue.record("Expected .ping frame")
        }

        // Give auto-pong a moment to be sent
        try await Task.sleep(for: .milliseconds(50))

        #expect(mockTask.sentMessages.count == 1)
        let json = try jsonFromMessage(mockTask.sentMessages[0])
        #expect(json["type"] as? String == "pong")
    }
}
