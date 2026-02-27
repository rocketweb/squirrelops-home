import Foundation

// MARK: - WebSocketTaskProtocol

/// Protocol abstraction over URLSessionWebSocketTask for testability.
public protocol WebSocketTaskProtocol: Sendable {
    func send(_ message: URLSessionWebSocketTask.Message) async throws
    func receive() async throws -> URLSessionWebSocketTask.Message
    func resume()
    func cancel(with closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?)
}

extension URLSessionWebSocketTask: WebSocketTaskProtocol {}

// MARK: - WebSocketManager

/// Manages a WebSocket connection to the sensor, handling message encoding/decoding,
/// keepalive pong responses, and sequence number tracking.
/// All public methods must be called from the main actor.
/// Full @MainActor isolation deferred to Phase 3 (WebSocketManagerProtocol: Sendable conformance conflict).
@Observable
public final class WebSocketManager: @unchecked Sendable {

    // MARK: - Public Properties

    public private(set) var isConnected: Bool = false
    public private(set) var lastSeq: Int = 0

    // MARK: - Private Properties

    private var task: (any WebSocketTaskProtocol)?
    private let taskFactory: @Sendable () -> any WebSocketTaskProtocol
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    // MARK: - Init

    /// Creates a WebSocketManager with a task factory closure.
    /// For production, pass a closure that creates a URLSessionWebSocketTask.
    /// For testing, pass a closure that returns a mock.
    public init(taskFactory: @escaping @Sendable () -> any WebSocketTaskProtocol) {
        self.taskFactory = taskFactory
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
    }

    /// Convenience initializer for production use that creates a WebSocketTask from a URL and session.
    public convenience init(url: URL, session: URLSession = .shared) {
        self.init(taskFactory: { [url, session] in
            session.webSocketTask(with: url)
        })
    }

    // MARK: - Connection Lifecycle

    /// Creates and resumes a WebSocketTask. Does not send any frames yet.
    public func connect() {
        let newTask = taskFactory()
        self.task = newTask
        newTask.resume()
        isConnected = true
    }

    /// Cancels the WebSocket task with a normal closure code.
    public func disconnect() {
        task?.cancel(with: .normalClosure, reason: nil)
        task = nil
        isConnected = false
    }

    // MARK: - Sending Frames

    /// Sends an auth frame to the sensor.
    public func sendAuth(certFingerprint: String?, token: String?) async throws {
        let frame = WSOutgoing.auth(certFingerprint: certFingerprint, token: token)
        try await sendFrame(frame)
    }

    /// Sends a replay request to the sensor.
    public func requestReplay(sinceSeq: Int) async throws {
        let frame = WSOutgoing.replay(sinceSeq: sinceSeq)
        try await sendFrame(frame)
    }

    /// Sends a pong frame to the sensor in response to a ping.
    public func sendPong() async throws {
        let frame = WSOutgoing.pong
        try await sendFrame(frame)
    }

    // MARK: - Receiving Messages

    /// Returns an AsyncStream that continuously receives and decodes WebSocket messages.
    /// On receiving .event, updates lastSeq.
    /// On receiving .ping, automatically sends pong.
    public func receiveMessages() -> AsyncStream<WSFrame> {
        AsyncStream { continuation in
            let receiveTask = Task { [weak self] in
                guard let self else {
                    continuation.finish()
                    return
                }

                while !Task.isCancelled {
                    guard let task = self.task else {
                        continuation.finish()
                        return
                    }

                    do {
                        let message = try await task.receive()
                        guard let frame = self.decodeMessage(message) else {
                            continue
                        }

                        // Update lastSeq on event frames
                        if case .event(let seq, _, _) = frame {
                            self.lastSeq = seq
                        }

                        // Auto-pong on ping frames
                        if case .ping = frame {
                            Task {
                                try? await self.sendPong()
                            }
                        }

                        continuation.yield(frame)
                    } catch {
                        // Connection closed or error — finish the stream
                        self.isConnected = false
                        continuation.finish()
                        return
                    }
                }

                continuation.finish()
            }

            continuation.onTermination = { _ in
                receiveTask.cancel()
            }
        }
    }

    // MARK: - Private Helpers

    private func sendFrame(_ frame: WSOutgoing) async throws {
        guard let task else { return }
        let data = try encoder.encode(frame)
        let string = String(data: data, encoding: .utf8)!
        try await task.send(.string(string))
    }

    private func decodeMessage(_ message: URLSessionWebSocketTask.Message) -> WSFrame? {
        let data: Data
        switch message {
        case .string(let text):
            guard let textData = text.data(using: .utf8) else { return nil }
            data = textData
        case .data(let binaryData):
            data = binaryData
        @unknown default:
            return nil
        }

        return try? decoder.decode(WSFrame.self, from: data)
    }
}
