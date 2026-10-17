import Darwin
import Dispatch
import Foundation
import Testing
@testable import SquirrelOpsDeceptionGuest

@Suite("Guest relay diagnostics")
struct RuntimeDiagnosticsTests {
    @Test("Diagnostic pipe is separate from unchanged readiness and connection telemetry")
    func separatePipes() throws {
        let telemetry = Pipe()
        let diagnostic = Pipe()
        defer {
            try? telemetry.fileHandleForReading.close()
            try? diagnostic.fileHandleForReading.close()
        }
        let nonce = String(repeating: "a", count: 32)
        let output = RuntimeOutput(diagnosticNonce: nonce, telemetryHandle: telemetry.fileHandleForWriting,
                                   diagnosticHandle: diagnostic.fileHandleForWriting)
        output.write(["status": "ready"])
        output.writeDiagnostic(RelayDiagnostic(stage: .accepted, servicePort: 22, connectionID: 1,
                                               sequence: 1, errorNumber: 0, direction: .none))
        try telemetry.fileHandleForWriting.close()
        try diagnostic.fileHandleForWriting.close()
        let publicData = telemetry.fileHandleForReading.readDataToEndOfFile()
        let object = try JSONSerialization.jsonObject(with: publicData) as? [String: String]
        #expect(object == ["status": "ready"])
        let privateData = diagnostic.fileHandleForReading.readDataToEndOfFile()
        let line = try #require(String(data: privateData, encoding: .utf8))
        #expect(line.hasPrefix("SQUIRRELOPS_RELAY_DIAGNOSTIC \(nonce) "))
        #expect(!String(decoding: publicData, as: UTF8.self).contains(nonce))
        let json = try #require(line.split(separator: " ", maxSplits: 2).last)
        let record = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        #expect(record?["stage"] as? String == "accepted")
    }

    @Test("Real TCP listener accepts repeated loopback clients and preserves bytes")
    func realListener() async throws {
        let records = DiagnosticRecords()
        let diagnostics = RuntimeDiagnostics { records.append($0) }
        let service = diagnostics.service(22)
        let limiter = ConnectionLimiter(maximum: 16)
        let handler = guestConnectionHandler(limiter: limiter, diagnostic: service, onConnection: { _, _ in }) { connection, _ in
            let bytes: [UInt8] = [83, 83, 72, 45, 50, 46, 48, 45, 116, 101, 115, 116, 13, 10]
            let sent = bytes.withUnsafeBytes { Darwin.send(connection.descriptor, $0.baseAddress, $0.count, 0) }
            #expect(sent == bytes.count)
            connection.close()
            return .guestConnected
        }
        let listener = try TCPListener(bindAddress: "127.0.0.1", diagnostic: service, handler: handler)
        defer { listener.stop() }
        listener.start()
        listener.start() // Activation remains idempotent.
        let port = listener.localPort
        for _ in 0..<8 {
            let response = try await Task.detached { try readBanner(port: port) }.value
            #expect(response == Array("SSH-2.0-test\r\n".utf8))
        }
        diagnostics.flushForTesting()
        #expect(records.values.filter { $0.stage == .listenerActivated }.count == 1)
        let accepted = records.values.filter { $0.stage == .accepted }
        let entered = records.values.filter { $0.stage == .mainActorEntered }
        #expect(accepted.count == 8)
        #expect(entered.count == 8)
        #expect(Set(accepted.map(\.connectionID)).count == 8)
        for record in accepted {
            #expect(entered.contains { $0.connectionID == record.connectionID && $0.sequence > record.sequence })
        }
        #expect(limiter.acquire())
        limiter.release()
    }

    @Test("Acceptance is observable before the MainActor task can drain")
    @MainActor
    func beforeMainActor() async throws {
        let records = DiagnosticRecords()
        let diagnostics = RuntimeDiagnostics { records.append($0) }
        let handler = guestConnectionHandler(limiter: ConnectionLimiter(maximum: 1), diagnostic: diagnostics.service(445), onConnection: { _, _ in }) { connection, _ in
            connection.close()
            return .guestConnectFailed
        }
        var pair = [Int32](repeating: -1, count: 2)
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
        defer { Darwin.close(pair[1]) }
        handler(pair[0], PeerEndpoint(address: "127.0.0.1", port: 12345))
        diagnostics.flushForTesting()
        #expect(records.values.map(\.stage) == [.accepted])
        for _ in 0..<100 {
            if records.values.contains(where: { $0.stage == .mainActorEntered }) { break }
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(records.values.map(\.stage) == [.accepted, .mainActorEntered])
    }

    @Test("Blocked diagnostic sink cannot block a real listener or grow the queue without bound")
    func blockedSink() async throws {
        let gate = DispatchSemaphore(value: 0)
        let records = DiagnosticRecords()
        let diagnostics = RuntimeDiagnostics { record in
            if record.sequence == 1 { _ = gate.wait(timeout: .now() + 5) }
            records.append(record)
        }
        defer { gate.signal() }
        let service = diagnostics.service(22)
        let listener = try TCPListener(bindAddress: "127.0.0.1", diagnostic: service) { descriptor, _ in
            defer { Darwin.close(descriptor) }
            let bytes = Array("SSH-2.0-test\r\n".utf8)
            _ = bytes.withUnsafeBytes { Darwin.send(descriptor, $0.baseAddress, $0.count, 0) }
        }
        defer { listener.stop() }
        listener.start()
        for _ in 0..<2_000 { service.record(.listenerReadable) }
        let response = try await Task.detached { try readBanner(port: listener.localPort) }.value
        #expect(response == Array("SSH-2.0-test\r\n".utf8))
        // The sink is still blocked, but all listener work above completed.
        #expect(records.values.isEmpty)
        gate.signal()
        diagnostics.flushForTesting()
        #expect(records.values.count == RuntimeDiagnostics.maximumRecords + 1)
        #expect(records.values.last?.stage == .diagnosticsTruncated)
        #expect(records.values.map(\.sequence) == Array(1...513))
    }

    @Test("Diagnostic schema has no place for credentials, peers or payloads")
    func safeSchema() throws {
        let records = DiagnosticRecords()
        let diagnostics = RuntimeDiagnostics { records.append($0) }
        diagnostics.service(445).connection().record(.readFailed, errno: ECONNRESET, direction: .clientToGuest)
        diagnostics.flushForTesting()
        let payload = try #require(records.values.first).payload
        #expect(Set(payload.keys) == Set(["event", "stage", "service_port", "connection_id", "sequence", "errno", "direction"]))
        #expect(payload["errno"] as? Int == Int(ECONNRESET))
        #expect(payload["direction"] as? String == "client_to_guest")
        #expect(JSONSerialization.isValidJSONObject(payload))
    }
}

final class DiagnosticRecords: @unchecked Sendable {
    private let lock = NSLock()
    private var records: [RelayDiagnostic] = []
    var values: [RelayDiagnostic] { lock.withLock { records } }
    func append(_ record: RelayDiagnostic) { lock.withLock { records.append(record) } }
}

private func readBanner(port: UInt16) throws -> [UInt8] {
    let descriptor = socket(AF_INET, SOCK_STREAM, 0)
    try #require(descriptor >= 0)
    defer { Darwin.close(descriptor) }
    var timeout = timeval(tv_sec: 2, tv_usec: 0)
    try #require(setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0)
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = port.bigEndian
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    let result = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    try #require(result == 0)
    var output: [UInt8] = []
    var bytes = [UInt8](repeating: 0, count: 64)
    while output.count < 64 {
        let count = Darwin.read(descriptor, &bytes, bytes.count)
        try #require(count >= 0)
        if count == 0 { break }
        output.append(contentsOf: bytes.prefix(count))
    }
    return output
}
