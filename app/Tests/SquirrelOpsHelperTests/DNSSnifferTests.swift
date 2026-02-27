import Foundation
import Testing

@testable import SquirrelOpsHelper

@Suite("DNSSniffer")
struct DNSSnifferTests {

    // MARK: - DNS Name Parsing

    @Test("Parse simple DNS name")
    func parseSimpleName() {
        // www.example.com encoded: [3]www[7]example[3]com[0]
        var data = Data()
        data.append(3) // length
        data.append(contentsOf: "www".utf8)
        data.append(7)
        data.append(contentsOf: "example".utf8)
        data.append(3)
        data.append(contentsOf: "com".utf8)
        data.append(0) // terminator

        let name = DNSSniffer.parseDNSName(from: data, offset: 0)
        #expect(name == "www.example.com")
    }

    @Test("Parse single-label DNS name")
    func parseSingleLabel() {
        var data = Data()
        data.append(9)
        data.append(contentsOf: "localhost".utf8)
        data.append(0)

        let name = DNSSniffer.parseDNSName(from: data, offset: 0)
        #expect(name == "localhost")
    }

    @Test("Parse DNS name at offset")
    func parseAtOffset() {
        var data = Data([0x00, 0x00]) // 2 bytes padding
        data.append(4)
        data.append(contentsOf: "test".utf8)
        data.append(0)

        let name = DNSSniffer.parseDNSName(from: data, offset: 2)
        #expect(name == "test")
    }

    @Test("Parse empty DNS data returns nil")
    func parseEmptyData() {
        let name = DNSSniffer.parseDNSName(from: Data(), offset: 0)
        #expect(name == nil)
    }

    // MARK: - Source IP Parsing

    @Test("Parse source IP from IPv4 header")
    func parseSourceIP() {
        var header = Data(count: 20)
        // Source IP at offset 12-15: 192.168.1.50
        header[12] = 192; header[13] = 168; header[14] = 1; header[15] = 50
        let ip = DNSSniffer.parseSourceIP(from: header)
        #expect(ip == "192.168.1.50")
    }

    @Test("Parse source IP from short data returns nil")
    func parseSourceIPShort() {
        let ip = DNSSniffer.parseSourceIP(from: Data(count: 10))
        #expect(ip == nil)
    }

    // MARK: - Query Result Formatting

    @Test("Queries convert to JSON-RPC result format")
    func queriesToResult() {
        let date = Date()
        let queries = [
            DNSSniffer.CapturedQuery(queryName: "example.com", sourceIP: "192.168.1.50", timestamp: date),
        ]
        let result = DNSSniffer.queriesToResult(queries)
        #expect(result.count == 1)
        #expect(result[0]["query_name"] as? String == "example.com")
        #expect(result[0]["source_ip"] as? String == "192.168.1.50")
        #expect(result[0]["timestamp"] != nil)
    }

    // MARK: - Sniffer State

    @Test("Stop without start does not crash")
    func stopWithoutStart() {
        let sniffer = DNSSniffer()
        sniffer.stop()
        // Should not throw
    }

    @Test("Get queries returns empty when not sniffing")
    func getQueriesEmpty() {
        let sniffer = DNSSniffer()
        let queries = sniffer.getQueries(since: Date.distantPast)
        #expect(queries.isEmpty)
    }
}
