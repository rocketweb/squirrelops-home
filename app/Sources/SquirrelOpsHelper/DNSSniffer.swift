import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Captures DNS queries from the network via BPF and parses them.
final class DNSSniffer: @unchecked Sendable {

    struct CapturedQuery: Sendable {
        let queryName: String
        let sourceIP: String
        let timestamp: Date
    }

    private var queries: [CapturedQuery] = []
    private let lock = NSLock()
    private var isSniffing = false
    private var sniffThread: Thread?

    /// Start sniffing DNS queries on the given interface.
    /// Requires root for BPF device access.
    func start(interface: String) throws {
        guard !isSniffing else { return }
        isSniffing = true
        queries = []
        // BPF sniffing would be started here in production
        // Actual BPF implementation deferred — requires root + careful C interop
    }

    /// Stop sniffing.
    func stop() {
        isSniffing = false
        sniffThread = nil
    }

    /// Return queries captured since the given date.
    func getQueries(since: Date) -> [CapturedQuery] {
        lock.lock()
        defer { lock.unlock() }
        return queries.filter { $0.timestamp >= since }
    }

    /// Convert captured queries to JSON-RPC result format.
    static func queriesToResult(_ queries: [CapturedQuery]) -> [[String: Any]] {
        let formatter = ISO8601DateFormatter()
        return queries.map { q in
            [
                "query_name": q.queryName,
                "source_ip": q.sourceIP,
                "timestamp": formatter.string(from: q.timestamp),
            ]
        }
    }

    // MARK: - DNS Packet Parsing

    /// Parse a DNS query name from raw packet bytes starting at the given offset.
    /// DNS names are encoded as length-prefixed labels: [3]www[7]example[3]com[0]
    static func parseDNSName(from data: Data, offset: Int) -> String? {
        var labels: [String] = []
        var pos = offset

        while pos < data.count {
            let len = Int(data[pos])
            if len == 0 { break }
            // Pointer (compression) — 2 high bits set
            if len & 0xC0 == 0xC0 {
                guard pos + 1 < data.count else { return nil }
                let ptrOffset = Int(len & 0x3F) << 8 | Int(data[pos + 1])
                if let name = parseDNSName(from: data, offset: ptrOffset) {
                    labels.append(name)
                }
                break
            }
            pos += 1
            guard pos + len <= data.count else { return nil }
            if let label = String(data: data[pos..<(pos + len)], encoding: .utf8) {
                labels.append(label)
            }
            pos += len
        }

        return labels.isEmpty ? nil : labels.joined(separator: ".")
    }

    /// Parse source IP from an IPv4 header (bytes 12-15).
    /// Note: Accepts any Data/slice — re-indexes from 0 internally.
    static func parseSourceIP(from data: Data) -> String? {
        // Re-index to ensure subscript access starts at 0
        let bytes = Data(data)
        // IPv4 header: source IP at offset 12
        guard bytes.count >= 20 else { return nil }
        let a = bytes[12], b = bytes[13], c = bytes[14], d = bytes[15]
        return "\(a).\(b).\(c).\(d)"
    }

    /// Extract DNS query name from a full UDP/DNS packet.
    /// Assumes: Ethernet(14) + IP(20) + UDP(8) + DNS header(12) + query
    static func parseDNSQuery(from packet: Data, ethernetOffset: Int = 14) -> (queryName: String, sourceIP: String)? {
        let ipOffset = ethernetOffset
        guard let sourceIP = parseSourceIP(from: packet.dropFirst(ipOffset).prefix(20)) else { return nil }

        let dnsOffset = ipOffset + 20 + 8 // IP header + UDP header
        let queryOffset = dnsOffset + 12 // DNS header is 12 bytes
        guard queryOffset < packet.count else { return nil }

        guard let name = parseDNSName(from: Data(packet), offset: queryOffset) else { return nil }
        return (queryName: name, sourceIP: sourceIP)
    }
}
