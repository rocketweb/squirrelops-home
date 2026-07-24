import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Constructs and parses ARP packets, sends via raw socket.
enum ARPScanner {

    /// Perform an ARP scan on the given subnet.
    /// Requires root for raw socket access.
    /// - Parameter subnet: CIDR string (e.g., "192.168.1.0/24")
    /// - Returns: Array of dictionaries with ip and mac keys.
    static func scan(subnet: String) throws -> [[String: String]] {
        _ = try parseCIDR(subnet)
        return try arpViaCLI(subnet: subnet)
    }

    /// Fallback: use the `arp` command to scan.
    /// Sends a ping sweep first to populate the ARP cache, then reads it.
    static func arpViaCLI(subnet: String) throws -> [[String: String]] {
        // Ping sweep to populate ARP table
        let (network, prefixLen) = try parseCIDR(subnet)
        let ips = generateIPs(network: network, prefixLen: prefixLen)

        // Keep a bounded number of child processes and reap every one. The old
        // implementation launched 254 fire-and-forget pings per allocation,
        // which could exhaust process resources when a full profile deployed
        // many mimics in sequence.
        for batchStart in stride(from: 0, to: ips.count, by: 32) {
            let batchEnd = min(batchStart + 32, ips.count)
            var processes: [Process] = []
            for ip in ips[batchStart..<batchEnd] {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/sbin/ping")
                process.arguments = ["-n", "-c", "1", "-W", "100", ip]
                process.standardOutput = FileHandle.nullDevice
                process.standardError = FileHandle.nullDevice
                do {
                    try process.run()
                    processes.append(process)
                } catch {
                    // One failed probe does not invalidate the ARP table read;
                    // an entirely empty result still fails closed in Python.
                    continue
                }
            }
            for process in processes {
                process.waitUntilExit()
            }
        }

        // Read ARP table
        let arpProcess = Process()
        arpProcess.executableURL = URL(fileURLWithPath: "/usr/sbin/arp")
        arpProcess.arguments = ["-an"]
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        arpProcess.standardOutput = stdoutPipe
        arpProcess.standardError = stderrPipe
        try arpProcess.run()
        arpProcess.waitUntilExit()

        guard arpProcess.terminationStatus == 0 else {
            let stderr = String(
                data: stderrPipe.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            ) ?? ""
            throw RPCError.internalError("arp table read failed: \(stderr)")
        }
        let output = String(
            data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(),
            encoding: .utf8
        ) ?? ""
        return parseARPTable(output, subnet: subnet)
    }

    /// Parse CIDR notation into network address and prefix length.
    static func parseCIDR(_ cidr: String) throws -> (UInt32, Int) {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2,
              let prefixLen = Int(parts[1]),
              prefixLen >= 0, prefixLen <= 32 else {
            throw RPCError.internalError("Invalid CIDR: \(cidr)")
        }

        guard isValidIPv4(String(parts[0])) else {
            throw RPCError.internalError("Invalid IP in CIDR: \(cidr)")
        }
        let octets = parts[0].split(separator: ".").compactMap { UInt32($0) }

        let network = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        return (network, prefixLen)
    }

    /// Generate all host IPs in a subnet (excluding network and broadcast).
    static func generateIPs(network: UInt32, prefixLen: Int) -> [String] {
        let mask: UInt32 = prefixLen == 0 ? 0 : ~((1 << (32 - prefixLen)) - 1)
        let base = network & mask
        let hostBits = 32 - prefixLen
        guard hostBits > 1 else { return [] }

        let count = (1 << hostBits) - 2 // exclude network and broadcast
        var ips: [String] = []
        for i in 1...min(count, 254) { // Cap at 254 hosts
            let ip = base + UInt32(i)
            let a = (ip >> 24) & 0xFF
            let b = (ip >> 16) & 0xFF
            let c = (ip >> 8) & 0xFF
            let d = ip & 0xFF
            ips.append("\(a).\(b).\(c).\(d)")
        }
        return ips
    }

    /// Parse `arp -an` output, filtering to the target subnet.
    static func parseARPTable(_ output: String, subnet: String) -> [[String: String]] {
        // Lines look like: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
        var results: [[String: String]] = []

        let (network, prefixLen) = (try? parseCIDR(subnet)) ?? (0, 0)
        let mask: UInt32 = prefixLen == 0 ? 0 : ~((1 << (32 - prefixLen)) - 1)

        for line in output.split(separator: "\n") {
            let str = String(line)
            // Extract IP from parentheses
            guard let ipStart = str.firstIndex(of: "("),
                  let ipEnd = str.firstIndex(of: ")"),
                  ipStart < ipEnd else { continue }

            let ip = String(str[str.index(after: ipStart)..<ipEnd])

            // Extract MAC after " at "
            guard let atRange = str.range(of: " at ") else { continue }
            let afterAt = str[atRange.upperBound...]
            let mac = String(afterAt.prefix(while: { $0 != " " }))

            // Skip incomplete entries
            if mac == "(incomplete)" { continue }

            // Check if IP is in subnet
            let octets = ip.split(separator: ".").compactMap { UInt32($0) }
            if octets.count == 4 {
                let ipNum = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
                if (ipNum & mask) == (network & mask) {
                    results.append(["ip": ip, "mac": mac])
                }
            }
        }

        return results
    }
}
