import Foundation
import Testing

@testable import SquirrelOpsHelper

@Suite("ARPScanner")
struct ARPScannerTests {

    // MARK: - CIDR Parsing

    @Test("Parse valid CIDR /24")
    func parseCIDR24() throws {
        let (network, prefix) = try ARPScanner.parseCIDR("192.168.1.0/24")
        #expect(prefix == 24)
        #expect(network == (192 << 24 | 168 << 16 | 1 << 8 | 0))
    }

    @Test("Parse invalid CIDR throws")
    func parseInvalidCIDR() {
        #expect(throws: RPCError.self) {
            try ARPScanner.parseCIDR("not-a-cidr")
        }
    }

    // MARK: - IP Generation

    @Test("Generate IPs for /24 produces 254 addresses")
    func generateIPs24() {
        let ips = ARPScanner.generateIPs(network: (192 << 24 | 168 << 16 | 1 << 8 | 0), prefixLen: 24)
        #expect(ips.count == 254)
        #expect(ips.first == "192.168.1.1")
        #expect(ips.last == "192.168.1.254")
    }

    @Test("Generate IPs for /30 produces 2 addresses")
    func generateIPs30() {
        let ips = ARPScanner.generateIPs(network: (10 << 24 | 0 << 16 | 0 << 8 | 0), prefixLen: 30)
        #expect(ips.count == 2)
        #expect(ips[0] == "10.0.0.1")
        #expect(ips[1] == "10.0.0.2")
    }

    // MARK: - ARP Table Parsing

    @Test("Parse arp -an output extracts IP and MAC")
    func parseARPTable() {
        let output = """
        ? (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0 ifscope [ethernet]
        ? (192.168.1.2) at aa:bb:cc:dd:ee:02 on en0 ifscope [ethernet]
        ? (192.168.1.3) at (incomplete) on en0 ifscope [ethernet]
        ? (10.0.0.1) at ff:ff:ff:ff:ff:ff on en1 ifscope [ethernet]
        """

        let results = ARPScanner.parseARPTable(output, subnet: "192.168.1.0/24")
        #expect(results.count == 2) // incomplete and 10.x excluded
        #expect(results[0]["ip"] == "192.168.1.1")
        #expect(results[0]["mac"] == "aa:bb:cc:dd:ee:01")
        #expect(results[1]["ip"] == "192.168.1.2")
    }

    @Test("Parse arp output with empty string returns empty")
    func parseARPEmpty() {
        let results = ARPScanner.parseARPTable("", subnet: "192.168.1.0/24")
        #expect(results.isEmpty)
    }
}
