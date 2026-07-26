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

    @Test("ARP table parser can require the helper-observed interface")
    func parseARPTableOnExpectedInterface() {
        let output = """
        ? (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0 ifscope [ethernet]
        ? (192.168.1.2) at aa:bb:cc:dd:ee:02 on en1 ifscope [ethernet]
        """

        let results = ARPScanner.parseARPTable(
            output,
            subnet: "192.168.1.0/24",
            interface: "en0"
        )
        #expect(results.map { $0["ip"] } == ["192.168.1.1"])
    }

    @Test("ARP table read uses the shared concurrent-drain command runner")
    func readsARPTableThroughCommandRunner() throws {
        var commands: [[String]] = []
        let output = try ARPScanner.readARPTable(interface: "en0") {
            executable,
            arguments in
            commands.append([executable] + arguments)
            return CommandResult(
                status: 0,
                stdout: String(repeating: "a", count: 128 * 1024),
                stderr: String(repeating: "b", count: 128 * 1024)
            )
        }

        #expect(
            commands == [["/usr/sbin/arp", "-an", "-i", "en0"]]
        )
        #expect(output.count == 128 * 1024)
    }

    @Test("ARP scans are limited to canonical directly connected private CIDRs")
    func validatesARPScanBoundary() throws {
        let networks = try interfaceIPv4Networks(
            from: """
            inet 192.168.1.18 netmask 0xffffff00 broadcast 192.168.1.255
            """
        )

        try validateARPScanCIDR(
            "192.168.1.0/24",
            interface: "en0",
            networks: networks,
            gateway: "192.168.1.1",
            hasEthernetAddress: true
        )

        for cidr in [
            "192.168.0.0/23",
            "192.168.1.18/24",
            "192.168.2.0/24",
            "8.8.8.0/24",
            "192.168.1.0/16",
            "192.168.1.0/31",
        ] {
            #expect(throws: RPCError.self) {
                try validateARPScanCIDR(
                    cidr,
                    interface: "en0",
                    networks: networks,
                    gateway: "192.168.1.1",
                    hasEthernetAddress: true
                )
            }
        }

        #expect(throws: RPCError.self) {
            try validateARPScanCIDR(
                "192.168.1.0/24",
                interface: "utun4",
                networks: networks,
                gateway: "192.168.1.1",
                hasEthernetAddress: false
            )
        }
    }

    @Test("Default route parser rejects ambiguity and invalid interfaces")
    func parsesDefaultRoute() {
        let route = """
           route to: default
        destination: default
            gateway: 192.168.1.1
          interface: en0
        """
        #expect(
            ipv4DefaultRoute(from: route)
                == IPv4DefaultRoute(
                    gateway: "192.168.1.1",
                    interface: "en0"
                )
        )
        #expect(
            ipv4DefaultRoute(from: route + "\ninterface: en1") == nil
        )
        #expect(
            ipv4DefaultRoute(
                from: "gateway: 8.8.8.8\ninterface: en0"
            ) == nil
        )
    }

    @Test("Default route observation explicitly selects IPv4")
    func observesIPv4DefaultRoute() throws {
        var observedExecutable: String?
        var observedArguments: [String]?
        let route = try observeIPv4DefaultRoute { executable, arguments in
            observedExecutable = executable
            observedArguments = arguments
            return CommandResult(
                status: 0,
                stdout: """
                   route to: default
                destination: default
                       mask: default
                    gateway: 192.168.1.1
                  interface: en0
                      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
                """,
                stderr: ""
            )
        }

        #expect(observedExecutable == "/sbin/route")
        #expect(
            observedArguments == ["-n", "get", "-inet", "default"]
        )
        #expect(
            route == IPv4DefaultRoute(
                gateway: "192.168.1.1",
                interface: "en0"
            )
        )
    }
}
