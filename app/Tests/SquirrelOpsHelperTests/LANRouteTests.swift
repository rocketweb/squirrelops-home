import Foundation
import Testing
@testable import SquirrelOpsHelper

struct LANRouteTests {
    @Test("Local MAC inventory RPC is available to the authenticated sensor")
    func localMACInventoryRegistered() {
        let router = RPCRouter()
        registerMethods(router: router)
        #expect(router.handlers["getLocalInterfaceMACs"] != nil)
    }

    @Test("Local identity observation uses fixed arguments and excludes placeholders")
    func localMACObservation() throws {
        let macs = try observeLocalInterfaceMACs { executable, arguments in
            #expect(executable == "/sbin/ifconfig")
            #expect(arguments == ["-a"])
            return CommandResult(status: 0, stdout: """
                en0: flags=1
                    ether 1c:1d:d3:e0:7d:03
                    ether 1c:1d:d3:e0:7d:03
                    ether 02:00:00:00:00:00
                    ether 00:00:00:00:00:00
                    ether ff:ff:ff:ff:ff:ff
                    ether invalid
                """, stderr: "")
        }
        #expect(macs == ["1c:1d:d3:e0:7d:03"])
    }

    @Test("Failed or redacted identity observation fails closed")
    func failedLocalMACObservation() {
        for result in [
            CommandResult(status: 1, stdout: "ether 1c:1d:d3:e0:7d:03", stderr: "failed"),
            CommandResult(status: 0, stdout: "ether 02:00:00:00:00:00", stderr: ""),
        ] {
            #expect(throws: (any Error).self) {
                try observeLocalInterfaceMACs { _, _ in result }
            }
        }
    }

    private func fixture(_ executable: String, _ arguments: [String]) -> CommandResult {
        var output = ""
        switch (executable, arguments) {
        case ("/sbin/route", ["-n", "get", "-inet", "default"]):
            output = "destination: default\ninterface: utun12"
        case ("/usr/sbin/networksetup", ["-listnetworkserviceorder"]):
            output = "(1) Ethernet\n(Hardware Port: Ethernet, Device: en0)\n(2) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en1)"
        case ("/sbin/route", ["-n", "get", "-inet", "-ifscope", "en0", "default"]):
            output = "destination: default\ngateway: 192.168.1.1\ninterface: en0"
        case ("/sbin/ifconfig", ["en0"]):
            output = "ether 00:11:22:33:44:55\ninet 192.168.1.18 netmask 0xffffff00 broadcast 192.168.1.255\nstatus: active"
        default:
            return CommandResult(status: 1, stdout: "", stderr: "No route")
        }
        return CommandResult(status: 0, stdout: output, stderr: "")
    }

    @Test("VPN default without a gateway selects the ordered physical LAN")
    func vpnDefaultSelectsPhysicalLAN() throws {
        let route = try observeIPv4DefaultRoute(using: fixture)
        #expect(route == IPv4DefaultRoute(gateway: "192.168.1.1", interface: "en0"))
    }

    @Test("A VPN with an RFC1918 gateway is not a physical LAN")
    func privateVPNGatewayDoesNotWin() throws {
        let route = try observeIPv4DefaultRoute { executable, arguments in
            if arguments == ipv4DefaultRouteCommandArguments {
                return CommandResult(status: 0, stdout: "gateway: 10.8.0.1\ninterface: utun12", stderr: "")
            }
            return fixture(executable, arguments)
        }
        #expect(route.interface == "en0")
    }

    @Test("A scoped route must name the independently selected physical interface")
    func mismatchedScopedRouteFailsClosed() {
        #expect(throws: (any Error).self) {
            try observeIPv4DefaultRoute { executable, arguments in
                if arguments.contains("-ifscope") {
                    return CommandResult(status: 0, stdout: "gateway: 192.168.1.1\ninterface: utun12", stderr: "")
                }
                return fixture(executable, arguments)
            }
        }
    }

    @Test("A physical LAN needs an on-link gateway and an Ethernet address")
    func missingHardwareAddressFailsClosed() {
        #expect(throws: (any Error).self) {
            try observeIPv4DefaultRoute { executable, arguments in
                if executable == "/sbin/ifconfig" {
                    return CommandResult(status: 0, stdout: "inet 192.168.1.18 netmask 0xffffff00 broadcast 192.168.1.255", stderr: "")
                }
                return fixture(executable, arguments)
            }
        }
    }

    @Test("An off-link private gateway is not a verified LAN")
    func offLinkGatewayFailsClosed() {
        #expect(throws: (any Error).self) {
            try observeIPv4DefaultRoute { executable, arguments in
                if arguments.contains("-ifscope") {
                    return CommandResult(status: 0, stdout: "gateway: 10.0.0.1\ninterface: en0", stderr: "")
                }
                return fixture(executable, arguments)
            }
        }
    }

    @Test("Read-only live LAN observation", .enabled(if:
        ProcessInfo.processInfo.environment["SQUIRRELOPS_TEST_LIVE_LAN"] == "1"
    ))
    func liveLANContext() throws {
        let route = try observeIPv4DefaultRoute { executable, arguments in
            try runCommand(executable: executable, arguments: arguments)
        }
        let info = try runCommand(executable: "/sbin/ifconfig", arguments: [route.interface])
        let context = try physicalLANContext(
            route: route, networks: interfaceIPv4Networks(from: info.stdout)
        )
        #expect(context["interface"] == route.interface)
        #expect(context["gateway_ip"] == route.gateway)
        let macs = try observeLocalInterfaceMACs { executable, arguments in
            try runCommand(executable: executable, arguments: arguments)
        }
        let primaryMAC = try #require(ethernetAddressFromIfconfig(info.stdout))
        #expect(macs.contains(primaryMAC))
        #expect(primaryMAC != "02:00:00:00:00:00")
        print("Live verified local MAC count: \(macs.count), selected LAN MAC: \(primaryMAC)")
        print("Live verified LAN: \(context)")
    }
}
