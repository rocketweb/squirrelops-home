import Foundation
import Testing

@testable import SquirrelOpsHelper

@Suite("PF virtual-IP isolation")
struct PFIsolationTests {
    private let forwardingRule: [String: Any] = [
        "from_ip": "192.168.1.200",
        "from_port": 80,
        "to_ip": "192.168.1.200",
        "to_port": 10080,
    ]

    @Test("Builds redirect-pass and default-deny alias rules")
    func buildsIsolatedRuleset() throws {
        let rules = try buildPFRules(
            forwardingRules: [forwardingRule],
            protectedEndpoints: [[
                "ip": "192.168.1.200",
                "direct_ports": [8443, 8080],
            ]],
            interface: "en0"
        )

        #expect(
            rules.contains(
                "rdr pass on en0 inet proto tcp from any to 192.168.1.200 "
                    + "port 80 -> 192.168.1.200 port 10080"
            )
        )
        #expect(
            rules.contains(
                "pass in quick on en0 inet proto tcp from any to 192.168.1.200 "
                    + "port { 8080, 8443 }"
            )
        )
        #expect(
            rules.contains(
                "pass in quick on en0 inet proto icmp from any to 192.168.1.200 "
                    + "icmp-type echoreq"
            )
        )
        #expect(
            rules.last
                == "block drop in quick inet from any to 192.168.1.200"
        )

        // The implementation-only high port is reachable through rdr-pass,
        // but a direct scan of :10080 must hit the final block.
        #expect(!rules.contains(where: { $0.contains("to 192.168.1.200 port 10080") }))
    }

    @Test("Protects aliases that only expose redirected ports")
    func noDirectPortsStillBlocksHostSurface() throws {
        let rules = try buildPFRules(
            forwardingRules: [forwardingRule],
            protectedEndpoints: [[
                "ip": "192.168.1.200",
                "direct_ports": [Int](),
            ]],
            interface: "en0"
        )

        #expect(rules.count == 3)
        #expect(rules[0].hasPrefix("rdr pass "))
        #expect(rules[1].contains("proto icmp"))
        #expect(rules[2].hasPrefix("block drop in quick"))
    }

    @Test("Default deny covers every ingress interface")
    func defaultDenyIsNotInterfaceScoped() throws {
        let rules = try buildPFRules(
            forwardingRules: [forwardingRule],
            protectedEndpoints: [[
                "ip": "192.168.1.200",
                "direct_ports": [Int](),
            ]],
            interface: "en0"
        )

        #expect(
            rules.contains("block drop in quick inet from any to 192.168.1.200")
        )
        #expect(
            !rules.contains(
                "block drop in quick on en0 inet from any to 192.168.1.200"
            )
        )
    }

    @Test("Merges duplicate protected endpoint entries before blocking")
    func mergesDuplicateEndpoints() throws {
        let rules = try buildPFRules(
            forwardingRules: [],
            protectedEndpoints: [
                ["ip": "192.168.1.200", "direct_ports": [8080]],
                ["ip": "192.168.1.200", "direct_ports": [8443]],
            ],
            interface: "en0"
        )

        #expect(rules.count == 3)
        #expect(rules[0].contains("port { 8080, 8443 }"))
        #expect(rules.filter { $0.hasPrefix("block ") }.count == 1)
    }

    @Test("First PF ruleset application cleans every endpoint state")
    func firstRulesetCleansEveryEndpoint() throws {
        let current = try pfEndpointStateSignatures(
            forwardingRules: [
                forwardingRule,
                [
                    "from_ip": "192.168.1.201",
                    "from_port": 443,
                    "to_ip": "192.168.1.201",
                    "to_port": 10443,
                ],
            ],
            protectedEndpoints: [
                ["ip": "192.168.1.200", "direct_ports": [8080]],
                ["ip": "192.168.1.201", "direct_ports": [8443]],
            ],
            interface: "en0"
        )

        #expect(
            pfStateCleanupIPs(previous: nil, current: current)
                == ["192.168.1.200", "192.168.1.201"]
        )
    }

    @Test("Equivalent PF endpoint signatures require no state cleanup")
    func equivalentRulesetSkipsStateCleanup() throws {
        let previous = try pfEndpointStateSignatures(
            forwardingRules: [
                forwardingRule,
                forwardingRule,
            ],
            protectedEndpoints: [
                ["ip": "192.168.1.200", "direct_ports": [8443, 8080]],
                ["ip": "192.168.1.200", "direct_ports": [8080]],
            ],
            interface: "en0"
        )
        let current = try pfEndpointStateSignatures(
            forwardingRules: [forwardingRule],
            protectedEndpoints: [[
                "ip": "192.168.1.200",
                "direct_ports": [8080, 8443],
            ]],
            interface: "en0"
        )

        #expect(
            pfStateCleanupIPs(previous: previous, current: current).isEmpty
        )
    }

    @Test("Changed redirects or direct ports clean only affected IP states")
    func changedRulesCleanAffectedEndpoints() throws {
        let previous = try pfEndpointStateSignatures(
            forwardingRules: [
                forwardingRule,
                [
                    "from_ip": "192.168.1.201",
                    "from_port": 443,
                    "to_ip": "192.168.1.201",
                    "to_port": 10443,
                ],
                [
                    "from_ip": "192.168.1.202",
                    "from_port": 22,
                    "to_ip": "192.168.1.202",
                    "to_port": 10022,
                ],
            ],
            protectedEndpoints: [
                ["ip": "192.168.1.200", "direct_ports": [8080]],
                ["ip": "192.168.1.201", "direct_ports": [8443]],
                ["ip": "192.168.1.202", "direct_ports": [2222]],
            ],
            interface: "en0"
        )
        let current = try pfEndpointStateSignatures(
            forwardingRules: [
                [
                    "from_ip": "192.168.1.200",
                    "from_port": 80,
                    "to_ip": "192.168.1.200",
                    "to_port": 10081,
                ],
                [
                    "from_ip": "192.168.1.201",
                    "from_port": 443,
                    "to_ip": "192.168.1.201",
                    "to_port": 10443,
                ],
                [
                    "from_ip": "192.168.1.202",
                    "from_port": 22,
                    "to_ip": "192.168.1.202",
                    "to_port": 10022,
                ],
            ],
            protectedEndpoints: [
                ["ip": "192.168.1.200", "direct_ports": [8080]],
                ["ip": "192.168.1.201", "direct_ports": [9443]],
                ["ip": "192.168.1.202", "direct_ports": [2222]],
            ],
            interface: "en0"
        )

        #expect(
            pfStateCleanupIPs(previous: previous, current: current)
                == ["192.168.1.200", "192.168.1.201"]
        )
    }

    @Test("Removed PF endpoints have their existing states cleaned")
    func removedEndpointStateIsCleaned() throws {
        let previous = try pfEndpointStateSignatures(
            forwardingRules: [forwardingRule],
            protectedEndpoints: [
                ["ip": "192.168.1.200", "direct_ports": [8080]],
                ["ip": "192.168.1.201", "direct_ports": [8443]],
            ],
            interface: "en0"
        )
        let current = try pfEndpointStateSignatures(
            forwardingRules: [forwardingRule],
            protectedEndpoints: [[
                "ip": "192.168.1.200",
                "direct_ports": [8080],
            ]],
            interface: "en0"
        )

        #expect(
            pfStateCleanupIPs(previous: previous, current: current)
                == ["192.168.1.201"]
        )
    }

    @Test("Failed removed-endpoint cleanup retains the removed IP")
    func failedRemovedEndpointCleanupIsRetried() {
        let previous = [
            "192.168.1.200": endpointSignature(directPorts: [8080]),
            "192.168.1.201": endpointSignature(directPorts: [8443]),
        ]
        let current = [
            "192.168.1.200": endpointSignature(directPorts: [8080]),
        ]
        var cache = cleanCache(with: previous)
        let firstAttempt = cache.cleanupIPs(for: current)
        #expect(firstAttempt == ["192.168.1.201"])

        cache.recordSuccessfulLiveMutation(
            current,
            cleanupIPs: firstAttempt
        )

        #expect(
            cache.cleanupIPs(for: current)
                == ["192.168.1.201"]
        )
    }

    @Test("Consecutive failed rule changes retain intermediate live IPs")
    func consecutiveRuleChangesRetainEveryCleanupIP() {
        let endpointA = [
            "192.168.1.200": endpointSignature(directPorts: [8080]),
        ]
        let endpointB = [
            "192.168.1.201": endpointSignature(directPorts: [8443]),
        ]
        let endpointC = [
            "192.168.1.202": endpointSignature(directPorts: [9443]),
        ]
        var cache = cleanCache(
            with: endpointA.merging(endpointB) { first, _ in first }
        )

        let removeB = cache.cleanupIPs(for: endpointA)
        #expect(removeB == ["192.168.1.201"])
        cache.recordSuccessfulLiveMutation(
            endpointA,
            cleanupIPs: removeB
        )

        // Cleanup of B failed. The anchor now contains A, so replacing it with
        // C must clean the intermediate A, pending B, and newly added C.
        #expect(
            cache.cleanupIPs(for: endpointC)
                == [
                    "192.168.1.200",
                    "192.168.1.201",
                    "192.168.1.202",
                ]
        )
    }

    @Test("Failed empty-ruleset cleanup retains every removed IP")
    func failedEmptyRulesetCleanupIsRetried() {
        let previous = [
            "192.168.1.200": endpointSignature(directPorts: [8080]),
            "192.168.1.201": endpointSignature(directPorts: [8443]),
        ]
        var cache = cleanCache(with: previous)
        let firstAttempt = cache.cleanupIPs(for: [:])
        cache.recordSuccessfulLiveMutation(
            [:],
            cleanupIPs: firstAttempt
        )

        #expect(
            cache.cleanupIPs(for: [:])
                == ["192.168.1.200", "192.168.1.201"]
        )
    }

    @Test("Failed clear cleanup retries pending IPs until cleanup succeeds")
    func failedClearCleanupIsRetried() {
        let previous = [
            "192.168.1.200": endpointSignature(directPorts: [8080]),
        ]
        var cache = cleanCache(with: previous)
        let firstAttempt = cache.cleanupIPs(for: [:])
        cache.recordSuccessfulLiveMutation(
            [:],
            cleanupIPs: firstAttempt
        )

        #expect(cache.cleanupIPs(for: [:]) == ["192.168.1.200"])

        cache.completeCleanup()
        #expect(cache.cleanupIPs(for: [:]).isEmpty)
    }

    @Test("Failed changed-endpoint cleanup retries the current endpoint")
    func failedCurrentEndpointCleanupIsRetried() {
        let previous = [
            "192.168.1.200": endpointSignature(directPorts: [8080]),
        ]
        let current = [
            "192.168.1.200": endpointSignature(directPorts: [8443]),
        ]
        var cache = cleanCache(with: previous)
        let firstAttempt = cache.cleanupIPs(for: current)
        #expect(firstAttempt == ["192.168.1.200"])

        cache.recordSuccessfulLiveMutation(
            current,
            cleanupIPs: firstAttempt
        )

        #expect(cache.cleanupIPs(for: current) == ["192.168.1.200"])
    }

    @Test("Generated rules pass the macOS pfctl parser")
    func generatedRulesParse() throws {
        let rules = try buildPFRules(
            forwardingRules: [forwardingRule],
            protectedEndpoints: [[
                "ip": "192.168.1.200",
                "direct_ports": [8080, 8443],
            ]],
            interface: "en0"
        )
        let result = try runPFCTL(
            arguments: ["-n", "-f", "-"],
            input: Data((rules.joined(separator: "\n") + "\n").utf8)
        )

        #expect(result.status == 0, Comment(rawValue: result.stderr))
    }

    @Test("PF enabled state accepts output stream, spacing, and case variants")
    func parsesPFEnabledStateRobustly() {
        #expect(
            packetFilteringIsEnabled(
                CommandResult(
                    status: 0,
                    stdout:
                        "Status: Enabled for 0 days 10:44:48 "
                        + "Debug: Urgent\n",
                    stderr: ""
                )
            )
        )
        #expect(
            packetFilteringIsEnabled(
                CommandResult(
                    status: 1,
                    stdout: "",
                    stderr: "  STATUS \t: \t eNaBlEd  \n"
                )
            )
        )
        #expect(
            !packetFilteringIsEnabled(
                CommandResult(
                    status: 0,
                    stdout: "Status: Disabled\n",
                    stderr: ""
                )
            )
        )
        #expect(
            !packetFilteringIsEnabled(
                CommandResult(
                    status: 0,
                    stdout: "Status: Enabled\n",
                    stderr: "Status: Disabled\n"
                )
            )
        )
    }

    @Test("PF enable skips mutation when the status is already enabled")
    func skipsPFEnableWhenAlreadyEnabled() throws {
        var calls: [[String]] = []

        try ensurePacketFilteringEnabled { arguments, _ in
            calls.append(arguments)
            return CommandResult(
                status: 1,
                stdout: "Status: Enabled for 0 days 10:44:48\n",
                stderr: "No ALTQ support in kernel\n"
            )
        }

        #expect(calls == [["-s", "info"]])
    }

    @Test("PF enable verifies state after a benign nonzero enable result")
    func verifiesPFStateAfterEnable() throws {
        var calls: [[String]] = []
        var statusChecks = 0

        try ensurePacketFilteringEnabled { arguments, _ in
            calls.append(arguments)
            if arguments == ["-e"] {
                return CommandResult(
                    status: 1,
                    stdout: "",
                    stderr: "pfctl: pf already enabled\n"
                )
            }

            statusChecks += 1
            let status = statusChecks == 1 ? "Disabled" : "Enabled"
            return CommandResult(
                status: 0,
                stdout: "Status: \(status)\n",
                stderr: ""
            )
        }

        #expect(calls == [["-s", "info"], ["-e"], ["-s", "info"]])
    }

    @Test("PF enable failure reports only bounded state diagnostics")
    func reportsSafePFEnableFailure() {
        var statusChecks = 0

        #expect(throws: RPCError.self) {
            try ensurePacketFilteringEnabled { arguments, _ in
                if arguments == ["-e"] {
                    return CommandResult(
                        status: 2,
                        stdout: "",
                        stderr: "secret-looking raw diagnostic"
                    )
                }

                statusChecks += 1
                return CommandResult(
                    status: statusChecks == 1 ? 1 : 3,
                    stdout: statusChecks == 1
                        ? "Status: Disabled\n"
                        : "unexpected output",
                    stderr: ""
                )
            }
        }

        do {
            try ensurePacketFilteringEnabled { arguments, _ in
                if arguments == ["-e"] {
                    return CommandResult(
                        status: 2,
                        stdout: "",
                        stderr: "secret-looking raw diagnostic"
                    )
                }
                return CommandResult(
                    status: 3,
                    stdout: "Status: Disabled\n",
                    stderr: ""
                )
            }
            Issue.record("Expected PF enable verification to fail")
        } catch {
            let detail = String(describing: error)
            #expect(detail.contains("enable exit=2"))
            #expect(detail.contains("status exit=3, reported=disabled"))
            #expect(!detail.contains("secret-looking"))
        }
    }

    @Test("PF post-load verification fails closed on unknown state")
    func verifiesPFStateAfterAnchorLoad() {
        #expect(throws: RPCError.self) {
            try requirePacketFilteringEnabled(
                phase: "after anchor load"
            ) { arguments, _ in
                #expect(arguments == ["-s", "info"])
                return CommandResult(
                    status: 0,
                    stdout: "No status line\n",
                    stderr: ""
                )
            }
        }
    }

    @Test("Rejects malformed rule data")
    func rejectsMalformedRules() {
        #expect(throws: RPCError.self) {
            try buildPFRules(
                forwardingRules: [[
                    "from_ip": "192.168.1.200",
                    "from_port": 0,
                    "to_ip": "192.168.1.200",
                    "to_port": 10080,
                ]],
                protectedEndpoints: [],
                interface: "en0"
            )
        }
        #expect(throws: RPCError.self) {
            try buildPFRules(
                forwardingRules: [],
                protectedEndpoints: [[
                    "ip": "192.168.1.200",
                    "direct_ports": [70000],
                ]],
                interface: "en0"
            )
        }
        #expect(throws: RPCError.self) {
            try buildPFRules(
                forwardingRules: [],
                protectedEndpoints: [],
                interface: "en0;pass"
            )
        }
    }

    @Test("IPv4 netmasks require contiguous one bits")
    func validatesNetmasks() {
        #expect(ipv4PrefixLength("255.255.255.255") == 32)
        #expect(ipv4PrefixLength("255.255.255.0") == 24)
        #expect(ipv4PrefixLength("255.255.0.0") == 16)
        #expect(ipv4PrefixLength("0.0.0.0") == 0)
        #expect(ipv4PrefixLength("255.0.255.0") == nil)
        #expect(ipv4PrefixLength("255.255.255.256") == nil)
    }

    @Test("IPv4 validation rejects ambiguous and malformed forms")
    func validatesIPv4Addresses() {
        #expect(isValidIPv4("192.168.1.200"))
        #expect(!isValidIPv4("192.168.001.200"))
        #expect(!isValidIPv4("192.168.1.256"))
        #expect(!isValidIPv4("192.168..200"))
        #expect(!isValidIPv4("-1.168.1.200"))
    }

    @Test("Virtual IPs use loopback ownership and scoped proxy ARP")
    func virtualIPCommandArguments() {
        #expect(
            loopbackAliasAddArguments(
                ip: "192.168.1.200",
                prefixLength: 32
            ) == ["lo0", "inet", "192.168.1.200/32", "alias"]
        )
        #expect(
            loopbackAliasRemoveArguments(ip: "192.168.1.200")
                == ["lo0", "-alias", "192.168.1.200"]
        )
        #expect(
            neighborARPDeleteArguments(
                ip: "192.168.1.200",
                interface: "en0"
            ) == ["-d", "192.168.1.200", "ifscope", "en0"]
        )
        #expect(
            proxyARPSetArguments(
                ip: "192.168.1.200",
                interface: "en0",
                ethernetAddress: "1c:1d:d3:e0:7d:03"
            )
                == [
                    "-s", "192.168.1.200", "1c:1d:d3:e0:7d:03", "pub", "only",
                    "ifscope", "en0",
                ]
        )
        #expect(
            proxyARPDeleteArguments(ip: "192.168.1.200", interface: "en0")
                == ["-d", "192.168.1.200", "pub", "ifscope", "en0"]
        )
        #expect(
            proxyARPLookupArguments(ip: "192.168.1.200", interface: "en0")
                == ["-n", "-i", "en0", "192.168.1.200"]
        )
    }

    @Test("Proxy ARP uses the selected interface hardware address")
    func parsesInterfaceHardwareAddress() {
        let output = """
        en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
            options=567<RXCSUM,TXCSUM,VLAN_MTU,TSO4,TSO6,AV,CHANNEL_IO>
            ether 1c:1d:d3:e0:7d:03
            inet 192.168.1.18 netmask 0xffffff00 broadcast 192.168.1.255
        """

        #expect(
            ethernetAddressFromIfconfig(output) == "1c:1d:d3:e0:7d:03"
        )
        #expect(ethernetAddressFromIfconfig("ether auto") == nil)
        #expect(ethernetAddressFromIfconfig("ether aa:bb:cc:dd:ee") == nil)
        #expect(
            ethernetAddressFromIfconfig(
                "ether aa:bb:cc:dd:ee:ff;touch-/tmp/owned"
            ) == nil
        )
    }

    @Test("Proxy ARP withdrawal requires authoritative absence")
    func verifiesProxyARPAbsence() {
        #expect(
            proxyARPEntryIsAbsent(
                CommandResult(
                    status: 1,
                    stdout:
                        "192.168.1.200 (192.168.1.200) "
                        + "-- no entry on en0\n",
                    stderr: ""
                ),
                ip: "192.168.1.200"
            )
        )
        #expect(
            proxyARPEntryIsAbsent(
                CommandResult(
                    status: 0,
                    stdout:
                        "? (192.168.1.200) at aa:bb:cc:dd:ee:ff "
                        + "on en0 ifscope [ethernet]\n",
                    stderr: ""
                ),
                ip: "192.168.1.200"
            )
        )
        #expect(
            !proxyARPEntryIsAbsent(
                CommandResult(
                    status: 0,
                    stdout:
                        "? (192.168.1.200) at aa:bb:cc:dd:ee:ff "
                        + "on en0 ifscope permanent published "
                        + "(proxy only) [ethernet]\n",
                    stderr: ""
                ),
                ip: "192.168.1.200"
            )
        )
        #expect(
            !proxyARPEntryIsAbsent(
                CommandResult(
                    status: 1,
                    stdout: "",
                    stderr: "unexpected failure"
                ),
                ip: "192.168.1.200"
            )
        )
        #expect(
            !proxyARPEntryIsAbsent(
                CommandResult(
                    status: 1,
                    stdout:
                        "192.168.1.200 (192.168.1.200) "
                        + "-- no entry on en0\n"
                        + "? (192.168.1.200) at aa:bb:cc:dd:ee:ff "
                        + "on en0 ifscope permanent published "
                        + "(proxy only) [ethernet]\n",
                    stderr: ""
                ),
                ip: "192.168.1.200"
            )
        )
    }

    @Test("Proxy ARP publication requires one exact scoped entry")
    func verifiesExactProxyARPPublication() {
        let matchingLookup = CommandResult(
            status: 0,
            stdout:
                "? (192.168.1.200) at (incomplete) "
                + "on en0 ifscope [ethernet]\n"
                + "? (192.168.1.200) at 1c:1d:d3:e0:7d:3 "
                + "on en0 ifscope permanent published "
                + "(proxy only) [ethernet]\n",
            stderr: ""
        )
        #expect(
            proxyARPEntryIsPublished(
                matchingLookup,
                ip: "192.168.1.200",
                interface: "en0",
                ethernetAddress: "1c:1d:d3:e0:7d:03"
            )
        )

        let incompleteOnly = CommandResult(
            status: 0,
            stdout:
                "? (192.168.1.200) at (incomplete) "
                + "on en0 ifscope [ethernet]\n",
            stderr: ""
        )
        #expect(
            !proxyARPEntryIsPublished(
                incompleteOnly,
                ip: "192.168.1.200",
                interface: "en0",
                ethernetAddress: "1c:1d:d3:e0:7d:03"
            )
        )

        let plainPublished = CommandResult(
            status: 0,
            stdout:
                "? (192.168.1.200) at 1c:1d:d3:e0:7d:3 "
                + "on en0 ifscope permanent published [ethernet]\n",
            stderr: ""
        )
        #expect(
            !proxyARPEntryIsPublished(
                plainPublished,
                ip: "192.168.1.200",
                interface: "en0",
                ethernetAddress: "1c:1d:d3:e0:7d:03"
            )
        )

        let splitEvidence = CommandResult(
            status: 0,
            stdout:
                "? (192.168.1.200) at 1c:1d:d3:e0:7d:3 "
                + "on en0 ifscope permanent [ethernet]\n"
                + "? (192.168.1.200) at aa:bb:cc:dd:ee:ff "
                + "on en1 ifscope permanent published "
                + "(proxy only) [ethernet]\n",
            stderr: ""
        )
        #expect(
            !proxyARPEntryIsPublished(
                splitEvidence,
                ip: "192.168.1.200",
                interface: "en0",
                ethernetAddress: "1c:1d:d3:e0:7d:03"
            )
        )
        #expect(
            !proxyARPEntryIsPublished(
                CommandResult(
                    status: 1,
                    stdout: matchingLookup.stdout,
                    stderr: ""
                ),
                ip: "192.168.1.200",
                interface: "en0",
                ethernetAddress: "1c:1d:d3:e0:7d:03"
            )
        )
    }

    @Test("Unverified proxy publication rolls back the complete virtual IP")
    func unverifiedPublicationRollsBack() {
        var commands: [[String]] = []
        var results = [
            CommandResult(status: 1, stdout: "", stderr: "no entry"),
            CommandResult(status: 1, stdout: "", stderr: "no entry"),
            CommandResult(status: 0, stdout: "", stderr: ""),
            CommandResult(status: 0, stdout: "", stderr: ""),
            CommandResult(
                status: 0,
                stdout:
                    "? (192.168.1.200) at (incomplete) "
                    + "on en0 ifscope [ethernet]\n",
                stderr: ""
            ),
            CommandResult(status: 0, stdout: "", stderr: ""),
            CommandResult(status: 0, stdout: "", stderr: ""),
        ]

        #expect(throws: RPCError.self) {
            try publishVirtualIP(
                ip: "192.168.1.200",
                interface: "en0",
                prefixLength: 32,
                ethernetAddress: "1c:1d:d3:e0:7d:03"
            ) { executable, arguments in
                commands.append([executable] + arguments)
                return results.removeFirst()
            }
        }

        #expect(
            commands == [
                [
                    "/usr/sbin/arp", "-d", "192.168.1.200",
                    "ifscope", "en0",
                ],
                [
                    "/usr/sbin/arp", "-d", "192.168.1.200",
                    "pub", "ifscope", "en0",
                ],
                [
                    "/sbin/ifconfig", "lo0", "inet",
                    "192.168.1.200/32", "alias",
                ],
                [
                    "/usr/sbin/arp", "-s", "192.168.1.200",
                    "1c:1d:d3:e0:7d:03", "pub", "only",
                    "ifscope", "en0",
                ],
                [
                    "/usr/sbin/arp", "-n", "-i", "en0",
                    "192.168.1.200",
                ],
                [
                    "/usr/sbin/arp", "-d", "192.168.1.200",
                    "pub", "ifscope", "en0",
                ],
                [
                    "/sbin/ifconfig", "lo0", "-alias",
                    "192.168.1.200",
                ],
            ]
        )
        #expect(results.isEmpty)
    }

    @Test("Verified proxy publication does not invoke rollback")
    func verifiedPublicationSucceeds() throws {
        var commands: [[String]] = []
        var results = [
            CommandResult(status: 1, stdout: "", stderr: "no entry"),
            CommandResult(status: 1, stdout: "", stderr: "no entry"),
            CommandResult(status: 0, stdout: "", stderr: ""),
            CommandResult(status: 0, stdout: "", stderr: ""),
            CommandResult(
                status: 0,
                stdout:
                    "? (192.168.1.200) at 1c:1d:d3:e0:7d:3 "
                    + "on en0 ifscope permanent published "
                    + "(proxy only) [ethernet]\n",
                stderr: ""
            ),
        ]

        try publishVirtualIP(
            ip: "192.168.1.200",
            interface: "en0",
            prefixLength: 32,
            ethernetAddress: "1c:1d:d3:e0:7d:03"
        ) { executable, arguments in
            commands.append([executable] + arguments)
            return results.removeFirst()
        }

        #expect(commands.count == 5)
        #expect(
            commands[0] == [
                "/usr/sbin/arp", "-d", "192.168.1.200",
                "ifscope", "en0",
            ]
        )
        #expect(
            commands[1] == [
                "/usr/sbin/arp", "-d", "192.168.1.200",
                "pub", "ifscope", "en0",
            ]
        )
        #expect(results.isEmpty)
    }

    @Test("Proxy withdrawal failure keeps the loopback alias in place")
    func proxyWithdrawalFailureKeepsAlias() {
        var commands: [[String]] = []
        var addressProviderCalled = false
        var results = [
            CommandResult(status: 0, stdout: "", stderr: ""),
            CommandResult(
                status: 0,
                stdout:
                    "? (192.168.1.200) at 1c:1d:d3:e0:7d:3 "
                    + "on en0 ifscope permanent published "
                    + "(proxy only) [ethernet]\n",
                stderr: ""
            ),
        ]

        #expect(throws: RPCError.self) {
            try withdrawVirtualIP(
                ip: "192.168.1.200",
                interface: "en0",
                hadLoopbackAlias: true,
                using: { executable, arguments in
                    commands.append([executable] + arguments)
                    return results.removeFirst()
                },
                interfaceAddresses: {
                    addressProviderCalled = true
                    return []
                }
            )
        }

        #expect(!commands.contains(where: { $0.first == "/sbin/ifconfig" }))
        #expect(!addressProviderCalled)
        #expect(results.isEmpty)
    }

    @Test("Virtual IP removal verifies both proxy and loopback absence")
    func verifiesCompleteVirtualIPRemoval() throws {
        var commands: [[String]] = []
        var results = [
            CommandResult(status: 0, stdout: "", stderr: ""),
            CommandResult(
                status: 1,
                stdout:
                    "192.168.1.200 (192.168.1.200) "
                    + "-- no entry on en0\n",
                stderr: ""
            ),
            CommandResult(status: 0, stdout: "", stderr: ""),
            CommandResult(
                status: 1,
                stdout:
                    "192.168.1.200 (192.168.1.200) "
                    + "-- no entry on en0\n",
                stderr: ""
            ),
        ]

        try withdrawVirtualIP(
            ip: "192.168.1.200",
            interface: "en0",
            hadLoopbackAlias: true,
            using: { executable, arguments in
                commands.append([executable] + arguments)
                return results.removeFirst()
            },
            interfaceAddresses: { [] }
        )

        #expect(
            commands == [
                [
                    "/usr/sbin/arp", "-d", "192.168.1.200",
                    "pub", "ifscope", "en0",
                ],
                [
                    "/usr/sbin/arp", "-n", "-i", "en0",
                    "192.168.1.200",
                ],
                [
                    "/sbin/ifconfig", "lo0", "-alias",
                    "192.168.1.200",
                ],
                [
                    "/usr/sbin/arp", "-n", "-i", "en0",
                    "192.168.1.200",
                ],
            ]
        )
        #expect(results.isEmpty)
    }

    @Test("Virtual IP removal fails when a split state remains")
    func removalRejectsSplitState() {
        var results = [
            CommandResult(status: 0, stdout: "", stderr: ""),
            CommandResult(
                status: 1,
                stdout:
                    "192.168.1.200 (192.168.1.200) "
                    + "-- no entry on en0\n",
                stderr: ""
            ),
            CommandResult(status: 0, stdout: "", stderr: ""),
            CommandResult(
                status: 1,
                stdout:
                    "192.168.1.200 (192.168.1.200) "
                    + "-- no entry on en0\n",
                stderr: ""
            ),
        ]

        #expect(throws: RPCError.self) {
            try withdrawVirtualIP(
                ip: "192.168.1.200",
                interface: "en0",
                hadLoopbackAlias: true,
                using: { _, _ in results.removeFirst() },
                interfaceAddresses: {
                    [(interface: "lo0", address: "192.168.1.200")]
                }
            )
        }
        #expect(results.isEmpty)
    }

    @Test("Runtime alias RPCs refuse every physical-interface address")
    func refusesPhysicalAddressConflicts() throws {
        #expect(throws: RPCError.self) {
            try validateNoPhysicalAddressConflict(
                ip: "192.168.1.200",
                interface: "en0",
                physicalAddressPresent: true
            )
        }
        try validateNoPhysicalAddressConflict(
            ip: "192.168.1.200",
            interface: "en0",
            physicalAddressPresent: false
        )
    }

    @Test("Alias publication detects addresses on alternate physical interfaces")
    func detectsDualInterfaceAddressConflicts() {
        let addresses = [
            (interface: "lo0", address: "127.0.0.1"),
            (interface: "en0", address: "192.168.1.18"),
            (interface: "en1", address: "192.168.1.79"),
        ]

        #expect(
            physicalInterfaceHasIPv4Address(
                "192.168.1.18",
                interfaceAddresses: addresses
            )
        )
        #expect(
            physicalInterfaceHasIPv4Address(
                "192.168.1.79",
                interfaceAddresses: addresses
            )
        )
        #expect(
            !physicalInterfaceHasIPv4Address(
                "127.0.0.1",
                interfaceAddresses: addresses
            )
        )
        #expect(
            !physicalInterfaceHasIPv4Address(
                "192.168.1.200",
                interfaceAddresses: addresses
            )
        )
    }

    @Test("Virtual IP addition refuses pre-existing loopback addresses")
    func refusesLoopbackAddressConflictsOnAdd() throws {
        #expect(throws: RPCError.self) {
            try validateAliasAddition(
                ip: "192.168.1.200",
                interface: "en0",
                physicalAddressPresent: false,
                loopbackAddressPresent: true
            )
        }
        try validateAliasAddition(
            ip: "192.168.1.200",
            interface: "en0",
            physicalAddressPresent: false,
            loopbackAddressPresent: false
        )
    }

    @Test("Loopback address detection sees the system loopback")
    func detectsLoopbackAddress() {
        #expect(interfaceHasIPv4Address("lo0", address: "127.0.0.1"))
        #expect(!interfaceHasIPv4Address("lo0", address: "192.0.2.255"))
    }

    private func endpointSignature(
        directPorts: [Int]
    ) -> PFEndpointStateSignature {
        PFEndpointStateSignature(
            interface: "en0",
            redirects: [],
            directPorts: directPorts
        )
    }

    private func cleanCache(
        with live: [String: PFEndpointStateSignature]
    ) -> PFEndpointStateCache {
        var cache = PFEndpointStateCache()
        let cleanupIPs = cache.cleanupIPs(for: live)
        cache.recordSuccessfulLiveMutation(
            live,
            cleanupIPs: cleanupIPs
        )
        cache.completeCleanup()
        return cache
    }
}
