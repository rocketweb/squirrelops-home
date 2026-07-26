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
    private let testInterfaceAddresses = [
        (interface: "lo0", address: "127.0.0.1"),
        (interface: "en0", address: "192.168.1.18"),
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

    @Test("Listener ownership race quarantines and kills endpoint states")
    func listenerRaceCleansRedirectStates() throws {
        let endpoints: [[String: Any]] = [[
            "ip": "192.168.1.200",
            "direct_ports": [Int](),
        ]]
        // Normal flow first loads block-only quarantine before the alias is
        // published. Even though the cached and fallback rules match, a state
        // may have formed while the redirect rules were briefly live.
        let live = try pfEndpointStateSignatures(
            forwardingRules: [],
            protectedEndpoints: endpoints,
            interface: "en0"
        )
        var cache = cleanCache(with: live)
        var calls: [[String]] = []

        try quarantinePortForwardingAfterListenerRace(
            protectedEndpoints: endpoints,
            interface: "en0",
            stateCache: &cache
        ) { arguments, input in
            calls.append(arguments)
            if arguments == [
                "-a", "com.apple/squirrelops", "-f", "-",
            ] {
                let text = input.flatMap {
                    String(data: $0, encoding: .utf8)
                } ?? ""
                #expect(!text.contains("rdr pass"))
                #expect(
                    text.contains(
                        "block drop in quick inet from any to 192.168.1.200"
                    )
                )
                return CommandResult(status: 0, stdout: "", stderr: "")
            }
            if arguments == ["-s", "info"] {
                return CommandResult(
                    status: 0,
                    stdout: "Status: Enabled\n",
                    stderr: ""
                )
            }
            if arguments == [
                "-k", "0.0.0.0/0", "-k", "192.168.1.200",
            ] {
                return CommandResult(status: 0, stdout: "", stderr: "")
            }
            Issue.record("Unexpected pfctl call: \(arguments)")
            return CommandResult(status: 1, stdout: "", stderr: "")
        }

        #expect(
            calls == [
                ["-a", "com.apple/squirrelops", "-f", "-"],
                ["-s", "info"],
                ["-k", "0.0.0.0/0", "-k", "192.168.1.200"],
                ["-s", "info"],
            ]
        )
        #expect(cache.cleanupIPs(for: [:]) == ["192.168.1.200"])
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

    @Test("PF redirects require the observed interface and owned protected VIPs")
    func authorizesOnlyOwnedPFEndpoints() throws {
        let listeners = try validatePortForwardRequest(
            forwardingRules: [forwardingRule],
            protectedEndpoints: [[
                "ip": "192.168.1.200",
                "direct_ports": [Int](),
            ]],
            interface: "en0",
            route: testDefaultRoute,
            networks: testNetworks,
            interfaceAddresses: testInterfaceAddresses,
            ownedEntries: [OwnedVirtualIP(ip: "192.168.1.200", interface: "en0")]
        )

        #expect(
            listeners
                == [PFBackendListener(ip: "192.168.1.200", port: 10080)]
        )

        #expect(throws: RPCError.self) {
            try validatePortForwardRequest(
                forwardingRules: [forwardingRule],
                protectedEndpoints: [[
                    "ip": "192.168.1.200",
                    "direct_ports": [Int](),
                ]],
                interface: "en1",
                route: testDefaultRoute,
                networks: testNetworks,
                interfaceAddresses: testInterfaceAddresses,
                ownedEntries: [
                    OwnedVirtualIP(ip: "192.168.1.200", interface: "en0"),
                ]
            )
        }
        #expect(throws: RPCError.self) {
            try validatePortForwardRequest(
                forwardingRules: [[
                    "from_ip": "127.0.0.1",
                    "from_port": 80,
                    "to_ip": "127.0.0.1",
                    "to_port": 10080,
                ]],
                protectedEndpoints: [[
                    "ip": "127.0.0.1",
                    "direct_ports": [Int](),
                ]],
                interface: "en0",
                route: testDefaultRoute,
                networks: testNetworks,
                interfaceAddresses: testInterfaceAddresses,
                ownedEntries: [
                    OwnedVirtualIP(ip: "192.168.1.200", interface: "en0"),
                ]
            )
        }
    }

    @Test("PF replacements cannot omit owned aliases or allow direct host ports")
    func requiresCompleteOwnedPFProtection() {
        let owned: Set<OwnedVirtualIP> = [
            OwnedVirtualIP(ip: "192.168.1.200", interface: "en0"),
            OwnedVirtualIP(ip: "192.168.1.201", interface: "en0"),
        ]

        #expect(throws: RPCError.self) {
            try validatePortForwardRequest(
                forwardingRules: [forwardingRule],
                protectedEndpoints: [[
                    "ip": "192.168.1.200",
                    "direct_ports": [Int](),
                ]],
                interface: "en0",
                route: testDefaultRoute,
                networks: testNetworks,
                interfaceAddresses: testInterfaceAddresses,
                ownedEntries: owned
            )
        }
        #expect(throws: RPCError.self) {
            try validatePortForwardRequest(
                forwardingRules: [forwardingRule],
                protectedEndpoints: [
                    ["ip": "192.168.1.200", "direct_ports": [8443]],
                    ["ip": "192.168.1.201", "direct_ports": [Int]()],
                ],
                interface: "en0",
                route: testDefaultRoute,
                networks: testNetworks,
                interfaceAddresses: testInterfaceAddresses,
                ownedEntries: owned
            )
        }
    }

    @Test("Unowned PF endpoints are bounded quarantine-only candidates")
    func boundsPreAliasQuarantine() throws {
        let endpoints: [[String: Any]] = [[
            "ip": "192.168.1.200",
            "direct_ports": [Int](),
        ]]
        let listeners = try validatePortForwardRequest(
            forwardingRules: [],
            protectedEndpoints: endpoints,
            interface: "en0",
            route: testDefaultRoute,
            networks: testNetworks,
            interfaceAddresses: testInterfaceAddresses,
            ownedEntries: []
        )
        #expect(listeners.isEmpty)

        #expect(throws: RPCError.self) {
            try validatePortForwardRequest(
                forwardingRules: [],
                protectedEndpoints: endpoints,
                interface: "en0",
                route: testDefaultRoute,
                networks: testNetworks,
                interfaceAddresses: testInterfaceAddresses + [
                    (interface: "en7", address: "192.168.1.200"),
                ],
                ownedEntries: []
            )
        }
        #expect(throws: RPCError.self) {
            try validatePortForwardRequest(
                forwardingRules: [forwardingRule],
                protectedEndpoints: endpoints,
                interface: "en0",
                route: testDefaultRoute,
                networks: testNetworks,
                interfaceAddresses: testInterfaceAddresses,
                ownedEntries: []
            )
        }
        #expect(throws: RPCError.self) {
            try validatePortForwardRequest(
                forwardingRules: [],
                protectedEndpoints: [[
                    "ip": "192.168.1.199",
                    "direct_ports": [Int](),
                ]],
                interface: "en0",
                route: testDefaultRoute,
                networks: testNetworks,
                interfaceAddresses: testInterfaceAddresses,
                ownedEntries: []
            )
        }
    }

    @Test("First-ledger quarantine accepts the complete 51-address pool")
    func acceptsCompleteFirstLedgerQuarantinePool() throws {
        let endpoints: [[String: Any]] = (200...250).map { octet in
            [
                "ip": "192.168.1.\(octet)",
                "direct_ports": [Int](),
            ]
        }

        let listeners = try validatePortForwardRequest(
            forwardingRules: [],
            protectedEndpoints: endpoints,
            interface: "en0",
            route: testDefaultRoute,
            networks: testNetworks,
            interfaceAddresses: testInterfaceAddresses,
            ownedEntries: []
        )

        #expect(listeners.isEmpty)
    }

    @Test("First-ledger quarantine rejects addresses outside its bounded pool")
    func rejectsFirstLedgerQuarantineOutsideCandidatePool() {
        let endpoints: [[String: Any]] = (199...250).map { octet in
            [
                "ip": "192.168.1.\(octet)",
                "direct_ports": [Int](),
            ]
        }

        #expect(throws: RPCError.self) {
            try validatePortForwardRequest(
                forwardingRules: [],
                protectedEndpoints: endpoints,
                interface: "en0",
                route: testDefaultRoute,
                networks: testNetworks,
                interfaceAddresses: testInterfaceAddresses,
                ownedEntries: []
            )
        }
    }

    @Test(
        "PF quarantine rejects addresses newly assigned on any local interface"
    )
    func rechecksGlobalLocalAddressesBeforePFLoad() throws {
        let endpoints: [[String: Any]] = [[
            "ip": "192.168.1.200",
            "direct_ports": [Int](),
        ]]

        try requireNoLocalAddressConflictsForPreAliasQuarantine(
            protectedEndpoints: endpoints,
            interface: "en0",
            ownedEntries: [],
            interfaceAddresses: testInterfaceAddresses
        )
        #expect(throws: RPCError.self) {
            try requireNoLocalAddressConflictsForPreAliasQuarantine(
                protectedEndpoints: endpoints,
                interface: "en0",
                ownedEntries: [],
                interfaceAddresses: testInterfaceAddresses + [
                    (interface: "utun4", address: "192.168.1.200"),
                ]
            )
        }

        // An exact helper-owned loopback alias is not a pre-alias candidate.
        try requireNoLocalAddressConflictsForPreAliasQuarantine(
            protectedEndpoints: endpoints,
            interface: "en0",
            ownedEntries: [
                OwnedVirtualIP(ip: "192.168.1.200", interface: "en0"),
            ],
            interfaceAddresses: testInterfaceAddresses + [
                (interface: "lo0", address: "192.168.1.200"),
            ]
        )
    }

    @Test("PF redirects must stay on one VIP with unique ports")
    func rejectsAmbiguousPFRedirects() {
        let owned: Set<OwnedVirtualIP> = [
            OwnedVirtualIP(ip: "192.168.1.200", interface: "en0"),
        ]
        let endpoints: [[String: Any]] = [[
            "ip": "192.168.1.200",
            "direct_ports": [Int](),
        ]]

        #expect(throws: RPCError.self) {
            try validatePortForwardRequest(
                forwardingRules: [[
                    "from_ip": "192.168.1.200",
                    "from_port": 80,
                    "to_ip": "192.168.1.201",
                    "to_port": 10080,
                ]],
                protectedEndpoints: endpoints,
                interface: "en0",
                route: testDefaultRoute,
                networks: testNetworks,
                interfaceAddresses: testInterfaceAddresses,
                ownedEntries: owned
            )
        }
        #expect(throws: RPCError.self) {
            try validatePortForwardRequest(
                forwardingRules: [forwardingRule, forwardingRule],
                protectedEndpoints: endpoints,
                interface: "en0",
                route: testDefaultRoute,
                networks: testNetworks,
                interfaceAddresses: testInterfaceAddresses,
                ownedEntries: owned
            )
        }
    }

    @Test("PF ownership is rechecked immediately before live mutation")
    func rechecksPFOwnership() throws {
        try revalidatePortForwardOwnership(
            forwardingRules: [forwardingRule],
            protectedEndpoints: [[
                "ip": "192.168.1.200",
                "direct_ports": [Int](),
            ]],
            interface: "en0",
            ownedEntries: [
                OwnedVirtualIP(ip: "192.168.1.200", interface: "en0"),
            ]
        )
        #expect(throws: RPCError.self) {
            try revalidatePortForwardOwnership(
                forwardingRules: [forwardingRule],
                protectedEndpoints: [[
                    "ip": "192.168.1.200",
                    "direct_ports": [Int](),
                ]],
                interface: "en0",
                ownedEntries: [
                    OwnedVirtualIP(ip: "192.168.1.201", interface: "en0"),
                ]
            )
        }
    }

    @Test("Virtual IP publication requires a successful PF quarantine")
    func requiresPFQuarantineBeforeAliasPublication() throws {
        var cache = PFEndpointStateCache()
        #expect(throws: RPCError.self) {
            try requirePFProtectedVirtualIP(
                ip: "192.168.1.200",
                interface: "en0",
                stateCache: cache
            )
        }

        let quarantine = try pfEndpointStateSignatures(
            forwardingRules: [],
            protectedEndpoints: [[
                "ip": "192.168.1.200",
                "direct_ports": [Int](),
            ]],
            interface: "en0"
        )
        cache.recordSuccessfulLiveMutation(
            quarantine,
            cleanupIPs: cache.cleanupIPs(for: quarantine)
        )
        cache.completeCleanup()

        try requirePFProtectedVirtualIP(
            ip: "192.168.1.200",
            interface: "en0",
            stateCache: cache
        )
        #expect(throws: RPCError.self) {
            try requirePFProtectedVirtualIP(
                ip: "192.168.1.200",
                interface: "en1",
                stateCache: cache
            )
        }
    }

    @Test("PF network context is unchanged immediately before mutation")
    func rechecksPFNetworkContext() throws {
        let routeResult = CommandResult(
            status: 0,
            stdout: """
               route to: default
            destination: default
                gateway: 192.168.1.1
              interface: en0
            """,
            stderr: ""
        )
        let interfaceResult = CommandResult(
            status: 0,
            stdout: """
            en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
                inet 192.168.1.18 netmask 0xffffff00 broadcast 192.168.1.255
            """,
            stderr: ""
        )
        try requireUnchangedPFNetworkContext(
            expectedRoute: testDefaultRoute,
            expectedNetworks: testNetworks,
            routeResult: routeResult,
            interfaceResult: interfaceResult
        )

        #expect(throws: RPCError.self) {
            try requireUnchangedPFNetworkContext(
                expectedRoute: testDefaultRoute,
                expectedNetworks: testNetworks,
                routeResult: CommandResult(
                    status: 0,
                    stdout: """
                       route to: default
                    destination: default
                        gateway: 192.168.2.1
                      interface: en1
                    """,
                    stderr: ""
                ),
                interfaceResult: interfaceResult
            )
        }
        #expect(throws: RPCError.self) {
            try requireUnchangedPFNetworkContext(
                expectedRoute: testDefaultRoute,
                expectedNetworks: testNetworks,
                routeResult: routeResult,
                interfaceResult: CommandResult(
                    status: 0,
                    stdout: """
                    en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
                        inet 10.0.0.18 netmask 0xffffff00 broadcast 10.0.0.255
                    """,
                    stderr: ""
                )
            )
        }
    }

    @Test("Backend listeners require one exact sensor-owned VIP bind")
    func validatesBackendListenerOwnership() throws {
        let listener = PFBackendListener(
            ip: "192.168.1.200",
            port: 10080
        )
        try requireSensorOwnedListener(
            listener,
            serviceUID: 309
        ) { executable, arguments in
            #expect(executable == "/usr/sbin/lsof")
            #expect(arguments.contains("-iTCP:10080"))
            return CommandResult(
                status: 0,
                stdout: """
                p123
                u309
                f10
                n192.168.1.200:10080
                """,
                stderr: ""
            )
        }

        for output in [
            "p123\nu0\nf10\nn192.168.1.200:10080\n",
            "p123\nu309\nf10\nn*:10080\n",
            "p123\nu309\nf10\n",
            """
            p123
            u309
            p124
            u309
            f11
            n192.168.1.200:10080
            """,
            """
            p123
            u309
            f10
            n192.168.1.200:10080
            p124
            u309
            f11
            n192.168.1.200:10080
            """,
        ] {
            #expect(throws: RPCError.self) {
                try requireSensorOwnedListener(
                    listener,
                    serviceUID: 309
                ) { _, _ in
                    CommandResult(status: 0, stdout: output, stderr: "")
                }
            }
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

    @Test("Virtual IP policy is derived from the selected interface")
    func parsesInterfaceAddressPolicy() throws {
        let networks = try interfaceIPv4Networks(
            from: """
            en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
                ether 1c:1d:d3:e0:7d:03
                inet 192.168.1.18 netmask 0xffffff00 broadcast 192.168.1.255
            """
        )

        #expect(networks.count == 1)
        #expect(networks[0].address == "192.168.1.18")
        #expect(networks[0].network == "192.168.1.0")
        #expect(networks[0].broadcast == "192.168.1.255")
        try validateVirtualIPAddress(
            "192.168.1.200",
            interface: "en0",
            networks: networks,
            gateway: "192.168.1.1"
        )
    }

    @Test(
        "Virtual IP policy rejects gateway, boundaries, public, and off-subnet addresses",
        arguments: [
            "192.168.1.1",
            "192.168.1.0",
            "192.168.1.255",
            "192.168.1.199",
            "192.168.1.251",
            "192.168.2.200",
            "127.0.0.1",
            "8.8.8.8",
        ]
    )
    func rejectsUnsafeVirtualAddresses(ip: String) throws {
        let networks = try interfaceIPv4Networks(
            from: "inet 192.168.1.18 netmask 0xffffff00 broadcast 192.168.1.255"
        )

        #expect(throws: RPCError.self) {
            try validateVirtualIPAddress(
                ip,
                interface: "en0",
                networks: networks,
                gateway: "192.168.1.1"
            )
        }
    }

    @Test("Virtual IP pool uses fixed offsets from the observed network base")
    func enforcesHelperOwnedCandidatePool() throws {
        let networks = try interfaceIPv4Networks(
            from: """
            inet 192.168.1.18 netmask 0xfffffe00 broadcast 192.168.1.255
            """
        )

        try validateVirtualIPAddress(
            "192.168.0.200",
            interface: "en0",
            networks: networks,
            gateway: "192.168.1.1"
        )
        #expect(throws: RPCError.self) {
            try validateVirtualIPAddress(
                "192.168.1.200",
                interface: "en0",
                networks: networks,
                gateway: "192.168.1.1"
            )
        }
    }

    @Test("Duplicate-address probe accepts unresolved candidates without mutation")
    func acceptsUnresolvedCandidateWithoutMutation() throws {
        var commands: [[String]] = []
        var results = [
            CommandResult(
                status: 0,
                stdout:
                    "? (192.168.1.200) at (incomplete) "
                    + "on en0 ifscope [ethernet]\n",
                stderr: ""
            ),
            CommandResult(status: 2, stdout: "", stderr: ""),
            CommandResult(
                status: 0,
                stdout:
                    "? (192.168.1.200) at (incomplete) "
                    + "on en0 ifscope [ethernet]\n",
                stderr: ""
            ),
        ]

        try requireUnusedVirtualIPAddress(
            ip: "192.168.1.200",
            interface: "en0"
        ) { executable, arguments in
            commands.append([executable] + arguments)
            return results.removeFirst()
        }

        #expect(
            commands == [
                [
                    "/usr/sbin/arp", "-n", "-i", "en0",
                    "192.168.1.200",
                ],
                [
                    "/sbin/ping", "-n", "-b", "en0", "-c", "1",
                    "-W", "1000", "192.168.1.200",
                ],
                [
                    "/usr/sbin/arp", "-n", "-i", "en0",
                    "192.168.1.200",
                ],
            ]
        )
        #expect(!commands.contains(where: { $0.contains("-d") }))
        #expect(results.isEmpty)
    }

    @Test("Duplicate-address probe rejects an existing complete owner")
    func rejectsExistingAddressOwnerBeforeMutation() {
        var commands: [[String]] = []

        #expect(throws: RPCError.self) {
            try requireUnusedVirtualIPAddress(
                ip: "192.168.1.200",
                interface: "en0"
            ) { executable, arguments in
                commands.append([executable] + arguments)
                return CommandResult(
                    status: 0,
                    stdout:
                        "? (192.168.1.200) at aa:bb:cc:dd:ee:ff "
                        + "on en0 ifscope [ethernet]\n",
                    stderr: ""
                )
            }
        }

        #expect(commands.count == 1)
        #expect(!commands[0].contains("-d"))

        #expect(throws: RPCError.self) {
            try requireUnusedVirtualIPAddress(
                ip: "192.168.1.200",
                interface: "en0"
            ) { _, _ in
                CommandResult(
                    status: 0,
                    stdout:
                        "? (192.168.1.200) at aa:bb:cc:dd:ee:ff "
                        + "on en0 ifscope permanent published "
                        + "(proxy only) [ethernet]\n",
                    stderr: ""
                )
            }
        }
    }

    @Test("ICMP-drop still rejects an ARP-present address")
    func rejectsARPResponseWhenICMPDrops() {
        var commands: [[String]] = []
        var results = [
            CommandResult(
                status: 1,
                stdout:
                    "192.168.1.200 (192.168.1.200) "
                    + "-- no entry on en0\n",
                stderr: ""
            ),
            CommandResult(status: 2, stdout: "", stderr: ""),
            CommandResult(
                status: 0,
                stdout:
                    "? (192.168.1.200) at aa:bb:cc:dd:ee:ff "
                    + "on en0 ifscope [ethernet]\n",
                stderr: ""
            ),
        ]

        #expect(throws: RPCError.self) {
            try requireUnusedVirtualIPAddress(
                ip: "192.168.1.200",
                interface: "en0"
            ) { executable, arguments in
                commands.append([executable] + arguments)
                return results.removeFirst()
            }
        }

        #expect(commands.count == 3)
        #expect(!commands.contains(where: { $0.contains("-d") }))
        #expect(results.isEmpty)
    }

    @Test("Duplicate-address probe fails closed on command and parser errors")
    func duplicateProbeRejectsUnverifiableResults() {
        #expect(throws: RPCError.self) {
            try requireUnusedVirtualIPAddress(
                ip: "192.168.1.200",
                interface: "en0"
            ) { _, _ in
                CommandResult(
                    status: 64,
                    stdout: "",
                    stderr: "arp: invalid output"
                )
            }
        }

        var results = [
            CommandResult(
                status: 1,
                stdout:
                    "192.168.1.200 (192.168.1.200) "
                    + "-- no entry on en0\n",
                stderr: ""
            ),
            CommandResult(status: 68, stdout: "", stderr: "no route"),
        ]
        #expect(throws: RPCError.self) {
            try requireUnusedVirtualIPAddress(
                ip: "192.168.1.200",
                interface: "en0"
            ) { _, _ in
                results.removeFirst()
            }
        }
        #expect(results.isEmpty)

        var respondingResults = [
            CommandResult(
                status: 1,
                stdout:
                    "192.168.1.200 (192.168.1.200) "
                    + "-- no entry on en0\n",
                stderr: ""
            ),
            CommandResult(status: 0, stdout: "64 bytes", stderr: ""),
        ]
        #expect(throws: RPCError.self) {
            try requireUnusedVirtualIPAddress(
                ip: "192.168.1.200",
                interface: "en0"
            ) { _, _ in
                respondingResults.removeFirst()
            }
        }
        #expect(respondingResults.isEmpty)
    }

    @Test("Gateway policy requires the exact scoped route")
    func parsesScopedDefaultGateway() {
        let route = """
           route to: default
        destination: default
            gateway: 192.168.1.1
          interface: en0
        """

        #expect(
            defaultGateway(from: route, expectedInterface: "en0")
                == "192.168.1.1"
        )
        #expect(
            defaultGateway(from: route, expectedInterface: "en1") == nil
        )
        #expect(
            defaultGateway(
                from: "gateway: link#24\ninterface: en0",
                expectedInterface: "en0"
            ) == nil
        )
    }

    @Test("Alias removal requires durable helper ownership")
    func tracksAliasOwnershipDurably() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let stateFile = directory.appendingPathComponent("owned-aliases")
        defer { try? FileManager.default.removeItem(at: directory) }

        let store = VirtualIPOwnershipStore(
            stateFileURL: stateFile,
            expectedOwnerUID: geteuid(),
            expectedOwnerGID: getegid()
        )
        #expect(
            try !store.contains(ip: "192.168.1.200", interface: "en0")
        )

        try store.insert(ip: "192.168.1.200", interface: "en0")
        #expect(
            try store.contains(ip: "192.168.1.200", interface: "en0")
        )
        let directoryMode = try #require(
            FileManager.default.attributesOfItem(atPath: directory.path)[
                .posixPermissions
            ] as? NSNumber
        )
        let stateMode = try #require(
            FileManager.default.attributesOfItem(atPath: stateFile.path)[
                .posixPermissions
            ] as? NSNumber
        )
        #expect(directoryMode.intValue & 0o777 == 0o700)
        #expect(stateMode.intValue & 0o777 == 0o600)
        #expect(
            try !store.contains(ip: "192.168.1.200", interface: "en1")
        )

        let reloaded = VirtualIPOwnershipStore(
            stateFileURL: stateFile,
            expectedOwnerUID: geteuid(),
            expectedOwnerGID: getegid()
        )
        #expect(
            try reloaded.contains(ip: "192.168.1.200", interface: "en0")
        )

        try reloaded.remove(ip: "192.168.1.200", interface: "en0")
        #expect(
            try !store.contains(ip: "192.168.1.200", interface: "en0")
        )
    }

    @Test("Corrupt alias ownership state fails closed")
    func rejectsCorruptAliasOwnershipState() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let stateFile = directory.appendingPathComponent("owned-aliases")
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try Data("127.0.0.1|lo0\n".utf8).write(to: stateFile)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: stateFile.path
        )

        let store = VirtualIPOwnershipStore(
            stateFileURL: stateFile,
            expectedOwnerUID: geteuid(),
            expectedOwnerGID: getegid()
        )
        #expect(throws: RPCError.self) {
            try store.contains(ip: "192.168.1.200", interface: "en0")
        }
    }

    @Test("Alias ownership rejects a symlinked state file")
    func rejectsSymlinkedAliasOwnershipState() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let stateFile = directory.appendingPathComponent("owned-aliases")
        let targetFile = directory.appendingPathComponent("attacker-state")
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try Data("192.168.1.200|en0\n".utf8).write(to: targetFile)
        try FileManager.default.createSymbolicLink(
            at: stateFile,
            withDestinationURL: targetFile
        )

        let store = VirtualIPOwnershipStore(
            stateFileURL: stateFile,
            expectedOwnerUID: geteuid(),
            expectedOwnerGID: getegid()
        )
        #expect(throws: RPCError.self) {
            try store.contains(ip: "192.168.1.200", interface: "en0")
        }
    }

    @Test("Legacy unowned alias removal succeeds only when already absent")
    func allowsProvenAbsentLegacyAlias() throws {
        var commands: [[String]] = []
        var results = [
            CommandResult(
                status: 1,
                stdout:
                    "192.168.1.200 (192.168.1.200) "
                    + "-- no entry on en0\n",
                stderr: ""
            ),
            CommandResult(
                status: 0,
                stdout:
                    "? (192.168.1.1) at aa:bb:cc:dd:ee:ff "
                    + "on en0 ifscope [ethernet]\n",
                stderr: ""
            ),
        ]

        let disposition = try authorizeVirtualIPRemoval(
            ip: "192.168.1.200",
            interface: "en0",
            isOwned: false,
            interfaceAddresses: testInterfaceAddresses
        ) { executable, arguments in
            commands.append([executable] + arguments)
            return results.removeFirst()
        }

        #expect(disposition == .alreadyAbsent)
        #expect(
            commands == [
                [
                    "/usr/sbin/arp", "-n", "-i", "en0",
                    "192.168.1.200",
                ],
                ["/usr/sbin/arp", "-an"],
            ]
        )
        #expect(results.isEmpty)
        #expect(!commands.contains(where: {
            $0.contains("-d") || $0.first == "/sbin/ifconfig"
        }))
    }

    @Test("Durably owned alias removal proceeds without legacy probes")
    func allowsOwnedAliasWithdrawal() throws {
        var commandWasRun = false

        let disposition = try authorizeVirtualIPRemoval(
            ip: "192.168.1.200",
            interface: "en0",
            isOwned: true,
            interfaceAddresses: testInterfaceAddresses
        ) { _, _ in
            commandWasRun = true
            return CommandResult(status: 1, stdout: "", stderr: "")
        }

        #expect(disposition == .withdrawOwned)
        #expect(!commandWasRun)
    }

    @Test("Unowned alias removal rejects every local address")
    func rejectsUnownedLocalAlias() {
        var commandWasRun = false

        #expect(throws: RPCError.self) {
            try authorizeVirtualIPRemoval(
                ip: "192.168.1.200",
                interface: "en0",
                isOwned: false,
                interfaceAddresses: testInterfaceAddresses + [
                    (interface: "lo0", address: "192.168.1.200"),
                ]
            ) { _, _ in
                commandWasRun = true
                return CommandResult(status: 0, stdout: "", stderr: "")
            }
        }
        #expect(!commandWasRun)
    }

    @Test("Unowned alias removal rejects scoped or global proxy publication")
    func rejectsUnownedPublishedProxyARP() {
        let published =
            "? (192.168.1.200) at 1c:1d:d3:e0:7d:03 "
            + "on en0 ifscope permanent published "
            + "(proxy only) [ethernet]\n"

        #expect(throws: RPCError.self) {
            try authorizeVirtualIPRemoval(
                ip: "192.168.1.200",
                interface: "en0",
                isOwned: false,
                interfaceAddresses: testInterfaceAddresses
            ) { _, _ in
                CommandResult(status: 0, stdout: published, stderr: "")
            }
        }

        var results = [
            CommandResult(
                status: 1,
                stdout:
                    "192.168.1.200 (192.168.1.200) "
                    + "-- no entry on en0\n",
                stderr: ""
            ),
            CommandResult(status: 0, stdout: published, stderr: ""),
        ]
        #expect(throws: RPCError.self) {
            try authorizeVirtualIPRemoval(
                ip: "192.168.1.200",
                interface: "en0",
                isOwned: false,
                interfaceAddresses: testInterfaceAddresses
            ) { _, _ in
                results.removeFirst()
            }
        }
        #expect(results.isEmpty)
    }

    @Test("Unowned alias removal fails closed when ARP absence is unverified")
    func rejectsUnverifiedLegacyAbsence() {
        var results = [
            CommandResult(
                status: 1,
                stdout:
                    "192.168.1.200 (192.168.1.200) "
                    + "-- no entry on en0\n",
                stderr: ""
            ),
            CommandResult(
                status: 1,
                stdout: "",
                stderr: "arp table unavailable"
            ),
        ]

        #expect(throws: RPCError.self) {
            try authorizeVirtualIPRemoval(
                ip: "192.168.1.200",
                interface: "en0",
                isOwned: false,
                interfaceAddresses: testInterfaceAddresses
            ) { _, _ in
                results.removeFirst()
            }
        }
        #expect(results.isEmpty)
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

    private var testDefaultRoute: IPv4DefaultRoute {
        IPv4DefaultRoute(gateway: "192.168.1.1", interface: "en0")
    }

    private var testNetworks: [IPv4InterfaceNetwork] {
        [
            IPv4InterfaceNetwork(
                address: "192.168.1.18",
                network: "192.168.1.0",
                broadcast: "192.168.1.255"
            ),
        ]
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
