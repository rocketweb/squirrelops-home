import Foundation
import Testing
@testable import SquirrelOpsHelper

@Suite("PF listener ownership guards")
struct PFListenerGuardTests {
    private let endpoint: [[String: Any]] = [
        ["ip": "192.168.1.200", "direct_ports": [Int]()],
    ]
    private let forwarding: [[String: Any]] = [[
        "from_ip": "192.168.1.200", "from_port": 22,
        "to_ip": "192.168.1.200", "to_port": 49122,
    ]]

    @Test("Redirects require both translation provenance and the sensor socket UID")
    func redirectCannotBypassOwnerCheck() throws {
        let rules = try buildPFRules(
            forwardingRules: forwarding, protectedEndpoints: endpoint,
            interface: "en0", sensorUID: 550
        )
        #expect(!rules.contains { $0.hasPrefix("rdr pass ") })
        let redirect = try #require(rules.first { $0.hasPrefix("rdr ") })
        #expect(redirect.contains(" tag squirrelops_192_168_1_200_22_49122 "))
        #expect(rules.contains(
            "pass in quick on en0 inet proto tcp from any to 192.168.1.200 "
                + "port 49122 user 550 flags any tagged squirrelops_192_168_1_200_22_49122 keep state"
        ))
        #expect(rules.last == "block drop in quick inet from any to 192.168.1.200")
        // Without a translation tag, a direct scan of the private high port
        // must not match any TCP pass rule, even for the trusted socket owner.
        #expect(rules.filter { $0.hasPrefix("pass ") && $0.contains("proto tcp") }
            .allSatisfy { $0.contains(" user 550 ") && $0.contains(" tagged ") })
    }

    @Test("Missing, root, and unknown socket owners cannot authorize TCP publication")
    func invalidOwnersFailClosed() {
        for uid: uid_t? in [nil, 0, .max] {
            #expect(throws: RPCError.self) {
                try buildPFRules(forwardingRules: forwarding, protectedEndpoints: endpoint,
                                 interface: "en0", sensorUID: uid)
            }
        }
    }

    @Test("A failed quarantine write still attempts state cleanup and retains cleanup debt")
    func quarantineFailureStillCleansStates() throws {
        let signatures = try pfEndpointStateSignatures(
            forwardingRules: forwarding, protectedEndpoints: endpoint, interface: "en0")
        var cache = PFEndpointStateCache()
        cache.recordSuccessfulLiveMutation(signatures, cleanupIPs: [])
        cache.completeCleanup()
        var calls: [[String]] = []
        #expect(throws: RPCError.self) {
            try quarantinePortForwardingAfterListenerRace(
                protectedEndpoints: endpoint, interface: "en0", stateCache: &cache
            ) { arguments, _ in
                calls.append(arguments)
                if arguments.contains("-f") {
                    return CommandResult(status: 1, stdout: "", stderr: "injected load failure")
                }
                return CommandResult(status: 0, stdout: "Status: Enabled\n", stderr: "")
            }
        }
        #expect(calls.contains(["-k", "0.0.0.0/0", "-k", "192.168.1.200"]))
        #expect(cache.cleanupIPs(for: signatures) == ["192.168.1.200"])
        #expect(!cache.protectsVirtualIP(ip: "192.168.1.200", interface: "en0"))
    }

    @Test("A thrown quarantine command and first state-cleanup failure cannot skip later endpoints")
    func commandFailureCleansEveryEndpoint() throws {
        let endpoints = endpoint + [["ip": "192.168.1.201", "direct_ports": [Int]()]]
        var cache = PFEndpointStateCache()
        var cleaned: [String] = []
        #expect(throws: RPCError.self) {
            try quarantinePortForwardingAfterListenerRace(
                protectedEndpoints: endpoints, interface: "en0", stateCache: &cache
            ) { arguments, _ in
                if arguments.contains("-f") { throw CommandExecutionError.timedOut }
                if arguments.first == "-k" {
                    cleaned.append(arguments.last!)
                    return CommandResult(status: 1, stdout: "", stderr: "injected cleanup failure")
                }
                return CommandResult(status: 0, stdout: "Status: Enabled\n", stderr: "")
            }
        }
        #expect(cleaned == ["192.168.1.200", "192.168.1.201"])
        #expect(cache.cleanupIPs(for: [:]) == cleaned)
    }

    @Test("A sensor UID change invalidates only TCP-bearing endpoint states")
    func ownerChangeRequiresStateCleanup() throws {
        let endpoints = endpoint + [["ip": "192.168.1.201", "direct_ports": [Int]()]]
        let previous = try pfEndpointStateSignatures(
            forwardingRules: forwarding, protectedEndpoints: endpoints,
            interface: "en0", sensorUID: 550)
        let current = try pfEndpointStateSignatures(
            forwardingRules: forwarding, protectedEndpoints: endpoints,
            interface: "en0", sensorUID: 551)
        #expect(pfStateCleanupIPs(previous: previous, current: current) == ["192.168.1.200"])
        #expect(previous["192.168.1.201"] == current["192.168.1.201"])
    }

    @Test("Failed quarantine retains guarded live rules until a complete recovery succeeds")
    func failureThenRecovery() throws {
        var installed = try buildPFRules(
            forwardingRules: forwarding, protectedEndpoints: endpoint,
            interface: "en0", sensorUID: 550).joined(separator: "\n") + "\n"
        let signatures = try pfEndpointStateSignatures(
            forwardingRules: forwarding, protectedEndpoints: endpoint,
            interface: "en0", sensorUID: 550)
        var cache = PFEndpointStateCache()
        cache.recordSuccessfulLiveMutation(signatures, cleanupIPs: [])
        cache.completeCleanup()
        #expect(throws: RPCError.self) {
            try quarantinePortForwardingAfterListenerRace(
                protectedEndpoints: endpoint, interface: "en0", stateCache: &cache
            ) { arguments, _ in
                // Atomic load fails: the just-published generated rules remain.
                if arguments.contains("-f") {
                    return CommandResult(status: 1, stdout: "", stderr: "synthetic private diagnostic")
                }
                return CommandResult(status: 0, stdout: "Status: Enabled\n", stderr: "")
            }
        }
        #expect(!installed.contains("rdr pass"))
        #expect(installed.contains("user 550 flags any tagged squirrelops_"))
        #expect(!cache.protectsVirtualIP(ip: "192.168.1.200", interface: "en0"))
        try quarantinePortForwardingAfterListenerRace(
            protectedEndpoints: endpoint, interface: "en0", stateCache: &cache
        ) { arguments, input in
            if arguments.contains("-f") {
                installed = String(decoding: try #require(input), as: UTF8.self)
            }
            return CommandResult(status: 0, stdout: "Status: Enabled\n", stderr: "")
        }
        #expect(!installed.contains("rdr "))
        #expect(!installed.contains("proto tcp"))
        #expect(cache.protectsVirtualIP(ip: "192.168.1.200", interface: "en0"))
        let quarantine = try pfEndpointStateSignatures(
            forwardingRules: [], protectedEndpoints: endpoint, interface: "en0")
        #expect(cache.cleanupIPs(for: quarantine).isEmpty)
    }

    @Test("Tags are unique per redirect and the complete rules parse without changing PF")
    func tagsAreScopedAndRulesParse() throws {
        let rules = try buildPFRules(
            forwardingRules: forwarding + [[
                "from_ip": "192.168.1.200", "from_port": 445,
                "to_ip": "192.168.1.200", "to_port": 49445,
            ], [
                "from_ip": "192.168.1.201", "from_port": 22,
                "to_ip": "192.168.1.201", "to_port": 49122,
            ]],
            protectedEndpoints: endpoint + [["ip": "192.168.1.201", "direct_ports": [Int]()]],
            interface: "en0", sensorUID: 550)
        let tags = rules.filter { $0.hasPrefix("rdr ") }.compactMap { rule -> String? in
            let words = rule.split(separator: " ")
            guard let marker = words.firstIndex(of: "tag"), marker + 1 < words.count else { return nil }
            return String(words[marker + 1])
        }
        #expect(tags.count == 3 && Set(tags).count == 3)
        #expect(tags.allSatisfy { $0.utf8.count < 64 })
        for tag in tags {
            #expect(rules.filter { $0.contains("tagged \(tag) ") }.count == 1)
        }
        let result = try runPFCTL(arguments: ["-n", "-f", "-"],
            input: Data((rules.joined(separator: "\n") + "\n").utf8))
        #expect(result.status == 0, Comment(rawValue: result.stderr))
    }
}
