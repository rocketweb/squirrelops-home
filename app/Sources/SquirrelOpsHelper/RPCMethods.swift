import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Registers all RPC method handlers with the router.
func registerMethods(router: RPCRouter) {
    // The helper's accept loop dispatches one RPC at a time, so this cache is
    // serialized with every PF mutation. It is intentionally process-local:
    // after a helper restart the first ruleset update cleans every endpoint.
    var pfEndpointStateCache = PFEndpointStateCache()
    let virtualIPOwnership = VirtualIPOwnershipStore()

    router.handlers["ping"] = { _ in
        [
            "status": "ok",
            "protocol_version": 1,
            "capabilities": [
                "arp_scan",
                "virtual_ip",
                "port_forward_isolation",
            ],
        ]
    }

    router.handlers["runARPScan"] = { params in
        guard let subnet = params["subnet"] as? String else {
            throw RPCError.internalError("Missing 'subnet' parameter")
        }
        let route = try observeIPv4DefaultRoute { executable, arguments in
            try runCommand(executable: executable, arguments: arguments)
        }
        let interfaceResult = try runCommand(
            executable: "/sbin/ifconfig",
            arguments: [route.interface]
        )
        guard interfaceResult.status == 0 else {
            throw RPCError.internalError(
                "Could not inspect the default-route interface"
            )
        }
        let networks = try interfaceIPv4Networks(
            from: interfaceResult.stdout
        )
        try validateARPScanCIDR(
            subnet,
            interface: route.interface,
            networks: networks,
            gateway: route.gateway,
            hasEthernetAddress:
                ethernetAddressFromIfconfig(interfaceResult.stdout) != nil
        )
        return try ARPScanner.scan(
            subnet: subnet,
            interface: route.interface
        )
    }

    router.handlers["addIPAlias"] = { params in
        guard let ip = params["ip"] as? String else {
            throw RPCError.internalError("Missing 'ip' parameter")
        }
        let interface = (params["interface"] as? String) ?? "en0"
        let mask = (params["mask"] as? String) ?? "255.255.255.255"

        // Validate interface name — only alphanumeric
        guard interface.allSatisfy({ $0.isLetter || $0.isNumber }) else {
            throw RPCError.internalError("Invalid interface name: \(interface)")
        }
        // Validate IP address format
        guard isValidIPv4(ip) else {
            throw RPCError.internalError("Invalid IP address: \(ip)")
        }
        guard let prefixLength = ipv4PrefixLength(mask) else {
            throw RPCError.internalError("Invalid netmask: \(mask)")
        }
        guard prefixLength == 32 else {
            throw RPCError.internalError(
                "Virtual IP aliases require a host netmask (255.255.255.255)"
            )
        }

        let interfaceInfo = try runCommand(
            executable: "/sbin/ifconfig",
            arguments: [interface]
        )
        guard interfaceInfo.status == 0 else {
            throw RPCError.internalError(
                "Could not inspect selected interface \(interface): "
                    + interfaceInfo.stderr
            )
        }
        let networks = try interfaceIPv4Networks(from: interfaceInfo.stdout)
        let route = try observeIPv4DefaultRoute { executable, arguments in
            try runCommand(executable: executable, arguments: arguments)
        }
        guard route.interface == interface else {
            throw RPCError.internalError(
                "Virtual IP interface must be the IPv4 default route"
            )
        }
        try validateVirtualIPAddress(
            ip,
            interface: interface,
            networks: networks,
            gateway: route.gateway
        )

        guard let interfaceAddresses = ipv4InterfaceAddresses() else {
            throw RPCError.internalError(
                "Could not enumerate local IPv4 addresses"
            )
        }
        let hasPhysicalAddress = physicalInterfaceHasIPv4Address(
            ip,
            interfaceAddresses: interfaceAddresses
        )
        let hasLoopbackAddress = interfaceAddresses.contains {
            $0.interface == "lo0" && $0.address == ip
        }
        try validateAliasAddition(
            ip: ip,
            interface: interface,
            physicalAddressPresent: hasPhysicalAddress,
            loopbackAddressPresent: hasLoopbackAddress
        )
        try requireUnusedVirtualIPAddress(
            ip: ip,
            interface: interface
        ) { executable, arguments in
            try runCommand(executable: executable, arguments: arguments)
        }

        guard let ethernetAddress = ethernetAddressFromIfconfig(
            interfaceInfo.stdout
        ) else {
            throw RPCError.internalError(
                "Could not determine hardware address for \(interface): "
                    + interfaceInfo.stderr
            )
        }

        try requirePFProtectedVirtualIP(
            ip: ip,
            interface: interface,
            stateCache: pfEndpointStateCache
        )
        let currentRouteInfo = try runCommand(
            executable: "/sbin/route",
            arguments: ipv4DefaultRouteCommandArguments
        )
        let currentInterfaceInfo = try runCommand(
            executable: "/sbin/ifconfig",
            arguments: [interface]
        )
        try requireUnchangedPFNetworkContext(
            expectedRoute: route,
            expectedNetworks: networks,
            routeResult: currentRouteInfo,
            interfaceResult: currentInterfaceInfo
        )
        try requirePacketFilteringEnabled(
            phase: "before virtual-IP publication"
        ) { arguments, input in
            try runPFCTL(arguments: arguments, input: input)
        }
        guard let publicationAddresses = ipv4InterfaceAddresses() else {
            throw RPCError.internalError(
                "Could not re-enumerate local IPv4 addresses before publication"
            )
        }
        try validateAliasAddition(
            ip: ip,
            interface: interface,
            physicalAddressPresent: physicalInterfaceHasIPv4Address(
                ip,
                interfaceAddresses: publicationAddresses
            ),
            loopbackAddressPresent: publicationAddresses.contains {
                $0.interface == "lo0" && $0.address == ip
            }
        )
        try requireUnusedVirtualIPAddress(
            ip: ip,
            interface: interface
        ) { executable, arguments in
            try runCommand(executable: executable, arguments: arguments)
        }

        // Record conservative ownership before the first OS mutation. A crash
        // can leave a stale claim, but cannot leave an untracked root-owned
        // alias that a compromised sensor can later abuse.
        try virtualIPOwnership.insert(ip: ip, interface: interface)
        do {
            try publishVirtualIP(
                ip: ip,
                interface: interface,
                prefixLength: prefixLength,
                ethernetAddress: ethernetAddress
            ) { executable, arguments in
                try runCommand(executable: executable, arguments: arguments)
            }
        } catch {
            // Publication already performs best-effort rollback. Prove both
            // halves absent before releasing the durable ownership claim.
            if let addresses = ipv4InterfaceAddresses() {
                let hadLoopbackAlias = addresses.contains {
                    $0.interface == "lo0" && $0.address == ip
                }
                if (try? withdrawVirtualIP(
                    ip: ip,
                    interface: interface,
                    hadLoopbackAlias: hadLoopbackAlias,
                    using: { executable, arguments in
                        try runCommand(
                            executable: executable,
                            arguments: arguments
                        )
                    },
                    interfaceAddresses: ipv4InterfaceAddresses
                )) != nil {
                    // A failure to update the ledger is safe: the stale claim
                    // continues to authorize only this exact scoped cleanup.
                    try? virtualIPOwnership.remove(
                        ip: ip,
                        interface: interface
                    )
                }
            }
            throw error
        }
        return [
            "success": true,
            "owner_interface": "lo0",
            "proxy_interface": interface,
        ]
    }

    router.handlers["setupPortForwards"] = { params in
        guard let rules = params["rules"] as? [[String: Any]] else {
            throw RPCError.internalError("Missing 'rules' parameter")
        }
        let protectedEndpoints =
            (params["protected_endpoints"] as? [[String: Any]]) ?? []
        let interface = (params["interface"] as? String) ?? "en0"

        let route = try observeIPv4DefaultRoute { executable, arguments in
            try runCommand(executable: executable, arguments: arguments)
        }
        let interfaceResult = try runCommand(
            executable: "/sbin/ifconfig",
            arguments: [route.interface]
        )
        guard interfaceResult.status == 0 else {
            throw RPCError.internalError(
                "Could not inspect the PF default-route interface"
            )
        }
        let networks = try interfaceIPv4Networks(from: interfaceResult.stdout)
        guard let initialInterfaceAddresses = ipv4InterfaceAddresses() else {
            throw RPCError.internalError(
                "Could not enumerate local IPv4 addresses for PF isolation"
            )
        }
        let backendListeners = try validatePortForwardRequest(
            forwardingRules: rules,
            protectedEndpoints: protectedEndpoints,
            interface: interface,
            route: route,
            networks: networks,
            interfaceAddresses: initialInterfaceAddresses,
            ownedEntries: try virtualIPOwnership.allEntries()
        )
        let pfRules = try buildPFRules(
            forwardingRules: rules,
            protectedEndpoints: protectedEndpoints,
            interface: interface
        )
        let endpointSignatures = try pfEndpointStateSignatures(
            forwardingRules: rules,
            protectedEndpoints: protectedEndpoints,
            interface: interface
        )
        let stateCleanupIPs = pfEndpointStateCache.cleanupIPs(
            for: endpointSignatures
        )

        if pfRules.isEmpty {
            guard try virtualIPOwnership.allEntries().isEmpty else {
                throw RPCError.internalError(
                    "Cannot clear PF while helper-owned aliases exist"
                )
            }
            // No rules — flush the anchor
            let flush = try runPFCTL(
                arguments: ["-a", "com.apple/squirrelops", "-F", "all"]
            )
            guard flush.status == 0 else {
                throw RPCError.internalError(
                    "pfctl anchor flush failed: \(flush.stderr)"
                )
            }
            pfEndpointStateCache.recordSuccessfulLiveMutation(
                endpointSignatures,
                cleanupIPs: stateCleanupIPs
            )
            try cleanupPFStates(for: stateCleanupIPs) { arguments, input in
                try runPFCTL(arguments: arguments, input: input)
            }
            pfEndpointStateCache.completeCleanup()
            return [
                "success": true,
                "rules_count": 0,
                "protected_endpoints_count": 0,
            ]
        }

        let rulesText = pfRules.joined(separator: "\n") + "\n"
        let rulesData = Data(rulesText.utf8)

        // Parse the complete replacement ruleset before changing live state.
        // Feeding stdin avoids a predictable root-owned temp-file path.
        let syntaxCheck = try runPFCTL(arguments: ["-n", "-f", "-"], input: rulesData)
        if syntaxCheck.status != 0 {
            throw RPCError.internalError(
                "pfctl rule validation failed: \(syntaxCheck.stderr)"
            )
        }

        // Do not treat `pfctl -e`'s exit status as the PF state. macOS returns
        // nonzero for benign cases such as an already-enabled race. Read the
        // authoritative status first, enable only when needed, then re-read it.
        try ensurePacketFilteringEnabled { arguments, input in
            try runPFCTL(arguments: arguments, input: input)
        }

        let currentOwnedEntries = try virtualIPOwnership.allEntries()
        try revalidatePortForwardOwnership(
            forwardingRules: rules,
            protectedEndpoints: protectedEndpoints,
            interface: interface,
            ownedEntries: currentOwnedEntries
        )
        if !backendListeners.isEmpty {
            guard let sensorUID = serviceAccountUID() else {
                throw RPCError.internalError(
                    "Sensor service account is unavailable"
                )
            }
            for listener in backendListeners {
                try requireSensorOwnedListener(
                    listener,
                    serviceUID: sensorUID
                ) { executable, arguments in
                    try runCommand(
                        executable: executable,
                        arguments: arguments
                    )
                }
            }
        }

        let currentRouteResult = try runCommand(
            executable: "/sbin/route",
            arguments: ipv4DefaultRouteCommandArguments
        )
        let currentInterfaceResult = try runCommand(
            executable: "/sbin/ifconfig",
            arguments: [interface]
        )
        try requireUnchangedPFNetworkContext(
            expectedRoute: route,
            expectedNetworks: networks,
            routeResult: currentRouteResult,
            interfaceResult: currentInterfaceResult
        )
        guard let currentInterfaceAddresses = ipv4InterfaceAddresses() else {
            throw RPCError.internalError(
                "Could not re-enumerate local IPv4 addresses before PF load"
            )
        }
        try requireNoLocalAddressConflictsForPreAliasQuarantine(
            protectedEndpoints: protectedEndpoints,
            interface: interface,
            ownedEntries: try virtualIPOwnership.allEntries(),
            interfaceAddresses: currentInterfaceAddresses
        )

        // Loading a complete anchor ruleset is atomic.
        let load = try runPFCTL(
            arguments: ["-a", "com.apple/squirrelops", "-f", "-"],
            input: rulesData
        )

        if load.status != 0 {
            throw RPCError.internalError("pfctl anchor load failed: \(load.stderr)")
        }
        if !backendListeners.isEmpty {
            do {
                guard let sensorUID = serviceAccountUID() else {
                    throw RPCError.internalError(
                        "Sensor service account disappeared"
                    )
                }
                for listener in backendListeners {
                    try requireSensorOwnedListener(
                        listener,
                        serviceUID: sensorUID
                    ) { executable, arguments in
                        try runCommand(
                            executable: executable,
                            arguments: arguments
                        )
                    }
                }
            } catch {
                try quarantinePortForwardingAfterListenerRace(
                    protectedEndpoints: protectedEndpoints,
                    interface: interface,
                    stateCache: &pfEndpointStateCache
                ) { arguments, input in
                    try runPFCTL(arguments: arguments, input: input)
                }
                throw error
            }
        }
        pfEndpointStateCache.recordSuccessfulLiveMutation(
            endpointSignatures,
            cleanupIPs: stateCleanupIPs
        )

        try requirePacketFilteringEnabled(
            phase: "after anchor load"
        ) { arguments, input in
            try runPFCTL(arguments: arguments, input: input)
        }

        // Existing states are evaluated before new filter rules.  Kill only
        // endpoint states whose redirect/direct-port contract changed. The
        // first call after helper startup still cleans every endpoint.
        try cleanupPFStates(for: stateCleanupIPs) { arguments, input in
            try runPFCTL(arguments: arguments, input: input)
        }
        pfEndpointStateCache.completeCleanup()

        return [
            "success": true,
            "rules_count": rules.count,
            "protected_endpoints_count": protectedEndpoints.count,
        ]
    }

    router.handlers["clearPortForwards"] = { _ in
        guard try virtualIPOwnership.allEntries().isEmpty else {
            throw RPCError.internalError(
                "Cannot clear PF while helper-owned aliases exist"
            )
        }
        let stateCleanupIPs = pfEndpointStateCache.cleanupIPs(for: [:])
        let flush = try runPFCTL(
            arguments: ["-a", "com.apple/squirrelops", "-F", "all"]
        )
        guard flush.status == 0 else {
            throw RPCError.internalError(
                "pfctl anchor flush failed: \(flush.stderr)"
            )
        }
        pfEndpointStateCache.recordSuccessfulLiveMutation(
            [:],
            cleanupIPs: stateCleanupIPs
        )
        try cleanupPFStates(for: stateCleanupIPs) { arguments, input in
            try runPFCTL(arguments: arguments, input: input)
        }
        pfEndpointStateCache.completeCleanup()
        return ["success": true]
    }

    router.handlers["removeIPAlias"] = { params in
        guard let ip = params["ip"] as? String else {
            throw RPCError.internalError("Missing 'ip' parameter")
        }
        let interface = (params["interface"] as? String) ?? "en0"

        // Validate interface name — only alphanumeric
        guard interface.allSatisfy({ $0.isLetter || $0.isNumber }) else {
            throw RPCError.internalError("Invalid interface name: \(interface)")
        }
        // Validate IP address format
        guard isValidIPv4(ip) else {
            throw RPCError.internalError("Invalid IP address: \(ip)")
        }
        let isOwned = try virtualIPOwnership.contains(
            ip: ip,
            interface: interface
        )

        guard let interfaceAddresses = ipv4InterfaceAddresses() else {
            throw RPCError.internalError(
                "Could not enumerate local IPv4 addresses"
            )
        }
        let removalDisposition = try authorizeVirtualIPRemoval(
            ip: ip,
            interface: interface,
            isOwned: isOwned,
            interfaceAddresses: interfaceAddresses
        ) { executable, arguments in
            try runCommand(executable: executable, arguments: arguments)
        }
        if removalDisposition == .alreadyAbsent {
            return [
                "success": true,
                "already_absent": true,
            ]
        }

        let hadLoopbackAlias = interfaceAddresses.contains {
            $0.interface == "lo0" && $0.address == ip
        }
        let hadLegacyAlias = interfaceAddresses.contains {
            $0.interface == interface && $0.address == ip
        }
        try validateNoPhysicalAddressConflict(
            ip: ip,
            interface: interface,
            physicalAddressPresent: hadLegacyAlias
        )

        try withdrawVirtualIP(
            ip: ip,
            interface: interface,
            hadLoopbackAlias: hadLoopbackAlias,
            using: { executable, arguments in
                try runCommand(executable: executable, arguments: arguments)
            },
            interfaceAddresses: ipv4InterfaceAddresses
        )
        // Remove durable authority only after the OS proves that both the
        // scoped proxy entry and loopback alias are absent.
        try virtualIPOwnership.remove(ip: ip, interface: interface)
        return ["success": true]
    }
}

/// Validates that a string is a valid IPv4 address (four octets 0-255).
func isValidIPv4(_ address: String) -> Bool {
    let parts = address.split(
        separator: ".",
        omittingEmptySubsequences: false
    )
    guard parts.count == 4 else { return false }
    return parts.allSatisfy { part in
        guard !part.isEmpty,
              part.allSatisfy(\.isNumber),
              (part.count == 1 || part.first != "0"),
              let num = Int(part),
              num >= 0,
              num <= 255 else {
            return false
        }
        return true
    }
}

/// Converts a contiguous dotted-quad IPv4 netmask to its prefix length.
func ipv4PrefixLength(_ mask: String) -> Int? {
    let parts = mask.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return nil }

    var value: UInt32 = 0
    for part in parts {
        guard let octet = UInt8(part) else { return nil }
        value = (value << 8) | UInt32(octet)
    }

    var sawZero = false
    var prefix = 0
    for bitIndex in (0..<32).reversed() {
        let bit = (value >> UInt32(bitIndex)) & 1
        if bit == 1 {
            guard !sawZero else { return nil }
            prefix += 1
        } else {
            sawZero = true
        }
    }
    return prefix
}

func loopbackAliasAddArguments(ip: String, prefixLength: Int) -> [String] {
    ["lo0", "inet", "\(ip)/\(prefixLength)", "alias"]
}

func loopbackAliasRemoveArguments(ip: String) -> [String] {
    ["lo0", "-alias", ip]
}

func neighborARPDeleteArguments(ip: String, interface: String) -> [String] {
    ["-d", ip, "ifscope", interface]
}

func proxyARPSetArguments(
    ip: String,
    interface: String,
    ethernetAddress: String
) -> [String] {
    [
        "-s", ip, ethernetAddress, "pub", "only",
        "ifscope", interface,
    ]
}

func proxyARPDeleteArguments(ip: String, interface: String) -> [String] {
    ["-d", ip, "pub", "ifscope", interface]
}

func proxyARPLookupArguments(ip: String, interface: String) -> [String] {
    ["-n", "-i", interface, ip]
}

typealias AliasCommandRunner = (
    _ executable: String,
    _ arguments: [String]
) throws -> CommandResult

typealias IPv4InterfaceAddressProvider = (
) -> [(interface: String, address: String)]?

enum VirtualIPRemovalDisposition: Equatable {
    case withdrawOwned
    case alreadyAbsent
}

/// Authorize withdrawal only from root-owned state.
///
/// A legacy install has no helper ownership ledger. Its graceful shutdown
/// withdraws every alias before the ledger-aware helper is installed, while
/// retaining the sensor's durable mimic rows. Treating that proven-absent
/// state as an idempotent success lets startup republish through `addIPAlias`,
/// which records root ownership before mutation. Any local address or
/// published proxy-ARP entry still fails closed; an unowned request never
/// reaches a mutating command.
func authorizeVirtualIPRemoval(
    ip: String,
    interface: String,
    isOwned: Bool,
    interfaceAddresses: [(interface: String, address: String)],
    using runner: AliasCommandRunner
) throws -> VirtualIPRemovalDisposition {
    if isOwned {
        return .withdrawOwned
    }

    guard !interfaceAddresses.contains(where: { $0.address == ip }) else {
        throw RPCError.internalError(
            "Refusing to remove an unowned virtual IP"
        )
    }

    let scopedLookup = try runner(
        "/usr/sbin/arp",
        proxyARPLookupArguments(ip: ip, interface: interface)
    )
    guard proxyARPEntryIsAbsent(scopedLookup, ip: ip) else {
        throw RPCError.internalError(
            "Refusing to remove an unowned virtual IP"
        )
    }

    let globalLookup = try runner("/usr/sbin/arp", ["-an"])
    guard globalProxyARPEntryIsAbsent(globalLookup, ip: ip) else {
        throw RPCError.internalError(
            "Refusing to remove an unowned virtual IP"
        )
    }
    return .alreadyAbsent
}

/// Owns a virtual IP on loopback and publishes it on the selected LAN.
///
/// The ARP scanner's ping sweep deliberately creates ordinary, often
/// incomplete, neighbor entries. macOS `arp -s` can then receive EEXIST from
/// the route socket while still exiting zero. Purge both scoped entry kinds,
/// install the alias, and require a scoped lookup to prove that the exact
/// published entry exists. Any unverified publication is rolled back.
func publishVirtualIP(
    ip: String,
    interface: String,
    prefixLength: Int,
    ethernetAddress: String,
    using runner: AliasCommandRunner
) throws {
    _ = try runner(
        "/usr/sbin/arp",
        neighborARPDeleteArguments(ip: ip, interface: interface)
    )
    _ = try runner(
        "/usr/sbin/arp",
        proxyARPDeleteArguments(ip: ip, interface: interface)
    )

    // Own the address as a host route on loopback, then publish a narrowly
    // scoped proxy-ARP entry on the LAN interface. Incoming LAN packets still
    // reach local mimic sockets and PF still filters on `interface`, but
    // Bonjour no longer treats the decoy as a normal LAN address of the Mac.
    let alias = try runner(
        "/sbin/ifconfig",
        loopbackAliasAddArguments(ip: ip, prefixLength: prefixLength)
    )
    guard alias.status == 0 else {
        rollbackVirtualIPPublication(
            ip: ip,
            interface: interface,
            using: runner
        )
        throw RPCError.internalError(
            "ifconfig loopback alias failed: \(alias.stderr)"
        )
    }

    let proxyARP: CommandResult
    let proxyLookup: CommandResult
    do {
        proxyARP = try runner(
            "/usr/sbin/arp",
            proxyARPSetArguments(
                ip: ip,
                interface: interface,
                ethernetAddress: ethernetAddress
            )
        )
        proxyLookup = try runner(
            "/usr/sbin/arp",
            proxyARPLookupArguments(ip: ip, interface: interface)
        )
    } catch {
        rollbackVirtualIPPublication(
            ip: ip,
            interface: interface,
            using: runner
        )
        throw RPCError.internalError(
            "proxy ARP setup could not be verified for \(ip)"
        )
    }

    guard proxyARP.status == 0,
          proxyARPEntryIsPublished(
              proxyLookup,
              ip: ip,
              interface: interface,
              ethernetAddress: ethernetAddress
          ) else {
        rollbackVirtualIPPublication(
            ip: ip,
            interface: interface,
            using: runner
        )
        throw RPCError.internalError(
            "proxy ARP setup could not be verified for \(ip)"
        )
    }
}

/// Withdraws a virtual IP and proves that neither half remains.
///
/// The pre-removal lookup prevents a proxy-delete failure from turning a
/// reachable decoy into an orphan proxy. The final checks prevent command exit
/// status from being mistaken for the actual kernel state.
func withdrawVirtualIP(
    ip: String,
    interface: String,
    hadLoopbackAlias: Bool,
    using runner: AliasCommandRunner,
    interfaceAddresses: IPv4InterfaceAddressProvider
) throws {
    let proxyDelete = try runner(
        "/usr/sbin/arp",
        proxyARPDeleteArguments(ip: ip, interface: interface)
    )
    let proxyLookup = try runner(
        "/usr/sbin/arp",
        proxyARPLookupArguments(ip: ip, interface: interface)
    )
    guard proxyARPEntryIsAbsent(proxyLookup, ip: ip) else {
        let detail = proxyDelete.stderr.isEmpty
            ? proxyLookup.stdout + proxyLookup.stderr
            : proxyDelete.stderr
        throw RPCError.internalError(
            "proxy ARP removal could not be verified for \(ip): \(detail)"
        )
    }

    var loopbackRemovalFailed = false
    if hadLoopbackAlias {
        do {
            let loopbackRemoval = try runner(
                "/sbin/ifconfig",
                loopbackAliasRemoveArguments(ip: ip)
            )
            loopbackRemovalFailed = loopbackRemoval.status != 0
        } catch {
            loopbackRemovalFailed = true
        }
    }

    let finalProxyLookup = try runner(
        "/usr/sbin/arp",
        proxyARPLookupArguments(ip: ip, interface: interface)
    )
    guard let currentAddresses = interfaceAddresses() else {
        throw RPCError.internalError(
            "Could not verify loopback alias removal for \(ip)"
        )
    }
    let loopbackAliasRemains = currentAddresses.contains {
        $0.interface == "lo0" && $0.address == ip
    }
    guard !loopbackRemovalFailed,
          proxyARPEntryIsAbsent(finalProxyLookup, ip: ip),
          !loopbackAliasRemains else {
        throw RPCError.internalError(
            "virtual IP removal left unverified state for \(ip)"
        )
    }
}

/// Best-effort rollback for a publication that was not proven successful.
///
/// Keep the operations independent so an ARP command launch failure cannot
/// prevent cleanup of the loopback alias.
private func rollbackVirtualIPPublication(
    ip: String,
    interface: String,
    using runner: AliasCommandRunner
) {
    _ = try? runner(
        "/usr/sbin/arp",
        proxyARPDeleteArguments(ip: ip, interface: interface)
    )
    _ = try? runner(
        "/sbin/ifconfig",
        loopbackAliasRemoveArguments(ip: ip)
    )
}

/// Extract a canonical hardware address from ``ifconfig <interface>``.
///
/// macOS ``arp ... auto pub only`` can fail after a /32 loopback route is
/// installed because automatic interface selection follows that new route
/// instead of the explicitly scoped LAN interface. Supplying the validated
/// physical-interface address avoids that ambiguity.
func ethernetAddressFromIfconfig(_ output: String) -> String? {
    for line in output.split(separator: "\n") {
        let fields = line.split(whereSeparator: \.isWhitespace)
        guard fields.count == 2, fields[0] == "ether" else {
            continue
        }
        let candidate = String(fields[1]).lowercased()
        let octets = candidate.split(
            separator: ":",
            omittingEmptySubsequences: false
        )
        guard octets.count == 6,
              octets.allSatisfy({
                  $0.count == 2 && $0.allSatisfy(\.isHexDigit)
              }) else {
            return nil
        }
        return candidate
    }
    return nil
}

/// Canonicalizes the padded and unpadded Ethernet forms emitted by macOS tools.
///
/// `ifconfig` commonly prints `...:03`, while `arp` may render the same final
/// octet as `...:3`.
func canonicalEthernetAddress(_ address: String) -> String? {
    let octets = address.lowercased().split(
        separator: ":",
        omittingEmptySubsequences: false
    )
    guard octets.count == 6 else {
        return nil
    }

    var canonical: [String] = []
    canonical.reserveCapacity(6)
    for octet in octets {
        guard !octet.isEmpty,
              octet.count <= 2,
              octet.allSatisfy(\.isHexDigit),
              let value = UInt8(octet, radix: 16) else {
            return nil
        }
        canonical.append(String(format: "%02x", value))
    }
    return canonical.joined(separator: ":")
}

/// Whether one exact scoped lookup line proves the expected proxy publication.
func proxyARPEntryIsPublished(
    _ result: CommandResult,
    ip: String,
    interface: String,
    ethernetAddress: String
) -> Bool {
    guard result.status == 0,
          let expectedAddress = canonicalEthernetAddress(ethernetAddress) else {
        return false
    }

    for line in (result.stdout + result.stderr)
        .split(whereSeparator: \.isNewline) {
        let fields = line.split(whereSeparator: \.isWhitespace).map(String.init)
        guard fields.contains("(\(ip))"),
              fields.contains(where: {
                  $0.caseInsensitiveCompare("published") == .orderedSame
              }),
              line.localizedCaseInsensitiveContains("(proxy only)"),
              let atIndex = fields.firstIndex(of: "at"),
              fields.indices.contains(atIndex + 1),
              canonicalEthernetAddress(fields[atIndex + 1])
                == expectedAddress,
              let onIndex = fields.firstIndex(of: "on"),
              fields.indices.contains(onIndex + 1),
              fields[onIndex + 1] == interface else {
            continue
        }
        return true
    }
    return false
}

/// Whether a scoped ``arp`` lookup proves there is no published proxy entry.
///
/// A successful lookup may still show a normal dynamic neighbor for the IP;
/// only the `published` marker represents the local proxy entry. A failed
/// lookup is accepted solely for the explicit macOS `-- no entry` response.
func proxyARPEntryIsAbsent(_ result: CommandResult, ip: String) -> Bool {
    let output = result.stdout + result.stderr
    var sawExactEntry = false
    var sawExactNoEntry = false
    var sawPublishedEntry = false
    for line in output.split(whereSeparator: \.isNewline) {
        let fields = line.split(whereSeparator: \.isWhitespace).map(String.init)
        guard fields.contains("(\(ip))") else {
            continue
        }
        if fields.contains(where: {
            $0.caseInsensitiveCompare("published") == .orderedSame
        }) {
            sawPublishedEntry = true
        } else if line.contains("-- no entry") {
            sawExactNoEntry = true
        } else {
            sawExactEntry = true
        }
    }
    guard !sawPublishedEntry else {
        return false
    }
    return sawExactNoEntry || (result.status == 0 && sawExactEntry)
}

/// Whether a complete ARP-table read proves no published entry for one IP.
///
/// Bound parsing so unexpectedly large output fails closed rather than turning
/// a compromised sensor request into expensive root-helper work.
func globalProxyARPEntryIsAbsent(
    _ result: CommandResult,
    ip: String
) -> Bool {
    guard result.status == 0 else {
        return false
    }
    let lines = (result.stdout + result.stderr)
        .split(whereSeparator: \.isNewline)
    guard lines.count <= 16_384 else {
        return false
    }
    for line in lines {
        let fields = line.split(whereSeparator: \.isWhitespace).map(String.init)
        guard fields.contains("(\(ip))") else {
            continue
        }
        if fields.contains(where: {
            $0.caseInsensitiveCompare("published") == .orderedSame
        }) {
            return false
        }
    }
    return true
}

/// Refuse to mutate any address already assigned to a physical interface.
///
/// Runtime helper calls have no provenance proving that a secondary address
/// belongs to SquirrelOps. Upgrade cleanup handles tracked legacy aliases
/// separately; treating any physical address as disposable could remove a
/// legitimate host address.
func validateNoPhysicalAddressConflict(
    ip: String,
    interface: String,
    physicalAddressPresent: Bool
) throws {
    if physicalAddressPresent {
        throw RPCError.internalError(
            "Refusing to replace existing IPv4 address \(ip) on \(interface)"
        )
    }
}

/// Require a fresh address for runtime alias publication.
///
/// Callers withdraw and verify tracked aliases before invoking add. Any
/// address still present on loopback therefore belongs to unknown local state
/// and must not be adopted or published through proxy ARP.
func validateAliasAddition(
    ip: String,
    interface: String,
    physicalAddressPresent: Bool,
    loopbackAddressPresent: Bool
) throws {
    try validateNoPhysicalAddressConflict(
        ip: ip,
        interface: interface,
        physicalAddressPresent: physicalAddressPresent
    )
    if loopbackAddressPresent {
        throw RPCError.internalError(
            "Refusing to adopt existing loopback IPv4 address \(ip)"
        )
    }
}

/// Enumerate every local IPv4 address and the interface that owns it.
///
/// Returning ``nil`` distinguishes an enumeration failure from a host with no
/// matching address so security-sensitive alias publication can fail closed.
func ipv4InterfaceAddresses() -> [(interface: String, address: String)]? {
#if canImport(Darwin)
    var firstAddress: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&firstAddress) == 0, let firstAddress else {
        return nil
    }
    defer { freeifaddrs(firstAddress) }

    var addresses: [(interface: String, address: String)] = []
    var cursor: UnsafeMutablePointer<ifaddrs>? = firstAddress
    while let entry = cursor {
        let value = entry.pointee
        defer { cursor = value.ifa_next }
        guard value.ifa_addr != nil,
              value.ifa_addr.pointee.sa_family == UInt8(AF_INET) else {
            continue
        }

        var socketAddress = value.ifa_addr.withMemoryRebound(
            to: sockaddr_in.self,
            capacity: 1
        ) { $0.pointee }
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(
            AF_INET,
            &socketAddress.sin_addr,
            &buffer,
            socklen_t(INET_ADDRSTRLEN)
        ) != nil else {
            continue
        }
        let bytes = buffer.prefix(while: { $0 != 0 }).map {
            UInt8(bitPattern: $0)
        }
        addresses.append((
            interface: String(cString: value.ifa_name),
            address: String(decoding: bytes, as: UTF8.self)
        ))
    }
    return addresses
#else
    return []
#endif
}

/// Whether any non-loopback interface already owns an exact IPv4 address.
func physicalInterfaceHasIPv4Address(
    _ address: String,
    interfaceAddresses: [(interface: String, address: String)]
) -> Bool {
    interfaceAddresses.contains {
        $0.interface != "lo0" && $0.address == address
    }
}

/// Returns whether one named interface currently owns an exact IPv4 address.
func interfaceHasIPv4Address(_ interface: String, address: String) -> Bool {
    (ipv4InterfaceAddresses() ?? []).contains {
        $0.interface == interface && $0.address == address
    }
}

private let maximumPFForwardingRules = 512
private let maximumPFProtectedEndpoints = 256
// Crash recovery can include stopped or orphaned history beyond the current
// profile. The validated helper-owned candidate pool is exactly offsets
// .200...250, so 51 is the complete bounded set the sensor may reconcile.
private let maximumPFQuarantineCandidates = 51
private let maximumLSOFOutputBytes = 65_536
private let maximumLSOFRecords = 64

struct PFBackendListener: Hashable, Comparable {
    let ip: String
    let port: Int

    static func < (lhs: PFBackendListener, rhs: PFBackendListener) -> Bool {
        if lhs.ip != rhs.ip {
            return lhs.ip < rhs.ip
        }
        return lhs.port < rhs.port
    }
}

private struct PFPublishedPort: Hashable {
    let ip: String
    let port: Int
}

struct LSOFListenerRecord: Hashable {
    let pid: Int32
    let uid: uid_t
    let endpoint: String
}

/// Validates the authority boundary for a complete PF anchor replacement.
///
/// The sensor may quarantine a bounded number of policy-valid candidates
/// before alias creation, but it may advertise redirects only for aliases
/// already present in the root-owned ownership ledger.
func validatePortForwardRequest(
    forwardingRules: [[String: Any]],
    protectedEndpoints: [[String: Any]],
    interface: String,
    route: IPv4DefaultRoute,
    networks: [IPv4InterfaceNetwork],
    interfaceAddresses: [(interface: String, address: String)],
    ownedEntries: Set<OwnedVirtualIP>
) throws -> [PFBackendListener] {
    guard interface == route.interface,
          !interface.isEmpty,
          interface.count <= 32,
          interface.allSatisfy({ $0.isLetter || $0.isNumber }) else {
        throw RPCError.internalError(
            "PF interface must match the observed default route"
        )
    }
    guard forwardingRules.count <= maximumPFForwardingRules,
          protectedEndpoints.count <= maximumPFProtectedEndpoints else {
        throw RPCError.internalError("PF request exceeds safe rule limits")
    }

    let entriesOnInterface = ownedEntries.filter {
        $0.interface == interface
    }
    guard entriesOnInterface.count == ownedEntries.count else {
        throw RPCError.internalError(
            "Owned aliases span an unsupported PF interface"
        )
    }
    let ownedIPs = Set(entriesOnInterface.map(\.ip))

    var endpointIPs = Set<String>()
    for endpoint in protectedEndpoints {
        guard let ip = endpoint["ip"] as? String,
              isValidIPv4(ip),
              let directPorts = endpoint["direct_ports"] as? [Int],
              directPorts.isEmpty,
              endpointIPs.insert(ip).inserted else {
            throw RPCError.internalError(
                "Protected PF endpoints must be unique VIPs with no direct ports"
            )
        }
    }
    guard ownedIPs.isSubset(of: endpointIPs) else {
        throw RPCError.internalError(
            "PF replacement omits a helper-owned virtual IP"
        )
    }

    let quarantineCandidates = endpointIPs.subtracting(ownedIPs)
    guard quarantineCandidates.count <= maximumPFQuarantineCandidates else {
        throw RPCError.internalError(
            "PF request has too many pre-alias quarantine candidates"
        )
    }
    for candidate in quarantineCandidates {
        try validateVirtualIPAddress(
            candidate,
            interface: interface,
            networks: networks,
            gateway: route.gateway
        )
    }
    try requireNoLocalIPv4AddressConflicts(
        quarantineCandidates,
        interfaceAddresses: interfaceAddresses
    )

    var publishedPorts = Set<PFPublishedPort>()
    var backendListeners = Set<PFBackendListener>()
    for rule in forwardingRules {
        guard let fromIP = rule["from_ip"] as? String,
              let fromPort = rule["from_port"] as? Int,
              let toIP = rule["to_ip"] as? String,
              let toPort = rule["to_port"] as? Int,
              isValidIPv4(fromIP),
              isValidIPv4(toIP),
              (1...65535).contains(fromPort),
              (1...65535).contains(toPort) else {
            throw RPCError.internalError("Invalid PF forwarding rule")
        }
        guard fromIP == toIP,
              ownedIPs.contains(fromIP),
              endpointIPs.contains(fromIP) else {
            throw RPCError.internalError(
                "PF redirects require a protected helper-owned VIP"
            )
        }
        guard publishedPorts.insert(
            PFPublishedPort(ip: fromIP, port: fromPort)
        ).inserted else {
            throw RPCError.internalError(
                "PF request contains duplicate advertised ports"
            )
        }
        guard backendListeners.insert(
            PFBackendListener(ip: toIP, port: toPort)
        ).inserted else {
            throw RPCError.internalError(
                "PF request contains duplicate backend listeners"
            )
        }
    }
    return backendListeners.sorted()
}

/// Refuse to install block-only PF quarantine for an address already assigned
/// anywhere on the host. The selected default-route interface is insufficient:
/// a real address can live on another physical, tunnel, bridge, or loopback
/// interface while still falling inside the helper candidate pool.
func requireNoLocalIPv4AddressConflicts(
    _ quarantineCandidates: Set<String>,
    interfaceAddresses: [(interface: String, address: String)]
) throws {
    let localAddresses = Set(interfaceAddresses.map(\.address))
    guard quarantineCandidates.isDisjoint(with: localAddresses) else {
        throw RPCError.internalError(
            "PF quarantine candidate is already assigned to a local interface"
        )
    }
}

/// Recompute unowned quarantine candidates against fresh ownership and global
/// address observations immediately before loading the live PF anchor.
func requireNoLocalAddressConflictsForPreAliasQuarantine(
    protectedEndpoints: [[String: Any]],
    interface: String,
    ownedEntries: Set<OwnedVirtualIP>,
    interfaceAddresses: [(interface: String, address: String)]
) throws {
    let ownedOnInterface = ownedEntries.filter {
        $0.interface == interface
    }
    guard ownedOnInterface.count == ownedEntries.count else {
        throw RPCError.internalError(
            "Owned aliases changed to an unsupported PF interface"
        )
    }
    let ownedIPs = Set(ownedOnInterface.map(\.ip))
    var endpointIPs = Set<String>()
    for endpoint in protectedEndpoints {
        guard let ip = endpoint["ip"] as? String,
              isValidIPv4(ip),
              endpointIPs.insert(ip).inserted else {
            throw RPCError.internalError(
                "Protected PF endpoint changed during local-address revalidation"
            )
        }
    }
    try requireNoLocalIPv4AddressConflicts(
        endpointIPs.subtracting(ownedIPs),
        interfaceAddresses: interfaceAddresses
    )
}

func revalidatePortForwardOwnership(
    forwardingRules: [[String: Any]],
    protectedEndpoints: [[String: Any]],
    interface: String,
    ownedEntries: Set<OwnedVirtualIP>
) throws {
    let ownedOnInterface = ownedEntries.filter {
        $0.interface == interface
    }
    guard ownedOnInterface.count == ownedEntries.count else {
        throw RPCError.internalError(
            "Owned aliases changed to an unsupported PF interface"
        )
    }
    let ownedIPs = Set(ownedOnInterface.map(\.ip))
    let endpointIPs = Set(
        try protectedEndpoints.map { endpoint in
            guard let ip = endpoint["ip"] as? String else {
                throw RPCError.internalError(
                    "Protected PF endpoint changed during validation"
                )
            }
            return ip
        }
    )
    let forwardingIPs = Set(
        try forwardingRules.map { rule in
            guard let ip = rule["from_ip"] as? String else {
                throw RPCError.internalError(
                    "PF forwarding rule changed during validation"
                )
            }
            return ip
        }
    )
    guard ownedIPs.isSubset(of: endpointIPs),
          forwardingIPs.isSubset(of: ownedIPs) else {
        throw RPCError.internalError(
            "PF ownership changed before live anchor mutation"
        )
    }
}

/// Re-observes the network authority boundary immediately before a PF or
/// virtual-IP mutation. A route or address change invalidates the earlier
/// policy decision instead of applying it to a different LAN.
func requireUnchangedPFNetworkContext(
    expectedRoute: IPv4DefaultRoute,
    expectedNetworks: [IPv4InterfaceNetwork],
    routeResult: CommandResult,
    interfaceResult: CommandResult
) throws {
    guard routeResult.status == 0,
          interfaceResult.status == 0,
          let currentRoute = ipv4DefaultRoute(from: routeResult.stdout),
          currentRoute == expectedRoute else {
        throw RPCError.internalError(
            "Default-route context changed before privileged network mutation"
        )
    }
    let currentNetworks = try interfaceIPv4Networks(
        from: interfaceResult.stdout
    )
    guard currentNetworks.count == expectedNetworks.count,
          currentNetworks.allSatisfy(expectedNetworks.contains) else {
        throw RPCError.internalError(
            "Interface network changed before privileged network mutation"
        )
    }
}

/// Parses bounded `lsof -Fpun` output for TCP listener ownership.
func parseLSOFListeners(_ output: String) throws -> Set<LSOFListenerRecord> {
    guard output.utf8.count <= maximumLSOFOutputBytes else {
        throw RPCError.internalError("Listener ownership output is oversized")
    }

    var currentPID: Int32?
    var currentUID: uid_t?
    var currentHasEndpoint = false
    var records = Set<LSOFListenerRecord>()
    var fieldCount = 0
    for rawLine in output.split(
        separator: "\n",
        omittingEmptySubsequences: true
    ) {
        fieldCount += 1
        guard fieldCount <= maximumLSOFRecords * 4,
              let prefix = rawLine.first else {
            throw RPCError.internalError(
                "Listener ownership output has too many fields"
            )
        }
        let value = String(rawLine.dropFirst())
        switch prefix {
        case "p":
            guard currentPID == nil
                    || (currentUID != nil && currentHasEndpoint) else {
                throw RPCError.internalError(
                    "Listener ownership output has an incomplete process record"
                )
            }
            guard let pid = Int32(value), pid > 0 else {
                throw RPCError.internalError(
                    "Listener ownership output has an invalid PID"
                )
            }
            currentPID = pid
            currentUID = nil
            currentHasEndpoint = false
        case "u":
            guard currentPID != nil,
                  let parsedUID = UInt32(value) else {
                throw RPCError.internalError(
                    "Listener ownership output has an invalid UID"
                )
            }
            currentUID = uid_t(parsedUID)
        case "n":
            guard let pid = currentPID,
                  let uid = currentUID,
                  !value.isEmpty else {
                throw RPCError.internalError(
                    "Listener ownership output is incomplete"
                )
            }
            records.insert(
                LSOFListenerRecord(pid: pid, uid: uid, endpoint: value)
            )
            currentHasEndpoint = true
            guard records.count <= maximumLSOFRecords else {
                throw RPCError.internalError(
                    "Listener ownership output has too many records"
                )
            }
        case "f":
            continue
        default:
            throw RPCError.internalError(
                "Listener ownership output has an unexpected field"
            )
        }
    }
    guard currentPID == nil
            || (currentUID != nil && currentHasEndpoint) else {
        throw RPCError.internalError(
            "Listener ownership output has an incomplete process record"
        )
    }
    return records
}

func requireSensorOwnedListener(
    _ listener: PFBackendListener,
    serviceUID: uid_t,
    run: (String, [String]) throws -> CommandResult
) throws {
    let result = try run(
        "/usr/sbin/lsof",
        [
            "-n",
            "-P",
            "-l",
            "-a",
            "-iTCP:\(listener.port)",
            "-sTCP:LISTEN",
            "-Fpun",
        ]
    )
    guard result.status == 0,
          result.stderr.utf8.count <= maximumLSOFOutputBytes else {
        throw RPCError.internalError(
            "Could not verify mimic backend listener ownership"
        )
    }
    let records = try parseLSOFListeners(result.stdout)
    let expectedEndpoint = "\(listener.ip):\(listener.port)"
    guard !records.isEmpty,
          records.allSatisfy({
              $0.uid == serviceUID && $0.endpoint == expectedEndpoint
          }),
          Set(records.map(\.pid)).count == 1 else {
        throw RPCError.internalError(
            "Mimic backend listener is not an exact sensor-owned VIP bind"
        )
    }
}

/// Builds the complete PF anchor ruleset for redirects and alias isolation.
///
/// Redirects use ``rdr pass`` so only connections to an advertised port can
/// reach its private listener. Direct backend-port scans then fall through to
/// the endpoint's final block rule.
func buildPFRules(
    forwardingRules: [[String: Any]],
    protectedEndpoints: [[String: Any]],
    interface: String
) throws -> [String] {
    guard !interface.isEmpty,
          interface.allSatisfy({ $0.isLetter || $0.isNumber }) else {
        throw RPCError.internalError("Invalid interface name: \(interface)")
    }

    var translationRules: [String] = []
    for rule in forwardingRules {
        guard let fromIP = rule["from_ip"] as? String,
              let fromPort = rule["from_port"] as? Int,
              let toIP = rule["to_ip"] as? String,
              let toPort = rule["to_port"] as? Int else {
            throw RPCError.internalError(
                "Invalid rule: each needs from_ip, from_port, to_ip, to_port"
            )
        }
        guard isValidIPv4(fromIP), isValidIPv4(toIP) else {
            throw RPCError.internalError("Invalid IP in port forward rule")
        }
        guard (1...65535).contains(fromPort), (1...65535).contains(toPort) else {
            throw RPCError.internalError("Invalid port in port forward rule")
        }
        translationRules.append(
            "rdr pass on \(interface) inet proto tcp from any to \(fromIP) "
                + "port \(fromPort) -> \(toIP) port \(toPort)"
        )
    }

    // Merge duplicate endpoint entries before emitting quick rules.  Otherwise
    // the first block for an IP could shadow ports from a later entry.
    var directPortsByIP: [String: Set<Int>] = [:]
    for endpoint in protectedEndpoints {
        guard let ip = endpoint["ip"] as? String, isValidIPv4(ip),
              let ports = endpoint["direct_ports"] as? [Int] else {
            throw RPCError.internalError(
                "Invalid protected endpoint: each needs ip and direct_ports"
            )
        }
        guard ports.allSatisfy({ (1...65535).contains($0) }) else {
            throw RPCError.internalError("Invalid protected endpoint port")
        }
        directPortsByIP[ip, default: []].formUnion(ports)
    }

    var filterRules: [String] = []
    for ip in directPortsByIP.keys.sorted() {
        let ports = directPortsByIP[ip, default: []].sorted()
        if ports.count == 1, let port = ports.first {
            filterRules.append(
                "pass in quick on \(interface) inet proto tcp from any to \(ip) "
                    + "port \(port)"
            )
        } else if !ports.isEmpty {
            let portSet = ports.map(String.init).joined(separator: ", ")
            filterRules.append(
                "pass in quick on \(interface) inet proto tcp from any to \(ip) "
                    + "port { \(portSet) }"
            )
        }
        filterRules.append(
            "pass in quick on \(interface) inet proto icmp from any to \(ip) "
                + "icmp-type echoreq"
        )
        // The redirect and intentional pass rules stay scoped to the selected
        // proxy-ARP interface, but default-deny must cover every ingress path.
        // A multihomed Mac can receive packets for its loopback-owned VIP on a
        // second LAN interface through a stale or forged neighbor entry. If the
        // block were scoped only to `interface`, those packets could reach
        // wildcard-bound host services and make the mimic mirror the real Mac.
        filterRules.append(
            "block drop in quick inet from any to \(ip)"
        )
    }

    return translationRules + filterRules
}

struct PFRedirectStateSignature: Hashable {
    let fromPort: Int
    let toIP: String
    let toPort: Int
}

struct PFEndpointStateSignature: Equatable {
    let interface: String
    let redirects: [PFRedirectStateSignature]
    let directPorts: [Int]
}

/// Produces an order-independent state signature for each PF endpoint.
///
/// Redirect destinations matter because existing PF states retain their
/// translation target. Direct-port changes matter because existing pass states
/// can otherwise outlive a newly restrictive filter rule.
func pfEndpointStateSignatures(
    forwardingRules: [[String: Any]],
    protectedEndpoints: [[String: Any]],
    interface: String
) throws -> [String: PFEndpointStateSignature] {
    guard !interface.isEmpty,
          interface.allSatisfy({ $0.isLetter || $0.isNumber }) else {
        throw RPCError.internalError("Invalid interface name: \(interface)")
    }

    var directPortsByIP: [String: Set<Int>] = [:]
    for endpoint in protectedEndpoints {
        guard let ip = endpoint["ip"] as? String, isValidIPv4(ip),
              let ports = endpoint["direct_ports"] as? [Int] else {
            throw RPCError.internalError(
                "Invalid protected endpoint: each needs ip and direct_ports"
            )
        }
        guard ports.allSatisfy({ (1...65535).contains($0) }) else {
            throw RPCError.internalError("Invalid protected endpoint port")
        }
        if directPortsByIP[ip] == nil {
            directPortsByIP[ip] = []
        }
        directPortsByIP[ip]?.formUnion(ports)
    }

    var redirectsByIP: [String: Set<PFRedirectStateSignature>] = [:]
    for rule in forwardingRules {
        guard let fromIP = rule["from_ip"] as? String,
              let fromPort = rule["from_port"] as? Int,
              let toIP = rule["to_ip"] as? String,
              let toPort = rule["to_port"] as? Int else {
            throw RPCError.internalError(
                "Invalid rule: each needs from_ip, from_port, to_ip, to_port"
            )
        }
        guard isValidIPv4(fromIP), isValidIPv4(toIP) else {
            throw RPCError.internalError("Invalid IP in port forward rule")
        }
        guard (1...65535).contains(fromPort),
              (1...65535).contains(toPort) else {
            throw RPCError.internalError("Invalid port in port forward rule")
        }
        redirectsByIP[fromIP, default: []].insert(
            PFRedirectStateSignature(
                fromPort: fromPort,
                toIP: toIP,
                toPort: toPort
            )
        )
    }

    let endpointIPs = Set(directPortsByIP.keys)
        .union(redirectsByIP.keys)
    var signatures: [String: PFEndpointStateSignature] = [:]
    for ip in endpointIPs {
        let redirects = redirectsByIP[ip, default: []].sorted {
            if $0.fromPort != $1.fromPort {
                return $0.fromPort < $1.fromPort
            }
            if $0.toIP != $1.toIP {
                return $0.toIP < $1.toIP
            }
            return $0.toPort < $1.toPort
        }
        signatures[ip] = PFEndpointStateSignature(
            interface: interface,
            redirects: redirects,
            directPorts: directPortsByIP[ip, default: []].sorted()
        )
    }
    return signatures
}

/// Selects endpoint states that cannot safely survive a PF ruleset update.
func pfStateCleanupIPs(
    previous: [String: PFEndpointStateSignature]?,
    current: [String: PFEndpointStateSignature]
) -> [String] {
    guard let previous else {
        return current.keys.sorted()
    }
    return Set(previous.keys)
        .union(current.keys)
        .filter { previous[$0] != current[$0] }
        .sorted()
}

/// Tracks the last successfully loaded rules and state cleanups still owed.
///
/// The live signatures change as soon as an anchor load or flush succeeds,
/// even if its subsequent state cleanup fails. Pending cleanup IPs remain
/// required across later ruleset changes until one cleanup fully succeeds.
struct PFEndpointStateCache {
    private var live:
        [String: PFEndpointStateSignature]?
    private var pendingCleanupIPs: Set<String> = []

    func cleanupIPs(
        for current: [String: PFEndpointStateSignature]
    ) -> [String] {
        Set(
            pfStateCleanupIPs(previous: live, current: current)
        )
        .union(pendingCleanupIPs)
        .sorted()
    }

    func protectsVirtualIP(ip: String, interface: String) -> Bool {
        guard let signature = live?[ip] else {
            return false
        }
        return signature.interface == interface
            && signature.directPorts.isEmpty
    }

    mutating func recordSuccessfulLiveMutation(
        _ current: [String: PFEndpointStateSignature],
        cleanupIPs: [String]
    ) {
        pendingCleanupIPs.formUnion(cleanupIPs)
        live = current
    }

    mutating func completeCleanup() {
        pendingCleanupIPs.removeAll()
    }
}

func requirePFProtectedVirtualIP(
    ip: String,
    interface: String,
    stateCache: PFEndpointStateCache
) throws {
    guard stateCache.protectsVirtualIP(ip: ip, interface: interface) else {
        throw RPCError.internalError(
            "Virtual IP must be quarantined by PF before publication"
        )
    }
}

struct CommandResult {
    let status: Int32
    let stdout: String
    let stderr: String
}

enum CommandExecutionError: Error, Equatable, LocalizedError {
    case invalidLimits
    case inputFailed
    case timedOut

    var errorDescription: String? {
        switch self {
        case .invalidLimits:
            return "Command execution limits are invalid"
        case .inputFailed:
            return "Command input failed"
        case .timedOut:
            return "Command execution timed out"
        }
    }
}

let commandTimeoutSeconds: TimeInterval = 15
let commandOutputLimitBytes = 1_048_576
private let commandTerminationGraceSeconds: TimeInterval = 1

typealias PFCommandRunner = (
    _ arguments: [String],
    _ input: Data?
) throws -> CommandResult

/// Removes PF connection states for the selected destination IPs.
func cleanupPFStates(
    for ips: [String],
    using runner: PFCommandRunner
) throws {
    for ip in ips {
        let result = try runner(
            ["-k", "0.0.0.0/0", "-k", ip],
            nil
        )
        guard result.status == 0 else {
            throw RPCError.internalError(
                "pfctl state cleanup failed for \(ip): \(result.stderr)"
            )
        }
    }
}

private enum PFReportedStatus: String {
    case enabled
    case disabled
    case unknown
}

/// Reads the state line emitted by macOS `pfctl -s info`.
///
/// `pfctl` writes platform diagnostics to stderr and its exit status can be
/// nonzero even when PF is already enabled. The explicit `Status:` line is the
/// authoritative state, so inspect both streams and fail closed if they
/// conflict or do not contain a recognized state.
private func pfReportedStatus(_ result: CommandResult) -> PFReportedStatus {
    var states: Set<PFReportedStatus> = []
    for output in [result.stdout, result.stderr] {
        for line in output.split(whereSeparator: \.isNewline) {
            let fields = line.split(
                separator: ":",
                maxSplits: 1,
                omittingEmptySubsequences: false
            )
            guard fields.count == 2,
                  fields[0]
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                    .lowercased() == "status" else {
                continue
            }
            let value = fields[1]
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased()
                .split(whereSeparator: \.isWhitespace)
                .first
                .map(String.init)
            if let value, let state = PFReportedStatus(rawValue: value) {
                states.insert(state)
            }
        }
    }

    guard states.count == 1, let state = states.first else {
        return .unknown
    }
    return state
}

func packetFilteringIsEnabled(_ result: CommandResult) -> Bool {
    pfReportedStatus(result) == .enabled
}

private func pfStateDiagnostic(_ result: CommandResult) -> String {
    "exit=\(result.status), reported=\(pfReportedStatus(result).rawValue)"
}

/// Enables PF only when the current state requires it and verifies the result.
///
/// A nonzero `pfctl -e` result is accepted only when a fresh status query
/// proves PF is enabled. Raw command output is deliberately excluded from the
/// error so RPC responses cannot echo unexpected system details.
func ensurePacketFilteringEnabled(
    using runner: PFCommandRunner
) throws {
    let before = try runner(["-s", "info"], nil)
    if packetFilteringIsEnabled(before) {
        return
    }

    let enable = try runner(["-e"], nil)
    let after = try runner(["-s", "info"], nil)
    guard packetFilteringIsEnabled(after) else {
        throw RPCError.internalError(
            "Could not enable packet filtering: "
                + "enable \(pfStateDiagnostic(enable)); "
                + "status \(pfStateDiagnostic(after))"
        )
    }
}

/// Fails closed when PF is no longer enabled at a security boundary.
func requirePacketFilteringEnabled(
    phase: String,
    using runner: PFCommandRunner
) throws {
    let result = try runner(["-s", "info"], nil)
    guard packetFilteringIsEnabled(result) else {
        throw RPCError.internalError(
            "Packet filtering is not enabled \(phase): "
                + pfStateDiagnostic(result)
        )
    }
}

/// Replaces a just-loaded redirect ruleset with block-only quarantine if the
/// exact sensor listener changes during the load window. Existing PF states
/// are killed for every changed, removed, or still-protected endpoint before
/// the original request is allowed to fail.
func quarantinePortForwardingAfterListenerRace(
    protectedEndpoints: [[String: Any]],
    interface: String,
    stateCache: inout PFEndpointStateCache,
    using runner: PFCommandRunner
) throws {
    let quarantineRules = try buildPFRules(
        forwardingRules: [],
        protectedEndpoints: protectedEndpoints,
        interface: interface
    )
    let quarantineSignatures = try pfEndpointStateSignatures(
        forwardingRules: [],
        protectedEndpoints: protectedEndpoints,
        interface: interface
    )
    // The redirect rules were briefly live even when the cache still describes
    // an identical pre-alias quarantine. Kill every current endpoint
    // unconditionally so a state created in that window cannot survive the
    // block-only replacement.
    let cleanupIPs = Set(
        stateCache.cleanupIPs(for: quarantineSignatures)
    )
    .union(quarantineSignatures.keys)
    .sorted()
    let quarantineData = Data(
        (quarantineRules.joined(separator: "\n") + "\n").utf8
    )
    let load = try runner(
        ["-a", "com.apple/squirrelops", "-f", "-"],
        quarantineData
    )
    guard load.status == 0 else {
        throw RPCError.internalError(
            "Listener ownership changed and PF quarantine failed"
        )
    }
    stateCache.recordSuccessfulLiveMutation(
        quarantineSignatures,
        cleanupIPs: cleanupIPs
    )

    try ensurePacketFilteringEnabled(using: runner)
    try cleanupPFStates(for: cleanupIPs, using: runner)
    try requirePacketFilteringEnabled(
        phase: "after listener-race quarantine",
        using: runner
    )
    stateCache.completeCleanup()
}

/// Runs an absolute executable without invoking a shell.
func runCommand(
    executable: String,
    arguments: [String],
    input: Data? = nil,
    timeoutSeconds: TimeInterval = commandTimeoutSeconds,
    outputLimitBytes: Int = commandOutputLimitBytes
) throws -> CommandResult {
    guard timeoutSeconds.isFinite,
          timeoutSeconds > 0,
          timeoutSeconds < Double(UInt64.max) / 1_000_000_000,
          outputLimitBytes > 0 else {
        throw CommandExecutionError.invalidLimits
    }
    let timeoutNanoseconds = UInt64(timeoutSeconds * 1_000_000_000)

    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments

    let stdoutPipe = Pipe()
    let stderrPipe = Pipe()
    process.standardOutput = stdoutPipe
    process.standardError = stderrPipe

    let inputPipe: Pipe?
    if input != nil {
        let pipe = Pipe()
        process.standardInput = pipe
        inputPipe = pipe
    } else {
        inputPipe = nil
    }
    defer {
        try? stdoutPipe.fileHandleForReading.close()
        try? stdoutPipe.fileHandleForWriting.close()
        try? stderrPipe.fileHandleForReading.close()
        try? stderrPipe.fileHandleForWriting.close()
        try? inputPipe?.fileHandleForReading.close()
        try? inputPipe?.fileHandleForWriting.close()
    }

    try process.run()
    // Process owns the duplicated child-side descriptors after launch. Close
    // the parent's copies so readers observe EOF when the child exits and the
    // parent cannot keep a full output pipe alive indefinitely.
    try? stdoutPipe.fileHandleForWriting.close()
    try? stderrPipe.fileHandleForWriting.close()
    try? inputPipe?.fileHandleForReading.close()
    let start = DispatchTime.now().uptimeNanoseconds
    guard timeoutNanoseconds <= UInt64.max - start else {
        if process.isRunning {
            process.terminate()
            process.waitUntilExit()
        }
        throw CommandExecutionError.invalidLimits
    }
    let deadline = start + timeoutNanoseconds

    let stdoutBox = CommandOutputBox(limit: outputLimitBytes)
    let stderrBox = CommandOutputBox(limit: outputLimitBytes)
    let outputReaders = DispatchGroup()
    outputReaders.enter()
    DispatchQueue.global(qos: .userInitiated).async {
        defer { outputReaders.leave() }
        drainCommandOutput(
            stdoutPipe.fileHandleForReading,
            into: stdoutBox
        )
    }
    outputReaders.enter()
    DispatchQueue.global(qos: .userInitiated).async {
        defer { outputReaders.leave() }
        drainCommandOutput(
            stderrPipe.fileHandleForReading,
            into: stderrBox
        )
    }
    var timedOut = false
    var inputFailed = false
    if let input, let inputPipe {
        switch writeCommandInput(
            input,
            to: inputPipe.fileHandleForWriting,
            process: process,
            deadline: deadline
        ) {
        case .complete, .childClosedInput:
            break
        case .timedOut:
            timedOut = true
        case .failed:
            inputFailed = true
        }
    }

    if !timedOut, !inputFailed {
        while process.isRunning,
              DispatchTime.now().uptimeNanoseconds < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        timedOut = process.isRunning
    }

    if process.isRunning, timedOut || inputFailed {
        process.terminate()
        let terminationDeadline =
            DispatchTime.now().uptimeNanoseconds
            + UInt64(commandTerminationGraceSeconds * 1_000_000_000)
        while process.isRunning,
              DispatchTime.now().uptimeNanoseconds < terminationDeadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        if process.isRunning {
            _ = kill(process.processIdentifier, SIGKILL)
        }
    }

    process.waitUntilExit()
    if outputReaders.wait(timeout: .now() + 1) == .timedOut {
        // A descendant could inherit the pipe descriptors after the direct
        // child exits. Closing our readers keeps that descendant from holding
        // the synchronous helper indefinitely.
        try? stdoutPipe.fileHandleForReading.close()
        try? stderrPipe.fileHandleForReading.close()
        _ = outputReaders.wait(timeout: .now() + 1)
    }

    if timedOut {
        throw CommandExecutionError.timedOut
    }
    if inputFailed {
        throw CommandExecutionError.inputFailed
    }

    let stdout = String(decoding: stdoutBox.load(), as: UTF8.self)
    let stderr = String(decoding: stderrBox.load(), as: UTF8.self)
    return CommandResult(
        status: process.terminationStatus,
        stdout: stdout,
        stderr: stderr
    )
}

private enum CommandInputWriteResult {
    case complete
    case childClosedInput
    case timedOut
    case failed
}

/// Feed stdin without allowing a child that stops reading to bypass the
/// command's absolute deadline.
private func writeCommandInput(
    _ input: Data,
    to handle: FileHandle,
    process: Process,
    deadline: UInt64
) -> CommandInputWriteResult {
    defer { try? handle.close() }

    let fd = handle.fileDescriptor
    let flags = fcntl(fd, F_GETFL)
    guard flags >= 0,
          fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
          fcntl(fd, F_SETNOSIGPIPE, 1) == 0 else {
        return .failed
    }

    return input.withUnsafeBytes { rawBuffer in
        guard var pointer = rawBuffer.baseAddress else { return .complete }
        var remaining = rawBuffer.count

        while remaining > 0 {
            if !process.isRunning {
                return .childClosedInput
            }

            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { return .timedOut }
            let remainingNanoseconds = deadline - now
            let remainingMilliseconds =
                (remainingNanoseconds + 999_999) / 1_000_000
            let pollTimeout = Int32(
                min(remainingMilliseconds, UInt64(50))
            )

            var descriptor = pollfd(
                fd: fd,
                events: Int16(POLLOUT),
                revents: 0
            )
            let pollResult = poll(&descriptor, 1, pollTimeout)
            if pollResult == 0 { continue }
            if pollResult < 0 {
                if errno == EINTR { continue }
                return .failed
            }
            if descriptor.revents & Int16(POLLNVAL) != 0 {
                return .failed
            }
            if descriptor.revents & Int16(POLLERR | POLLHUP) != 0 {
                return .childClosedInput
            }

            let count = Darwin.write(
                fd,
                pointer,
                min(remaining, 16_384)
            )
            if count < 0 {
                if errno == EINTR || errno == EAGAIN
                    || errno == EWOULDBLOCK {
                    continue
                }
                if errno == EPIPE { return .childClosedInput }
                return .failed
            }
            if count == 0 { return .childClosedInput }
            pointer = pointer.advanced(by: count)
            remaining -= count
        }
        return .complete
    }
}

private final class CommandOutputBox: @unchecked Sendable {
    private let lock = NSLock()
    private let limit: Int
    private var data = Data()

    init(limit: Int) {
        self.limit = limit
    }

    func append(_ value: Data) {
        lock.lock()
        let remaining = limit - data.count
        if remaining > 0 {
            data.append(value.prefix(remaining))
        }
        lock.unlock()
    }

    func load() -> Data {
        lock.lock()
        defer { lock.unlock() }
        return data
    }
}

/// Drain the pipe for the lifetime of the child to avoid backpressure while
/// retaining only the configured prefix in memory.
private func drainCommandOutput(
    _ handle: FileHandle,
    into output: CommandOutputBox
) {
    while true {
        do {
            guard let chunk = try handle.read(upToCount: 16_384),
                  !chunk.isEmpty else {
                return
            }
            output.append(chunk)
        } catch {
            return
        }
    }
}

/// Runs the system PF controller without invoking a shell.
func runPFCTL(arguments: [String], input: Data? = nil) throws -> CommandResult {
    try runCommand(
        executable: "/sbin/pfctl",
        arguments: arguments,
        input: input
    )
}
