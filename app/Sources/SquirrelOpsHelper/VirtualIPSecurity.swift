import Foundation
#if canImport(Darwin)
import Darwin
#endif

private let maximumOwnedVirtualIPs = 256
private let maximumOwnershipStateBytes = 65_536
private let virtualIPCandidateOffsets = 200...250
private let allowedARPScanPrefixes = 24...30

/// One directly connected IPv4 network configured on a physical interface.
struct IPv4InterfaceNetwork: Equatable {
    let address: String
    let network: String
    let broadcast: String
}

struct IPv4DefaultRoute: Equatable {
    let gateway: String
    let interface: String
}

let ipv4DefaultRouteCommandArguments = [
    "-n", "get", "-inet", "default",
]

private enum ScopedARPResolution {
    case absent
    case incomplete
    case occupied
    case published
}

struct OwnedVirtualIP: Hashable, Comparable {
    let ip: String
    let interface: String

    static func < (lhs: OwnedVirtualIP, rhs: OwnedVirtualIP) -> Bool {
        if lhs.ip != rhs.ip {
            return lhs.ip < rhs.ip
        }
        return lhs.interface < rhs.interface
    }
}

/// Root-owned durable authority for virtual-IP removal.
///
/// An entry is recorded before the first OS mutation and retained until
/// withdrawal is completely verified. A helper crash can therefore leave a
/// conservative stale claim, but never an untracked alias that a compromised
/// sensor can repurpose to remove an unrelated loopback address.
final class VirtualIPOwnershipStore {
    static let defaultStateFileURL = URL(
        fileURLWithPath: "/var/db/com.squirrelops.helper/owned-aliases"
    )

    private let stateFileURL: URL
    private let expectedOwnerUID: uid_t
    private let expectedOwnerGID: gid_t

    init(
        stateFileURL: URL = VirtualIPOwnershipStore.defaultStateFileURL,
        expectedOwnerUID: uid_t = 0,
        expectedOwnerGID: gid_t = 0
    ) {
        self.stateFileURL = stateFileURL
        self.expectedOwnerUID = expectedOwnerUID
        self.expectedOwnerGID = expectedOwnerGID
    }

    func contains(ip: String, interface: String) throws -> Bool {
        try load().contains(OwnedVirtualIP(ip: ip, interface: interface))
    }

    func allEntries() throws -> Set<OwnedVirtualIP> {
        try load()
    }

    func insert(ip: String, interface: String) throws {
        let entry = try validatedEntry(ip: ip, interface: interface)
        var entries = try load()
        guard entries.count < maximumOwnedVirtualIPs || entries.contains(entry) else {
            throw RPCError.internalError(
                "Virtual-IP ownership state has reached its safe limit"
            )
        }
        entries.insert(entry)
        try persist(entries)
    }

    func remove(ip: String, interface: String) throws {
        let entry = try validatedEntry(ip: ip, interface: interface)
        var entries = try load()
        entries.remove(entry)
        try persist(entries)
    }

    private func validatedEntry(
        ip: String,
        interface: String
    ) throws -> OwnedVirtualIP {
        guard isValidIPv4(ip),
              isRFC1918IPv4(ip),
              interface != "lo0",
              !interface.isEmpty,
              interface.count <= 32,
              interface.allSatisfy({ $0.isLetter || $0.isNumber }) else {
            throw RPCError.internalError(
                "Invalid virtual-IP ownership entry"
            )
        }
        return OwnedVirtualIP(ip: ip, interface: interface)
    }

    private func load() throws -> Set<OwnedVirtualIP> {
        let parentURL = stateFileURL.deletingLastPathComponent()
        let parentExists = try validateSecureNode(
            at: parentURL,
            expectedType: S_IFDIR,
            allowMissing: true
        )
        guard parentExists else {
            return []
        }
        let stateExists = try validateSecureNode(
            at: stateFileURL,
            expectedType: S_IFREG,
            allowMissing: true
        )
        guard stateExists else {
            return []
        }

        let attributes = try FileManager.default.attributesOfItem(
            atPath: stateFileURL.path
        )
        guard let size = attributes[.size] as? NSNumber,
              size.intValue <= maximumOwnershipStateBytes else {
            throw RPCError.internalError(
                "Virtual-IP ownership state is oversized"
            )
        }

        let data: Data
        do {
            data = try Data(contentsOf: stateFileURL, options: [.mappedIfSafe])
        } catch {
            throw RPCError.internalError(
                "Could not read virtual-IP ownership state"
            )
        }
        guard data.count <= maximumOwnershipStateBytes,
              let text = String(data: data, encoding: .utf8) else {
            throw RPCError.internalError(
                "Virtual-IP ownership state is invalid"
            )
        }

        var entries = Set<OwnedVirtualIP>()
        let lines = text.split(
            separator: "\n",
            omittingEmptySubsequences: true
        )
        guard lines.count <= maximumOwnedVirtualIPs else {
            throw RPCError.internalError(
                "Virtual-IP ownership state has too many entries"
            )
        }
        for line in lines {
            let fields = line.split(
                separator: "|",
                maxSplits: 1,
                omittingEmptySubsequences: false
            )
            guard fields.count == 2 else {
                throw RPCError.internalError(
                    "Virtual-IP ownership state is malformed"
                )
            }
            let entry = try validatedEntry(
                ip: String(fields[0]),
                interface: String(fields[1])
            )
            guard entries.insert(entry).inserted else {
                throw RPCError.internalError(
                    "Virtual-IP ownership state contains duplicates"
                )
            }
        }
        return entries
    }

    private func persist(_ entries: Set<OwnedVirtualIP>) throws {
        let parentURL = stateFileURL.deletingLastPathComponent()
        try ensureSecureParentDirectory(parentURL)

        let lines = entries.sorted().map {
            "\($0.ip)|\($0.interface)"
        }
        let text = lines.isEmpty ? "" : lines.joined(separator: "\n") + "\n"
        let data = Data(text.utf8)
        guard data.count <= maximumOwnershipStateBytes else {
            throw RPCError.internalError(
                "Virtual-IP ownership state is oversized"
            )
        }

        let temporaryURL = parentURL.appendingPathComponent(
            ".owned-aliases.\(UUID().uuidString).tmp"
        )
        var temporaryExists = false
        defer {
            if temporaryExists {
                _ = unlink(temporaryURL.path)
            }
        }

        let descriptor = open(
            temporaryURL.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
            S_IRUSR | S_IWUSR
        )
        guard descriptor >= 0 else {
            throw RPCError.internalError(
                "Could not create virtual-IP ownership state"
            )
        }
        temporaryExists = true
        guard fchown(
            descriptor,
            expectedOwnerUID,
            expectedOwnerGID
        ) == 0,
        fchmod(descriptor, S_IRUSR | S_IWUSR) == 0 else {
            _ = close(descriptor)
            throw RPCError.internalError(
                "Could not secure virtual-IP ownership state"
            )
        }

        var writeSucceeded = true
        data.withUnsafeBytes { rawBuffer in
            guard var cursor = rawBuffer.baseAddress else {
                return
            }
            var remaining = rawBuffer.count
            while remaining > 0 {
                let written = Darwin.write(descriptor, cursor, remaining)
                if written <= 0 {
                    writeSucceeded = false
                    return
                }
                cursor = cursor.advanced(by: written)
                remaining -= written
            }
        }
        let syncSucceeded = writeSucceeded && fsync(descriptor) == 0
        let closeSucceeded = close(descriptor) == 0
        guard syncSucceeded, closeSucceeded else {
            throw RPCError.internalError(
                "Could not durably write virtual-IP ownership state"
            )
        }

        guard rename(temporaryURL.path, stateFileURL.path) == 0 else {
            throw RPCError.internalError(
                "Could not install virtual-IP ownership state"
            )
        }
        temporaryExists = false

        _ = chmod(stateFileURL.path, S_IRUSR | S_IWUSR)
        _ = try validateSecureNode(
            at: stateFileURL,
            expectedType: S_IFREG,
            allowMissing: false
        )

        let directoryDescriptor = open(parentURL.path, O_RDONLY)
        guard directoryDescriptor >= 0 else {
            throw RPCError.internalError(
                "Could not open virtual-IP ownership directory"
            )
        }
        let directorySyncSucceeded = fsync(directoryDescriptor) == 0
        let directoryCloseSucceeded = close(directoryDescriptor) == 0
        guard directorySyncSucceeded, directoryCloseSucceeded else {
            throw RPCError.internalError(
                "Could not durably commit virtual-IP ownership state"
            )
        }
    }

    private func ensureSecureParentDirectory(_ url: URL) throws {
        if try validateSecureNode(
            at: url,
            expectedType: S_IFDIR,
            allowMissing: true
        ) {
            return
        }
        do {
            try FileManager.default.createDirectory(
                at: url,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw RPCError.internalError(
                "Could not create virtual-IP ownership directory"
            )
        }
        guard chown(url.path, expectedOwnerUID, expectedOwnerGID) == 0,
              chmod(url.path, S_IRWXU) == 0 else {
            throw RPCError.internalError(
                "Could not secure virtual-IP ownership directory"
            )
        }
        _ = try validateSecureNode(
            at: url,
            expectedType: S_IFDIR,
            allowMissing: false
        )
    }

    @discardableResult
    private func validateSecureNode(
        at url: URL,
        expectedType: mode_t,
        allowMissing: Bool
    ) throws -> Bool {
        var information = stat()
        guard lstat(url.path, &information) == 0 else {
            if allowMissing && errno == ENOENT {
                return false
            }
            throw RPCError.internalError(
                "Could not inspect virtual-IP ownership state"
            )
        }
        let fileType = information.st_mode & mode_t(S_IFMT)
        let unsafePermissions = information.st_mode & mode_t(0o077)
        guard fileType == expectedType,
              information.st_uid == expectedOwnerUID,
              information.st_gid == expectedOwnerGID,
              unsafePermissions == 0 else {
            throw RPCError.internalError(
                "Virtual-IP ownership state permissions are unsafe"
            )
        }
        return true
    }
}

/// Parse every directly connected IPv4 network from `ifconfig <interface>`.
func interfaceIPv4Networks(from output: String) throws -> [IPv4InterfaceNetwork] {
    var networks: [IPv4InterfaceNetwork] = []
    for line in output.split(whereSeparator: \.isNewline) {
        let fields = line.split(whereSeparator: \.isWhitespace).map(String.init)
        guard fields.first == "inet",
              fields.count >= 4,
              let netmaskIndex = fields.firstIndex(of: "netmask"),
              fields.indices.contains(netmaskIndex + 1),
              let addressValue = strictIPv4Value(fields[1]),
              let maskValue = ipv4MaskValue(fields[netmaskIndex + 1]),
              isContiguousIPv4Mask(maskValue) else {
            continue
        }

        let networkValue = addressValue & maskValue
        let broadcastValue = networkValue | ~maskValue
        if let broadcastIndex = fields.firstIndex(of: "broadcast"),
           fields.indices.contains(broadcastIndex + 1) {
            guard strictIPv4Value(fields[broadcastIndex + 1])
                == broadcastValue else {
                throw RPCError.internalError(
                    "Interface reported an inconsistent IPv4 broadcast"
                )
            }
        }
        networks.append(
            IPv4InterfaceNetwork(
                address: ipv4String(addressValue),
                network: ipv4String(networkValue),
                broadcast: ipv4String(broadcastValue)
            )
        )
    }
    guard !networks.isEmpty else {
        throw RPCError.internalError(
            "Selected interface has no usable IPv4 network"
        )
    }
    return networks
}

/// Extract the gateway only when the scoped route names the expected interface.
func defaultGateway(
    from output: String,
    expectedInterface: String
) -> String? {
    guard let route = ipv4DefaultRoute(from: output),
          route.interface == expectedInterface else {
        return nil
    }
    return route.gateway
}

/// Observe the IPv4 routing table explicitly.
///
/// `route get default` can select a different address family as network
/// services change. Privileged LAN operations must never depend on that
/// implicit selection.
func observeIPv4DefaultRoute(
    using runner: (
        _ executable: String,
        _ arguments: [String]
    ) throws -> CommandResult
) throws -> IPv4DefaultRoute {
    let result = try runner(
        "/sbin/route",
        ipv4DefaultRouteCommandArguments
    )
    guard result.status == 0,
          let route = ipv4DefaultRoute(from: result.stdout) else {
        throw RPCError.internalError(
            "Could not verify the private IPv4 default route "
                + "(route status \(result.status))"
        )
    }
    return route
}

/// Parse one unambiguous private IPv4 default route.
func ipv4DefaultRoute(from output: String) -> IPv4DefaultRoute? {
    var gateway: String?
    var interface: String?
    for line in output.split(whereSeparator: \.isNewline) {
        let fields = line.split(
            separator: ":",
            maxSplits: 1,
            omittingEmptySubsequences: false
        ).map {
            $0.trimmingCharacters(in: .whitespaces)
        }
        guard fields.count == 2 else {
            continue
        }
        if fields[0] == "gateway" {
            guard gateway == nil else { return nil }
            gateway = fields[1]
        } else if fields[0] == "interface" {
            guard interface == nil else { return nil }
            interface = fields[1]
        }
    }
    guard let interface,
          interface != "lo0",
          !interface.isEmpty,
          interface.allSatisfy({ $0.isLetter || $0.isNumber }),
          let gateway,
          isRFC1918IPv4(gateway) else {
        return nil
    }
    return IPv4DefaultRoute(gateway: gateway, interface: interface)
}

/// Enforce a helper-observed LAN boundary for privileged alias mutations.
func validateVirtualIPAddress(
    _ ip: String,
    interface: String,
    networks: [IPv4InterfaceNetwork],
    gateway: String
) throws {
    guard interface != "lo0",
          !interface.isEmpty,
          interface.allSatisfy({ $0.isLetter || $0.isNumber }),
          let ipValue = strictIPv4Value(ip),
          isRFC1918IPv4(ip),
          let gatewayValue = strictIPv4Value(gateway),
          isRFC1918IPv4(gateway) else {
        throw RPCError.internalError(
            "Virtual IP must be a private IPv4 LAN address"
        )
    }
    guard ipValue != gatewayValue else {
        throw RPCError.internalError(
            "Refusing to use the default gateway as a virtual IP"
        )
    }

    var gatewayNetworks: [(
        network: IPv4InterfaceNetwork,
        networkValue: UInt32,
        broadcastValue: UInt32
    )] = []
    var seenGatewayNetworks = Set<String>()
    for network in networks {
        guard let addressValue = strictIPv4Value(network.address),
              let networkValue = strictIPv4Value(network.network),
              let broadcastValue = strictIPv4Value(network.broadcast),
              networkValue <= addressValue,
              addressValue <= broadcastValue else {
            throw RPCError.internalError(
                "Selected interface has invalid IPv4 network state"
            )
        }
        if gatewayValue > networkValue,
           gatewayValue < broadcastValue,
           isRFC1918IPv4(network.network),
           isRFC1918IPv4(network.broadcast) {
            let key = "\(network.network)|\(network.broadcast)"
            if seenGatewayNetworks.insert(key).inserted {
                gatewayNetworks.append((
                    network: network,
                    networkValue: networkValue,
                    broadcastValue: broadcastValue
                ))
            }
        }
    }
    guard gatewayNetworks.count == 1 else {
        throw RPCError.internalError(
            "Default gateway network is unavailable or ambiguous"
        )
    }
    let candidateNetwork = gatewayNetworks[0]
    guard ipValue >= candidateNetwork.networkValue,
          ipValue <= candidateNetwork.broadcastValue,
          let candidateOffset = Int(exactly:
              ipValue - candidateNetwork.networkValue
          ),
          virtualIPCandidateOffsets.contains(candidateOffset),
          ipValue != candidateNetwork.networkValue,
          ipValue != candidateNetwork.broadcastValue,
          candidateNetwork.network.address != ip else {
        throw RPCError.internalError(
            "Virtual IP is outside the helper-owned candidate pool"
        )
    }
}

/// Restrict a privileged ARP scan to one canonical, bounded LAN CIDR on the
/// helper-observed physical default-route network.
func validateARPScanCIDR(
    _ cidr: String,
    interface: String,
    networks: [IPv4InterfaceNetwork],
    gateway: String,
    hasEthernetAddress: Bool
) throws {
    guard interface != "lo0",
          !interface.isEmpty,
          interface.allSatisfy({ $0.isLetter || $0.isNumber }),
          hasEthernetAddress,
          let gatewayValue = strictIPv4Value(gateway),
          isRFC1918IPv4(gateway) else {
        throw RPCError.internalError(
            "ARP scans require a physical private default-route interface"
        )
    }

    let (requestedAddress, prefixLength) = try ARPScanner.parseCIDR(cidr)
    guard allowedARPScanPrefixes.contains(prefixLength) else {
        throw RPCError.internalError(
            "ARP scan prefix is outside the bounded host range"
        )
    }
    let mask = ipv4Mask(prefixLength: prefixLength)
    let requestedNetwork = requestedAddress & mask
    let requestedBroadcast = requestedNetwork | ~mask
    guard requestedAddress == requestedNetwork,
          isRFC1918IPv4(ipv4String(requestedNetwork)),
          isRFC1918IPv4(ipv4String(requestedBroadcast)) else {
        throw RPCError.internalError(
            "ARP scan CIDR must be canonical private IPv4 space"
        )
    }

    var matchingNetworks = Set<String>()
    for network in networks {
        guard let networkValue = strictIPv4Value(network.network),
              let broadcastValue = strictIPv4Value(network.broadcast),
              networkValue <= broadcastValue else {
            throw RPCError.internalError(
                "Selected interface has invalid IPv4 network state"
            )
        }
        if gatewayValue > networkValue,
           gatewayValue < broadcastValue,
           requestedNetwork >= networkValue,
           requestedBroadcast <= broadcastValue,
           isRFC1918IPv4(network.network),
           isRFC1918IPv4(network.broadcast) {
            matchingNetworks.insert(
                "\(network.network)|\(network.broadcast)"
            )
        }
    }
    guard matchingNetworks.count == 1 else {
        throw RPCError.internalError(
            "ARP scan CIDR is outside the observed default-route network"
        )
    }
}

/// Actively resolve a candidate without modifying any pre-existing ARP entry.
///
/// A ping exit status of 2 means no ICMP reply on macOS and is expected for
/// hosts that drop ICMP. The exact scoped ARP lookup after that ping remains
/// authoritative: any complete or published owner rejects the candidate.
func requireUnusedVirtualIPAddress(
    ip: String,
    interface: String,
    using runner: AliasCommandRunner
) throws {
    guard isValidIPv4(ip),
          interface != "lo0",
          !interface.isEmpty,
          interface.allSatisfy({ $0.isLetter || $0.isNumber }) else {
        throw RPCError.internalError(
            "Invalid duplicate-address probe target"
        )
    }

    let initialLookup: CommandResult
    do {
        initialLookup = try runner(
            "/usr/sbin/arp",
            proxyARPLookupArguments(ip: ip, interface: interface)
        )
    } catch {
        throw RPCError.internalError(
            "Could not inspect scoped ARP state before publication"
        )
    }
    switch try scopedARPResolution(
        initialLookup,
        ip: ip,
        interface: interface
    ) {
    case .occupied, .published:
        throw RPCError.internalError(
            "Virtual IP candidate already has an ARP owner"
        )
    case .absent, .incomplete:
        break
    }

    let ping: CommandResult
    do {
        ping = try runner(
            "/sbin/ping",
            [
                "-n", "-b", interface, "-c", "1",
                "-W", "1000", ip,
            ]
        )
    } catch {
        throw RPCError.internalError(
            "Could not actively probe virtual IP candidate"
        )
    }
    if ping.status == 0 {
        throw RPCError.internalError(
            "Virtual IP candidate answered duplicate-address probing"
        )
    }
    guard ping.status == 2 else {
        throw RPCError.internalError(
            "Virtual IP duplicate-address probe failed"
        )
    }

    let finalLookup: CommandResult
    do {
        finalLookup = try runner(
            "/usr/sbin/arp",
            proxyARPLookupArguments(ip: ip, interface: interface)
        )
    } catch {
        throw RPCError.internalError(
            "Could not verify scoped ARP state after probing"
        )
    }
    switch try scopedARPResolution(
        finalLookup,
        ip: ip,
        interface: interface
    ) {
    case .absent, .incomplete:
        return
    case .occupied, .published:
        throw RPCError.internalError(
            "Virtual IP candidate responded to duplicate-address probing"
        )
    }
}

private func scopedARPResolution(
    _ result: CommandResult,
    ip: String,
    interface: String
) throws -> ScopedARPResolution {
    let lines = (result.stdout + result.stderr)
        .split(whereSeparator: \.isNewline)
        .map(String.init)
    guard lines.count == 1 else {
        throw RPCError.internalError(
            "Scoped ARP lookup returned ambiguous output"
        )
    }
    let line = lines[0]
    let fields = line.split(whereSeparator: \.isWhitespace).map(String.init)
    guard fields.contains("(\(ip))"),
          let onIndex = fields.firstIndex(of: "on"),
          fields.indices.contains(onIndex + 1),
          fields[onIndex + 1] == interface else {
        throw RPCError.internalError(
            "Scoped ARP lookup returned unparseable output"
        )
    }

    if line.contains("-- no entry") {
        guard result.status == 1 else {
            throw RPCError.internalError(
                "Scoped ARP absence result had an invalid status"
            )
        }
        return .absent
    }
    guard result.status == 0,
          let atIndex = fields.firstIndex(of: "at"),
          fields.indices.contains(atIndex + 1) else {
        throw RPCError.internalError(
            "Scoped ARP lookup command failed"
        )
    }
    let owner = fields[atIndex + 1]
    if owner == "(incomplete)" {
        return .incomplete
    }
    guard canonicalEthernetAddress(owner) != nil else {
        throw RPCError.internalError(
            "Scoped ARP lookup returned an invalid owner"
        )
    }
    if fields.contains(where: {
        $0.caseInsensitiveCompare("published") == .orderedSame
    }) || line.localizedCaseInsensitiveContains("(proxy only)") {
        return .published
    }
    return .occupied
}

func isRFC1918IPv4(_ address: String) -> Bool {
    guard let value = strictIPv4Value(address) else {
        return false
    }
    let first = (value >> 24) & 0xff
    let second = (value >> 16) & 0xff
    return first == 10
        || (first == 172 && (16...31).contains(second))
        || (first == 192 && second == 168)
}

private func strictIPv4Value(_ address: String) -> UInt32? {
    guard isValidIPv4(address) else {
        return nil
    }
    var result: UInt32 = 0
    for part in address.split(separator: ".") {
        guard let octet = UInt32(part) else {
            return nil
        }
        result = (result << 8) | octet
    }
    return result
}

private func ipv4MaskValue(_ mask: String) -> UInt32? {
    if mask.hasPrefix("0x") {
        return UInt32(mask.dropFirst(2), radix: 16)
    }
    return strictIPv4Value(mask)
}

private func isContiguousIPv4Mask(_ mask: UInt32) -> Bool {
    let inverted = ~mask
    return inverted & (inverted &+ 1) == 0
}

private func ipv4Mask(prefixLength: Int) -> UInt32 {
    prefixLength == 0 ? 0 : ~((1 << (32 - prefixLength)) - 1)
}

private func ipv4String(_ value: UInt32) -> String {
    [
        String((value >> 24) & 0xff),
        String((value >> 16) & 0xff),
        String((value >> 8) & 0xff),
        String(value & 0xff),
    ].joined(separator: ".")
}
