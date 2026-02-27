import Foundation

/// Registers all RPC method handlers with the router.
func registerMethods(router: RPCRouter, dnsSniffer: DNSSniffer) {
    router.handlers["runARPScan"] = { params in
        guard let subnet = params["subnet"] as? String else {
            throw RPCError.internalError("Missing 'subnet' parameter")
        }
        return try ARPScanner.scan(subnet: subnet)
    }

    router.handlers["runServiceScan"] = { params in
        guard let targets = params["targets"] as? [String],
              let ports = params["ports"] as? [Int] else {
            throw RPCError.internalError("Missing 'targets' or 'ports' parameters")
        }
        return try ServiceScanner.scan(targets: targets, ports: ports)
    }

    router.handlers["bindListener"] = { params in
        guard let address = params["address"] as? String,
              let port = params["port"] as? Int else {
            throw RPCError.internalError("Missing 'address' or 'port' parameters")
        }
        return try SocketBinder.bind(address: address, port: port)
    }

    router.handlers["startDNSSniff"] = { params in
        guard let interface = params["interface"] as? String else {
            throw RPCError.internalError("Missing 'interface' parameter")
        }
        // Validate interface name — only alphanumeric (e.g., en0, eth0)
        guard interface.allSatisfy({ $0.isLetter || $0.isNumber }) else {
            throw RPCError.internalError("Invalid interface name: \(interface)")
        }
        try dnsSniffer.start(interface: interface)
        return ["ok": true]
    }

    router.handlers["stopDNSSniff"] = { _ in
        dnsSniffer.stop()
        return ["ok": true]
    }

    router.handlers["getDNSQueries"] = { params in
        guard let sinceStr = params["since"] as? String else {
            throw RPCError.internalError("Missing 'since' parameter")
        }
        let formatter = ISO8601DateFormatter()
        guard let since = formatter.date(from: sinceStr) else {
            throw RPCError.internalError("Invalid ISO8601 date: \(sinceStr)")
        }
        let queries = dnsSniffer.getQueries(since: since)
        return DNSSniffer.queriesToResult(queries)
    }

    router.handlers["addIPAlias"] = { params in
        guard let ip = params["ip"] as? String else {
            throw RPCError.internalError("Missing 'ip' parameter")
        }
        let interface = (params["interface"] as? String) ?? "en0"
        let mask = (params["mask"] as? String) ?? "255.255.255.0"

        // Validate interface name — only alphanumeric
        guard interface.allSatisfy({ $0.isLetter || $0.isNumber }) else {
            throw RPCError.internalError("Invalid interface name: \(interface)")
        }
        // Validate IP address format
        guard isValidIPv4(ip) else {
            throw RPCError.internalError("Invalid IP address: \(ip)")
        }
        guard isValidIPv4(mask) else {
            throw RPCError.internalError("Invalid netmask: \(mask)")
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
        process.arguments = [interface, "alias", ip, mask]
        let pipe = Pipe()
        process.standardError = pipe
        try process.run()
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            let stderr = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            throw RPCError.internalError("ifconfig alias failed: \(stderr)")
        }
        return ["success": true]
    }

    router.handlers["setupPortForwards"] = { params in
        guard let rules = params["rules"] as? [[String: Any]] else {
            throw RPCError.internalError("Missing 'rules' parameter")
        }
        let interface = (params["interface"] as? String) ?? "en0"

        // Validate interface name
        guard interface.allSatisfy({ $0.isLetter || $0.isNumber }) else {
            throw RPCError.internalError("Invalid interface name: \(interface)")
        }

        // Build pf anchor rules
        var pfRules: [String] = []
        for rule in rules {
            guard let fromIP = rule["from_ip"] as? String,
                  let fromPort = rule["from_port"] as? Int,
                  let toIP = rule["to_ip"] as? String,
                  let toPort = rule["to_port"] as? Int else {
                throw RPCError.internalError("Invalid rule: each needs from_ip, from_port, to_ip, to_port")
            }
            guard isValidIPv4(fromIP), isValidIPv4(toIP) else {
                throw RPCError.internalError("Invalid IP in port forward rule")
            }
            guard fromPort > 0, fromPort <= 65535, toPort > 0, toPort <= 65535 else {
                throw RPCError.internalError("Invalid port in port forward rule")
            }
            pfRules.append(
                "rdr on \(interface) proto tcp from any to \(fromIP) port \(fromPort) -> \(toIP) port \(toPort)"
            )
        }

        if pfRules.isEmpty {
            // No rules — flush the anchor
            let flush = Process()
            flush.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
            flush.arguments = ["-a", "com.apple/squirrelops", "-F", "all"]
            flush.standardError = Pipe()
            try flush.run()
            flush.waitUntilExit()
            return ["success": true, "rules_count": 0]
        }

        // Write rules to temp file
        let tempFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("squirrelops-pf-rules.conf")
        let rulesText = pfRules.joined(separator: "\n") + "\n"
        try rulesText.write(to: tempFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tempFile) }

        // Enable pf (ignore error if already enabled)
        let enable = Process()
        enable.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        enable.arguments = ["-e"]
        enable.standardOutput = Pipe()
        enable.standardError = Pipe()
        try enable.run()
        enable.waitUntilExit()

        // Load rules into anchor
        let load = Process()
        load.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        load.arguments = ["-a", "com.apple/squirrelops", "-f", tempFile.path]
        let loadPipe = Pipe()
        load.standardError = loadPipe
        try load.run()
        load.waitUntilExit()

        if load.terminationStatus != 0 {
            let stderr = String(
                data: loadPipe.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            ) ?? ""
            throw RPCError.internalError("pfctl anchor load failed: \(stderr)")
        }

        return ["success": true, "rules_count": pfRules.count]
    }

    router.handlers["clearPortForwards"] = { _ in
        let flush = Process()
        flush.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        flush.arguments = ["-a", "com.apple/squirrelops", "-F", "all"]
        let pipe = Pipe()
        flush.standardError = pipe
        try flush.run()
        flush.waitUntilExit()

        if flush.terminationStatus != 0 {
            let stderr = String(
                data: pipe.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            ) ?? ""
            throw RPCError.internalError("pfctl anchor flush failed: \(stderr)")
        }
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

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
        process.arguments = [interface, "-alias", ip]
        let pipe = Pipe()
        process.standardError = pipe
        try process.run()
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            let stderr = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            throw RPCError.internalError("ifconfig -alias failed: \(stderr)")
        }
        return ["success": true]
    }
}

/// Validates that a string is a valid IPv4 address (four octets 0-255).
private func isValidIPv4(_ address: String) -> Bool {
    let parts = address.split(separator: ".")
    guard parts.count == 4 else { return false }
    return parts.allSatisfy { part in
        guard let num = Int(part), num >= 0, num <= 255 else { return false }
        return true
    }
}
