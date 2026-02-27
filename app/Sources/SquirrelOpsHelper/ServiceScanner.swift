import Foundation

/// Performs service scanning by spawning nmap and parsing XML output.
enum ServiceScanner {

    /// Run a service scan using nmap.
    /// - Parameters:
    ///   - targets: IP addresses to scan.
    ///   - ports: Port numbers to check.
    /// - Returns: Array of dictionaries with ip, port, banner keys.
    private static let ipv4Pattern = try! NSRegularExpression(pattern: #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#)

    static func scan(targets: [String], ports: [Int]) throws -> [[String: Any]] {
        guard !targets.isEmpty, !ports.isEmpty else { return [] }

        // Validate inputs — this runs as root, reject anything suspicious
        for target in targets {
            let range = NSRange(target.startIndex..., in: target)
            guard ipv4Pattern.firstMatch(in: target, range: range) != nil else {
                throw RPCError.internalError("Invalid target IP: \(target)")
            }
        }
        for port in ports {
            guard (1...65535).contains(port) else {
                throw RPCError.internalError("Invalid port number: \(port)")
            }
        }

        let portStr = ports.map(String.init).joined(separator: ",")
        let args = ["-sV", "-T4", "--host-timeout", "15s", "--max-retries", "1",
                     "-p", portStr] + targets + ["-oX", "-"]

        let process = Process()
        // Check common nmap locations (Homebrew ARM, Homebrew Intel, system)
        let nmapPaths = ["/opt/homebrew/bin/nmap", "/usr/local/bin/nmap", "/usr/bin/nmap"]
        guard let nmapPath = nmapPaths.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            throw RPCError.internalError("nmap not found — install with: brew install nmap")
        }
        process.executableURL = URL(fileURLWithPath: nmapPath)
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        process.arguments = args

        try process.run()

        // Wait with timeout — kill nmap if it takes too long
        let nmapTimeout: TimeInterval = 120  // 2 minutes max
        let deadline = Date().addingTimeInterval(nmapTimeout)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.5)
        }
        if process.isRunning {
            process.terminate()
            // Give it a moment to clean up
            Thread.sleep(forTimeInterval: 1.0)
            if process.isRunning {
                process.interrupt()
            }
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return parseNmapXML(data)
    }

    /// Parse nmap XML output into result dictionaries.
    static func parseNmapXML(_ data: Data) -> [[String: Any]] {
        guard let xmlString = String(data: data, encoding: .utf8),
              !xmlString.isEmpty else { return [] }

        var results: [[String: Any]] = []

        // XMLDocument options: strip DTD to avoid parsing issues with DOCTYPE
        let options: XMLNode.Options = [.nodeLoadExternalEntitiesNever]
        guard let doc = try? XMLDocument(xmlString: xmlString, options: options) else {
            return []
        }

        let hosts = (try? doc.nodes(forXPath: "//host")) ?? []
        for host in hosts {
            guard let hostElem = host as? XMLElement,
                  let addrNode = try? hostElem.nodes(forXPath: "address[@addrtype='ipv4']").first
                      as? XMLElement,
                  let ip = addrNode.attribute(forName: "addr")?.stringValue else {
                continue
            }

            let portNodes = (try? hostElem.nodes(forXPath: ".//port")) ?? []
            for portNode in portNodes {
                guard let portElem = portNode as? XMLElement,
                      let stateNode = try? portElem.nodes(forXPath: "state").first
                          as? XMLElement,
                      stateNode.attribute(forName: "state")?.stringValue == "open",
                      let portId = portElem.attribute(forName: "portid")?.stringValue,
                      let portNum = Int(portId) else {
                    continue
                }

                var entry: [String: Any] = ["ip": ip, "port": portNum]

                if let serviceNode = try? portElem.nodes(forXPath: "service").first
                    as? XMLElement {
                    let product = serviceNode.attribute(forName: "product")?.stringValue ?? ""
                    let version = serviceNode.attribute(forName: "version")?.stringValue ?? ""
                    let banner = [product, version].filter { !$0.isEmpty }.joined(separator: "/")
                    if !banner.isEmpty {
                        entry["banner"] = banner
                    }
                }

                results.append(entry)
            }
        }

        return results
    }
}
