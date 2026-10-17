// Test entry point, compiled with unchanged production helper sources.
// No helper socket, launchd job, ledger, installed files or arbitrary RPC.
import Foundation
import Darwin
import os

// Linked helper sources use this logger, but no enrollment service is started.
let logger = Logger(subsystem: "com.squirrelops.test.pf-acceptance", category: "probe")

let ips = ["192.168.1.239", "192.168.1.240"]
let ports = [61322, 61445]
let endpoints: [[String: Any]] = ips.map { ["ip": $0, "direct_ports": [Int]()] }
let forwards: [[String: Any]] = ips.enumerated().map { index, ip in
    ["from_ip": ip, "from_port": index == 0 ? 22 : 445,
     "to_ip": ip, "to_port": ports[index]]
}

@MainActor func rules(_ live: Bool) throws -> [String] {
    try buildPFRules(forwardingRules: live ? forwards : [], protectedEndpoints: endpoints,
                     interface: "en0", sensorUID: live ? 309 : nil)
}

func emit(_ value: [String: Any]) {
    let data = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    FileHandle.standardOutput.write(data + Data([10]))
}

if CommandLine.arguments.count == 1 {
    emit(["live_rules": try rules(true), "quarantine_rules": try rules(false),
          "vips": ips, "ports": ports, "mutations": false])
    exit(0)
}
guard CommandLine.arguments.count == 3,
      CommandLine.arguments[1] == "--attended",
      getuid() == 0,
      CommandLine.arguments[2].range(of: "^com[.]apple/squirrelops-a5-[a-f0-9]{12}$",
                                    options: .regularExpression) != nil else {
    fputs("Invalid attended PF probe invocation\n", stderr)
    exit(2)
}
let anchor = CommandLine.arguments[2]
var cache = PFEndpointStateCache()
while let line = readLine() {
    guard line.utf8.count <= 512 else { exit(2) }
    var calls: [[String: Any]] = []
    do {
        guard let request = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: String],
              request.count == 1, let op = request["op"],
              ["unused", "listener_check", "publish", "quarantine", "fail_load",
               "fail_load_first_kill"].contains(op) else { throw RPCError.invalidRequest }
        let runner: PFCommandRunner = { arguments, input in
            var args = arguments
            if args == ["-a", "com.apple/squirrelops", "-f", "-"] {
                args[1] = anchor
                if op == "fail_load" || op == "fail_load_first_kill" {
                    calls.append(["args": args, "injected_failure": true, "status": 1])
                    return CommandResult(status: 1, stdout: "", stderr: "injected load failure")
                }
            }
            let load = args == ["-a", anchor, "-f", "-"]
            let kill = ips.contains(where: { args == ["-k", "0.0.0.0/0", "-k", $0] })
            guard load || kill || args == ["-s", "info"] else {
                throw RPCError.internalError("Probe rejected an out-of-scope PF command")
            }
            if op == "fail_load_first_kill" && args == ["-k", "0.0.0.0/0", "-k", ips[0]] {
                calls.append(["args": args, "injected_failure": true, "status": 1])
                return CommandResult(status: 1, stdout: "", stderr: "injected first-IP state failure")
            }
            let result = try runPFCTL(arguments: args, input: input)
            calls.append(["args": args, "status": result.status,
                          "stdout": result.stdout, "stderr": result.stderr])
            return result
        }
        switch op {
        case "unused":
            for ip in ips {
                try requireUnusedVirtualIPAddress(ip: ip, interface: "en0", using: { executable, args in
                    try runCommand(executable: executable, arguments: args)
                })
            }
        case "listener_check":
            for (index, ip) in ips.enumerated() {
                try requireSensorOwnedListener(PFBackendListener(ip: ip, port: ports[index]), serviceUID: 309,
                                               run: { executable, args in
                    try runCommand(executable: executable, arguments: args)
                })
            }
        case "publish":
            for (index, ip) in ips.enumerated() {
                try requireSensorOwnedListener(PFBackendListener(ip: ip, port: ports[index]), serviceUID: 309,
                                               run: { executable, args in
                    try runCommand(executable: executable, arguments: args)
                })
            }
            try requirePacketFilteringEnabled(phase: "before test publication", using: runner)
            let signatures = try pfEndpointStateSignatures(forwardingRules: forwards,
                protectedEndpoints: endpoints, interface: "en0", sensorUID: 309)
            let cleanup = cache.cleanupIPs(for: signatures)
            let result = try runner(["-a", "com.apple/squirrelops", "-f", "-"],
                                    Data((try rules(true)).joined(separator: "\n").appending("\n").utf8))
            guard result.status == 0 else { throw RPCError.internalError("Test publication failed") }
            cache.recordSuccessfulLiveMutation(signatures, cleanupIPs: cleanup)
            try cleanupPFStates(for: cleanup, using: runner)
            cache.completeCleanup()
        default:
            try quarantinePortForwardingAfterListenerRace(protectedEndpoints: endpoints,
                interface: "en0", stateCache: &cache, using: runner)
        }
        emit(["ok": true, "calls": calls,
              "alias_authorized": ips.map { cache.protectsVirtualIP(ip: $0, interface: "en0") }])
    } catch {
        emit(["ok": false, "error": String(describing: error), "calls": calls,
              "alias_authorized": ips.map { cache.protectsVirtualIP(ip: $0, interface: "en0") }])
    }
}
