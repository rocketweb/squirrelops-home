import Foundation
import ServiceManagement

/// Manages installation and version checking of the privileged helper.
enum HelperManager {

    private static let helperLabel = "com.squirrelops.helper"

    /// Install the helper if not already installed or if outdated.
    static func installIfNeeded() {
        #if os(macOS)
        // The desktop app is intentionally not authorized to connect. Check
        // launchd state instead of probing the privileged RPC socket.
        if isHelperResponding() {
            return
        }

        installHelper()
        #endif
    }

    /// Check whether launchd reports the helper as loaded.
    private static func isHelperResponding() -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["print", "system/\(helperLabel)"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }

    /// Install the helper via SMAppService.
    private static func installHelper() {
        #if DEBUG
        print("Skipping helper registration in debug build (requires code signing)")
        return
        #else
        let service = SMAppService.daemon(plistName: "\(helperLabel).plist")
        do {
            try service.register()
        } catch {
            print("SMAppService register failed: \(error.localizedDescription)")
        }
        #endif
    }
}
