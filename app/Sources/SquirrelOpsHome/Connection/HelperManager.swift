import Foundation
import ServiceManagement

/// Manages installation and version checking of the privileged helper.
enum HelperManager {

    private static let helperLabel = "com.squirrelops.helper"

    /// Install the helper if not already installed or if outdated.
    static func installIfNeeded() {
        #if os(macOS)
        // Check if helper is already running by attempting connection
        if isHelperResponding() {
            return
        }

        installHelper()
        #endif
    }

    /// Check if the helper is responding on its socket.
    private static func isHelperResponding() -> Bool {
        let socketPath = "/var/run/squirrelops-helper.sock"
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let pathPtr = UnsafeMutableRawPointer(ptr).bindMemory(to: CChar.self, capacity: 104)
            socketPath.withCString { src in
                _ = strlcpy(pathPtr, src, 104)
            }
        }

        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        return result == 0
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
