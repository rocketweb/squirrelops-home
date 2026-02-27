import Foundation

/// Manages local macOS sensor installation and lifecycle via launchd.
@Observable
final class SensorInstaller {
    private(set) var isInstalled = false
    private(set) var isRunning = false
    private(set) var installError: String?

    private let plistName = "com.squirrelops.sensor"
    private let installDir: URL
    private let plistURL: URL

    init() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        installDir = home.appendingPathComponent(".squirrelops/sensor")
        plistURL = home
            .appendingPathComponent("Library/LaunchAgents")
            .appendingPathComponent("\(plistName).plist")
    }

    /// Check if sensor is installed and running.
    func checkStatus() {
        isInstalled = FileManager.default.fileExists(atPath: plistURL.path)

        if isInstalled {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            process.arguments = ["print", "gui/\(getuid())/\(plistName)"]
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            try? process.run()
            process.waitUntilExit()
            isRunning = process.terminationStatus == 0
        } else {
            isRunning = false
        }
    }

    /// Install sensor by running the install script.
    func install() async {
        installError = nil
        let scriptURL = Bundle.main.url(forResource: "install-macos", withExtension: "sh")
            ?? URL(fileURLWithPath: "/usr/local/bin/squirrelops-install-macos.sh")

        guard FileManager.default.fileExists(atPath: scriptURL.path) else {
            installError = "Install script not found"
            return
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [scriptURL.path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            process.waitUntilExit()

            if process.terminationStatus != 0 {
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: data, encoding: .utf8) ?? "Unknown error"
                installError = "Installation failed: \(String(output.suffix(200)))"
            } else {
                checkStatus()
            }
        } catch {
            installError = "Failed to run installer: \(error.localizedDescription)"
        }
    }

    /// Start the sensor via launchctl.
    func start() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["bootstrap", "gui/\(getuid())", plistURL.path]
        try? process.run()
        process.waitUntilExit()
        checkStatus()
    }

    /// Stop the sensor via launchctl.
    func stop() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["bootout", "gui/\(getuid())/\(plistName)"]
        try? process.run()
        process.waitUntilExit()
        checkStatus()
    }

    /// Uninstall sensor completely.
    func uninstall() {
        stop()
        try? FileManager.default.removeItem(at: plistURL)
        try? FileManager.default.removeItem(at: installDir)
        checkStatus()
    }
}
