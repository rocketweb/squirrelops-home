// swift-tools-version: 6.0
import PackageDescription

// Used only in the disposable capture workspace created by build.sh.
let package = Package(name: "SquirrelOpsHome", platforms: [.macOS(.v14)], targets: [
    .target(name: "SquirrelOpsLocalEnrollment"),
    .executableTarget(name: "SquirrelOpsHome", dependencies: ["SquirrelOpsLocalEnrollment"],
        resources: [.copy("Resources/Fonts"), .copy("Resources/AppIcon.icns")]),
])
