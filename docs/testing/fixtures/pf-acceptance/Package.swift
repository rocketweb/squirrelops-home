// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SquirrelOpsPFProbe",
    platforms: [.macOS(.v14)],
    targets: [
        .target(name: "SquirrelOpsLocalEnrollment"),
        .executableTarget(name: "SquirrelOpsPFProbe", dependencies: ["SquirrelOpsLocalEnrollment"],
                          exclude: ["Resources"]),
    ]
)
