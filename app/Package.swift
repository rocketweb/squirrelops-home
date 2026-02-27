// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SquirrelOpsHome",
    platforms: [
        .macOS(.v14),
    ],
    targets: [
        .executableTarget(
            name: "SquirrelOpsHome",
            resources: [
                .copy("Resources/Fonts"),
                .copy("Resources/AppIcon.icns"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
        .executableTarget(
            name: "SquirrelOpsHelper",
            resources: [
                .copy("Resources/helper-info.plist"),
                .copy("Resources/launchd.plist"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
        .testTarget(
            name: "SquirrelOpsHomeTests",
            dependencies: ["SquirrelOpsHome"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
        .testTarget(
            name: "SquirrelOpsHelperTests",
            dependencies: ["SquirrelOpsHelper"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
    ]
)
