import Foundation
import Testing

@testable import SquirrelOpsHome

@Suite("First-launch setup paths")
struct SetupPathTests {
    @Test("First launch offers exactly local protection and remote connection")
    func offersTwoIntentionalPaths() {
        #expect(SetupPath.allCases == [
            .protectThisMac,
            .connectToAnotherSensor,
        ])
    }

    @Test("Only local protection depends on package-installed services")
    func scopesLocalServicesToLocalProtection() {
        #expect(SetupPath.protectThisMac.requiresLocalServices)
        #expect(!SetupPath.connectToAnotherSensor.requiresLocalServices)
        #expect(
            SetupPath.protectThisMac.installationNote
                == "Included with the SquirrelOps Home package"
        )
        #expect(
            SetupPath.connectToAnotherSensor.installationNote
                == "No local services installed"
        )
    }

    @Test("Setup copy states the user outcome")
    func presentsOutcomeFocusedCopy() {
        #expect(SetupPath.protectThisMac.title == "Build Local Sensor")
        #expect(SetupPath.connectToAnotherSensor.title == "Connect to Another Sensor")
        #expect(SetupPath.protectThisMac.detail.contains("this Mac"))
        #expect(SetupPath.connectToAnotherSensor.detail.contains("network"))
    }

    @Test("Installed sensor keeps retrying throughout upgrade recovery")
    func keepsRetryingDuringUpgradeRecovery() {
        #expect(
            LocalSensorStartupPolicy.decision(
                isInstalled: true,
                elapsedSeconds: 4 * 60
            ) == .retry
        )
        #expect(
            LocalSensorStartupPolicy.decision(
                isInstalled: true,
                elapsedSeconds: 19 * 60
            ) == .retry
        )
        #expect(
            LocalSensorStartupPolicy.decision(
                isInstalled: true,
                elapsedSeconds: 20 * 60
            ) == .timedOut
        )
    }

    @Test("Missing local installation does not enter startup polling")
    func missingInstallDoesNotPoll() {
        #expect(
            LocalSensorStartupPolicy.decision(
                isInstalled: false,
                elapsedSeconds: 0
            ) == .notInstalled
        )
    }

    @Test("Sensor startup presents the remote path as a bordered button")
    func startupRemoteActionHasButtonAffordance() throws {
        let appDirectory = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let setupSource = try String(
            contentsOf: appDirectory
                .appendingPathComponent("Sources/SquirrelOpsHome/Views/Setup/SetupFlow.swift"),
            encoding: .utf8
        )
        let checkingStart = try #require(
            setupSource.range(of: "private var checkingContent")
        )
        let nextStateStart = try #require(
            setupSource.range(
                of: "private var autoPairingContent",
                range: checkingStart.upperBound..<setupSource.endIndex
            )
        )
        let checkingSource = setupSource[
            checkingStart.lowerBound..<nextStateStart.lowerBound
        ]

        #expect(checkingSource.contains(
            "Label(\"Connect to Another Sensor\", systemImage: \"network\")"
        ))
        #expect(checkingSource.contains(".buttonStyle(.bordered)"))
        #expect(checkingSource.contains(".controlSize(.large)"))
    }

}
