import Foundation
import Testing
@testable import SquirrelOpsHelper

@Suite("SquirrelOpsHelper")
struct HelperTests {
    @Test("Module imports successfully")
    func moduleImports() {
        #expect(true, "SquirrelOpsHelper module imported successfully")
    }

    @Test("Privileged RPC allows only root and the sensor service account")
    func privilegedPeerAuthorization() {
        #expect(isAuthorizedPeer(0, serviceUID: 499))
        #expect(isAuthorizedPeer(499, serviceUID: 499))
        #expect(!isAuthorizedPeer(501, serviceUID: 499))
        #expect(!isAuthorizedPeer(501, serviceUID: nil))
    }

    @Test("Command runner drains large stdout and stderr without deadlocking")
    func commandRunnerDrainsBothPipes() throws {
        let emitLargeOutput = """
        i=0
        while [ "$i" -lt 20000 ]; do
            printf '0123456789abcdef0123456789abcdef'
            i=$((i + 1))
        done
        i=0
        while [ "$i" -lt 20000 ]; do
            printf 'fedcba9876543210fedcba9876543210' >&2
            i=$((i + 1))
        done
        """

        let result = try runCommand(
            executable: "/bin/sh",
            arguments: ["-c", emitLargeOutput]
        )

        #expect(result.status == 0)
        #expect(result.stdout.utf8.count == 640_000)
        #expect(result.stderr.utf8.count == 640_000)
    }

    @Test("Command runner caps retained stdout and stderr")
    func commandRunnerCapsOutput() throws {
        let emitOversizedOutput = """
        i=0
        while [ "$i" -lt 50000 ]; do
            printf '0123456789abcdef0123456789abcdef'
            printf 'fedcba9876543210fedcba9876543210' >&2
            i=$((i + 1))
        done
        """

        let result = try runCommand(
            executable: "/bin/sh",
            arguments: ["-c", emitOversizedOutput],
            outputLimitBytes: 32_768
        )

        #expect(result.status == 0)
        #expect(result.stdout.utf8.count == 32_768)
        #expect(result.stderr.utf8.count == 32_768)
    }

    @Test("Command runner kills a child after its absolute deadline")
    func commandRunnerTimesOut() {
        let start = DispatchTime.now().uptimeNanoseconds

        #expect(throws: CommandExecutionError.timedOut) {
            try runCommand(
                executable: "/bin/sh",
                arguments: ["-c", "trap '' TERM; while :; do :; done"],
                timeoutSeconds: 0.05
            )
        }

        let elapsed = Double(
            DispatchTime.now().uptimeNanoseconds - start
        ) / 1_000_000_000
        #expect(elapsed < 2)
    }

    @Test("Command input cannot block past the child deadline")
    func commandInputTimesOut() {
        let input = Data(repeating: 0x61, count: 1_048_576)
        let start = DispatchTime.now().uptimeNanoseconds

        #expect(throws: CommandExecutionError.timedOut) {
            try runCommand(
                executable: "/bin/sh",
                arguments: ["-c", "trap '' TERM; while :; do :; done"],
                input: input,
                timeoutSeconds: 0.05
            )
        }

        let elapsed = Double(
            DispatchTime.now().uptimeNanoseconds - start
        ) / 1_000_000_000
        #expect(elapsed < 2)
    }

    @Test("Command runner closes every parent-side pipe descriptor")
    func commandRunnerDoesNotLeakDescriptors() throws {
        let before = try FileManager.default.contentsOfDirectory(
            atPath: "/dev/fd"
        ).count

        for _ in 0..<64 {
            let result = try runCommand(
                executable: "/usr/bin/true",
                arguments: []
            )
            #expect(result.status == 0)
        }

        let after = try FileManager.default.contentsOfDirectory(
            atPath: "/dev/fd"
        ).count
        #expect(after <= before + 4)
    }
}
