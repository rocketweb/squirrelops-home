import Dispatch
import Darwin
import Foundation

func installRuntimeSignalPolicy() {
    signal(SIGPIPE, SIG_IGN)
}

@main
struct SquirrelOpsDeceptionGuestMain {
    @MainActor
    static func main() async {
        installRuntimeSignalPolicy()
        let output = RuntimeOutput()
        do {
            let arguments = try GuestArguments.parse(Array(CommandLine.arguments.dropFirst()))
            #if DEBUG
            let manifest = try ValidatedGuestManifest.load(
                bundleURL: arguments.bundleURL,
                trustedUIDs: [0, getuid()]
            )
            #else
            let manifest = try ValidatedGuestManifest.load(bundleURL: arguments.bundleURL)
            #endif
            let personaArchive = try PersonaArchive.read(from: .standardInput)
            let runtime = try VirtualMachineRuntime(
                manifest: manifest,
                bindAddress: arguments.bindAddress,
                personaArchive: personaArchive,
                output: output
            )

            signal(SIGTERM, SIG_IGN)
            signal(SIGINT, SIG_IGN)
            let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
            termination.setEventHandler {
                Task { @MainActor in await runtime.stop() }
            }
            termination.activate()
            let interruption = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
            interruption.setEventHandler {
                Task { @MainActor in await runtime.stop() }
            }
            interruption.activate()

            let ports = try await runtime.start()
            output.write([
                "status": "ready",
                "persona_id": manifest.manifest.personaID,
                "services": [
                    "22": Int(ports[22] ?? 0),
                    "445": Int(ports[445] ?? 0),
                ],
            ])
            runtime.activateListeners()
            await runtime.waitUntilStopped()
        } catch {
            FileHandle.standardError.write(Data("\(error.localizedDescription)\n".utf8))
            Foundation.exit(EXIT_FAILURE)
        }
    }
}
