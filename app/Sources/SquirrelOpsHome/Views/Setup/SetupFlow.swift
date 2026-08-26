import SwiftUI

/// The setup onboarding flow for first-time sensor pairing.
///
/// First launch asks whether to use the package-installed local sensor or a
/// sensor already running elsewhere on the network.
public struct SetupFlow: View {
    @Environment(\.colorScheme) private var colorScheme
    let pairingManager: PairingManager
    var onPaired: (PairingManager.PairedSensor) -> Void

    @State private var selectedSensor: PairingManager.DiscoveredSensor?
    @State private var pairingComplete = false
    @State private var setupPath: SetupPath?

    public init(pairingManager: PairingManager, onPaired: @escaping (PairingManager.PairedSensor) -> Void) {
        self.pairingManager = pairingManager
        self.onPaired = onPaired
    }

    public var body: some View {
        Group {
            if pairingComplete {
                PairingCompleteView(pairingManager: pairingManager) {
                    if case .paired(let sensor) = pairingManager.state {
                        onPaired(sensor)
                    }
                }
            } else if let sensor = selectedSensor {
                PairingView(
                    pairingManager: pairingManager,
                    sensor: sensor
                ) {
                    pairingComplete = true
                }
            } else if setupPath == .connectToAnotherSensor {
                ScanningView(pairingManager: pairingManager) { sensor in
                    selectedSensor = sensor
                }
            } else if setupPath == .protectThisMac {
                LocalSensorSetupView(pairingManager: pairingManager) { sensor in
                    selectedSensor = sensor
                } onAutoPaired: {
                    pairingComplete = true
                } onFallbackToScan: {
                    setupPath = .connectToAnotherSensor
                }
            } else {
                SetupChoiceView { path in
                    setupPath = path
                }
            }
        }
        .frame(minWidth: 480, minHeight: 400)
        .background(Theme.background(colorScheme))
        .overlay(alignment: .topLeading) {
            if setupPath != nil, selectedSensor == nil, !pairingComplete {
                Button {
                    pairingManager.stopDiscovery()
                    setupPath = nil
                } label: {
                    Label("Back", systemImage: "chevron.left")
                        .font(Typography.caption)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                }
                .buttonStyle(.plain)
                .padding(Spacing.md)
            }
        }
    }
}

// MARK: - SetupChoiceView

struct SetupChoiceView: View {
    @Environment(\.colorScheme) private var colorScheme
    let onSelect: (SetupPath) -> Void

    var body: some View {
        VStack(spacing: Spacing.lg) {
            Spacer()

            Image(systemName: "shield.checkered")
                .font(.system(size: 48))
                .foregroundStyle(Theme.accentDefault(colorScheme))

            VStack(spacing: Spacing.sm) {
                Text("Set Up SquirrelOps Home")
                    .font(Typography.h2)
                    .foregroundStyle(Theme.textPrimary(colorScheme))

                Text("Choose how you want to use this Mac.")
                    .font(Typography.body)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
            }

            HStack(spacing: Spacing.md) {
                ForEach(SetupPath.allCases) { path in
                    setupCard(path)
                }
            }
            .frame(maxWidth: 720)

            Spacer()
        }
        .padding(Spacing.xl)
    }

    private func setupCard(_ path: SetupPath) -> some View {
        Button {
            onSelect(path)
        } label: {
            VStack(alignment: .leading, spacing: Spacing.md) {
                Image(systemName: path.systemImage)
                    .font(.system(size: 28))
                    .foregroundStyle(Theme.accentDefault(colorScheme))

                Text(path.title)
                    .font(Typography.h3)
                    .foregroundStyle(Theme.textPrimary(colorScheme))

                Text(path.detail)
                    .font(Typography.body)
                    .foregroundStyle(Theme.textSecondary(colorScheme))
                    .multilineTextAlignment(.leading)

                Spacer(minLength: 0)

                Text(path.installationNote)
                    .font(Typography.caption)
                    .foregroundStyle(Theme.textTertiary(colorScheme))
            }
            .frame(maxWidth: .infinity, minHeight: 190, alignment: .topLeading)
            .padding(Spacing.lg)
            .background(Theme.backgroundSecondary(colorScheme))
            .overlay {
                RoundedRectangle(cornerRadius: Spacing.radiusLg)
                    .stroke(Theme.borderDefault(colorScheme), lineWidth: 1)
            }
            .clipShape(RoundedRectangle(cornerRadius: Spacing.radiusLg))
        }
        .buttonStyle(.plain)
        .accessibilityHint(path.detail)
    }
}

// MARK: - LocalSensorSetupView

/// First setup step: detect the local sensor installed by the .pkg.
///
/// Checks `localhost:8443` for a running sensor. If found, automatically
/// enrolls through the signed privileged helper. If not, checks whether the
/// LaunchDaemon is installed and keeps polling during bounded upgrade recovery.
struct LocalSensorSetupView: View {
    @Environment(\.colorScheme) private var colorScheme
    let pairingManager: PairingManager
    /// Called when auto-pair fails and user wants to enter the code manually.
    let onManualPair: (PairingManager.DiscoveredSensor) -> Void
    /// Called when auto-pairing completes successfully.
    let onAutoPaired: () -> Void
    let onFallbackToScan: () -> Void

    private enum DetectionState {
        case checking
        case autoPairing(PairingManager.DiscoveredSensor)
        case autoPairFailed(PairingManager.DiscoveredSensor, String)
        case notRunning   // LaunchDaemon installed but sensor not responding
        case notInstalled // No LaunchDaemon plist found
    }

    @State private var detectionState: DetectionState = .checking
    @State private var retryGeneration = 0
    @State private var startupElapsedSeconds = 0

    var body: some View {
        VStack(spacing: Spacing.lg) {
            Spacer()

            switch detectionState {
            case .checking:
                checkingContent
            case .autoPairing:
                autoPairingContent
            case .autoPairFailed(let sensor, let error):
                autoPairFailedContent(sensor: sensor, error: error)
            case .notRunning:
                notRunningContent
            case .notInstalled:
                notInstalledContent
            }

            Spacer()
        }
        .padding(Spacing.xl)
        .task(id: retryGeneration) {
            await detectAndPair()
        }
    }

    // MARK: - State Views

    private var checkingContent: some View {
        VStack(spacing: Spacing.lg) {
            Image(systemName: "sensor.tag.radiowaves.forward")
                .font(.system(size: 48))
                .foregroundStyle(Theme.accentDefault(colorScheme))

            Text("Setting Up Sensor")
                .font(Typography.h2)
                .foregroundStyle(Theme.textPrimary(colorScheme))

            Text(checkingMessage)
                .font(Typography.body)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)

            ProgressView()
                .controlSize(.large)
                .padding(.top, Spacing.md)

            if startupElapsedSeconds > 0 {
                Text("Elapsed \(formattedStartupElapsed)")
                    .font(Typography.caption)
                    .foregroundStyle(Theme.textTertiary(colorScheme))
                    .monospacedDigit()
            }

            Button {
                onFallbackToScan()
            } label: {
                Label("Connect to Another Sensor", systemImage: "network")
                    .frame(minWidth: 210)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
            .font(Typography.bodySmall)
            .accessibilityHint("Stop waiting and search for a sensor on your network")
        }
    }

    private var autoPairingContent: some View {
        VStack(spacing: Spacing.lg) {
            ProgressView()
                .controlSize(.large)

            Text("Pairing with Local Sensor")
                .font(Typography.h2)
                .foregroundStyle(Theme.textPrimary(colorScheme))

            Text("Establishing a secure connection with the sensor on this device...")
                .font(Typography.body)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)
        }
    }

    private func autoPairFailedContent(sensor: PairingManager.DiscoveredSensor, error: String) -> some View {
        VStack(spacing: Spacing.lg) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 48))
                .foregroundStyle(Theme.statusWarning(colorScheme))

            Text("Automatic Setup Couldn't Finish")
                .font(Typography.h2)
                .foregroundStyle(Theme.textPrimary(colorScheme))

            Text(error)
                .font(Typography.bodySmall)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)

            HStack(spacing: Spacing.md) {
                Button {
                    detectionState = .checking
                    startupElapsedSeconds = 0
                    retryGeneration += 1
                } label: {
                    Text("Retry")
                        .font(Typography.body)
                        .foregroundStyle(.white)
                        .frame(maxWidth: 140)
                        .padding(.vertical, Spacing.s12)
                        .background(Theme.accentDefault(colorScheme))
                        .cornerRadius(Spacing.radiusMd)
                }
                .buttonStyle(.plain)

                Button {
                    onManualPair(sensor)
                } label: {
                    Text("Use Setup Key")
                        .font(Typography.body)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                        .frame(maxWidth: 140)
                        .padding(.vertical, Spacing.s12)
                        .background(Theme.backgroundSecondary(colorScheme))
                        .cornerRadius(Spacing.radiusMd)
                        .overlay(
                            RoundedRectangle(cornerRadius: Spacing.radiusMd)
                                .stroke(Theme.borderDefault(colorScheme), lineWidth: 1)
                        )
                }
                .buttonStyle(.plain)
            }
        }
    }

    private var notRunningContent: some View {
        VStack(spacing: Spacing.lg) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 48))
                .foregroundStyle(Theme.statusWarning(colorScheme))

            Text("Sensor Not Responding")
                .font(Typography.h2)
                .foregroundStyle(Theme.textPrimary(colorScheme))

            Text("The sensor is installed but isn't responding yet. It may still be starting up.")
                .font(Typography.body)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)

            HStack(spacing: Spacing.md) {
                Button {
                    detectionState = .checking
                    startupElapsedSeconds = 0
                    retryGeneration += 1
                } label: {
                    Text("Retry")
                        .font(Typography.body)
                        .foregroundStyle(.white)
                        .frame(maxWidth: 140)
                        .padding(.vertical, Spacing.s12)
                        .background(Theme.accentDefault(colorScheme))
                        .cornerRadius(Spacing.radiusMd)
                }
                .buttonStyle(.plain)

                Button {
                    onFallbackToScan()
                } label: {
                    Text("Search Network")
                        .font(Typography.body)
                        .foregroundStyle(Theme.textSecondary(colorScheme))
                        .frame(maxWidth: 140)
                        .padding(.vertical, Spacing.s12)
                        .background(Theme.backgroundSecondary(colorScheme))
                        .cornerRadius(Spacing.radiusMd)
                        .overlay(
                            RoundedRectangle(cornerRadius: Spacing.radiusMd)
                                .stroke(Theme.borderDefault(colorScheme), lineWidth: 1)
                        )
                }
                .buttonStyle(.plain)
            }
        }
    }

    private var notInstalledContent: some View {
        VStack(spacing: Spacing.lg) {
            Image(systemName: "sensor.tag.radiowaves.forward")
                .font(.system(size: 48))
                .foregroundStyle(Theme.textTertiary(colorScheme))

            Text("No Local Sensor Found")
                .font(Typography.h2)
                .foregroundStyle(Theme.textPrimary(colorScheme))

            Text("The local sensor is installed by the SquirrelOps Home package. Install that package to protect this Mac, or connect to a sensor already on your network.")
                .font(Typography.body)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)

            Button {
                onFallbackToScan()
            } label: {
                Text("Search Network")
                    .font(Typography.body)
                    .foregroundStyle(.white)
                    .frame(maxWidth: 200)
                    .padding(.vertical, Spacing.s12)
                    .background(Theme.accentDefault(colorScheme))
                    .cornerRadius(Spacing.radiusMd)
            }
            .buttonStyle(.plain)
        }
    }

    // MARK: - Detection & Auto-Pair Logic

    private func detectAndPair() async {
        let startedAt = Date()

        while !Task.isCancelled {
            if let sensor = await pairingManager.detectLocalSensor() {
                detectionState = .autoPairing(sensor)
                do {
                    _ = try await pairingManager.autoLocalPair(sensor: sensor)
                    onAutoPaired()
                } catch {
                    detectionState = .autoPairFailed(
                        sensor,
                        error.localizedDescription
                    )
                }
                return
            }

            let elapsedSeconds = max(
                0,
                Int(Date().timeIntervalSince(startedAt))
            )
            startupElapsedSeconds = elapsedSeconds

            switch LocalSensorStartupPolicy.decision(
                isInstalled: PairingManager.isLocalSensorInstalled,
                elapsedSeconds: elapsedSeconds
            ) {
            case .retry:
                detectionState = .checking
                do {
                    try await Task.sleep(
                        for: LocalSensorStartupPolicy.retryInterval
                    )
                } catch {
                    return
                }
            case .timedOut:
                detectionState = .notRunning
                return
            case .notInstalled:
                detectionState = .notInstalled
                return
            }
        }
    }

    private var checkingMessage: String {
        if startupElapsedSeconds == 0 {
            return "Detecting the local sensor on this device..."
        }
        return "The sensor is restoring protection after the upgrade. This can take several minutes when decoys are present. This screen retries automatically."
    }

    private var formattedStartupElapsed: String {
        let minutes = startupElapsedSeconds / 60
        let seconds = startupElapsedSeconds % 60
        return String(format: "%d:%02d", minutes, seconds)
    }
}

// MARK: - ScanningView

/// Fallback step: Searching for sensors on the local network via mDNS.
struct ScanningView: View {
    @Environment(\.colorScheme) private var colorScheme
    let pairingManager: PairingManager
    let onSensorSelected: (PairingManager.DiscoveredSensor) -> Void

    var body: some View {
        VStack(spacing: Spacing.lg) {
            Spacer()

            Image(systemName: "sensor.tag.radiowaves.forward")
                .font(.system(size: 48))
                .foregroundStyle(Theme.accentDefault(colorScheme))

            Text("Searching for Sensors")
                .font(Typography.h2)
                .foregroundStyle(Theme.textPrimary(colorScheme))

            Text("Looking for SquirrelOps sensors on your network.")
                .font(Typography.body)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)

            if pairingManager.discoveredSensors.isEmpty {
                ProgressView()
                    .controlSize(.large)
                    .padding(.top, Spacing.md)
            } else {
                sensorList
            }

            Spacer()
        }
        .padding(Spacing.xl)
        .onAppear {
            pairingManager.startDiscovery()
        }
        .onDisappear {
            pairingManager.stopDiscovery()
        }
    }

    private var sensorList: some View {
        VStack(spacing: Spacing.sm) {
            ForEach(pairingManager.discoveredSensors) { sensor in
                Button {
                    pairingManager.stopDiscovery()
                    onSensorSelected(sensor)
                } label: {
                    HStack {
                        Image(systemName: "sensor.tag.radiowaves.forward.fill")
                            .foregroundStyle(Theme.statusSuccess(colorScheme))
                        VStack(alignment: .leading, spacing: 2) {
                            Text(sensor.name)
                                .font(Typography.body)
                                .foregroundStyle(Theme.textPrimary(colorScheme))
                            if let host = sensor.host {
                                Text(host)
                                    .font(Typography.mono)
                                    .foregroundStyle(Theme.textTertiary(colorScheme))
                            }
                        }
                        Spacer()
                        Image(systemName: "chevron.right")
                            .foregroundStyle(Theme.textTertiary(colorScheme))
                    }
                    .padding(Spacing.s12)
                    .background(Theme.backgroundSecondary(colorScheme))
                    .cornerRadius(Spacing.radiusMd)
                }
                .buttonStyle(.plain)
            }
        }
        .frame(maxWidth: 360)
    }
}

// MARK: - PairingCompleteView

/// Final step: Pairing is complete.
struct PairingCompleteView: View {
    @Environment(\.colorScheme) private var colorScheme
    let pairingManager: PairingManager
    let onContinue: () -> Void

    var body: some View {
        VStack(spacing: Spacing.lg) {
            Spacer()

            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 64))
                .foregroundStyle(Theme.statusSuccess(colorScheme))

            Text(connectedSensorName)
                .font(Typography.h2)
                .foregroundStyle(Theme.textPrimary(colorScheme))

            Text("Your sensor is paired and secured with mutual TLS. You can now monitor your network from the dashboard.")
                .font(Typography.body)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)

            Button {
                onContinue()
            } label: {
                Text("Continue")
                    .font(Typography.body)
                    .foregroundStyle(.white)
                    .frame(maxWidth: 200)
                    .padding(.vertical, Spacing.s12)
                    .background(Theme.accentDefault(colorScheme))
                    .cornerRadius(Spacing.radiusMd)
            }
            .buttonStyle(.plain)
            .padding(.top, Spacing.md)

            Spacer()
        }
        .padding(Spacing.xl)
    }

    private var connectedSensorName: String {
        if case .paired(let sensor) = pairingManager.state {
            return "Connected to \(sensor.name)"
        }
        return "Pairing Complete"
    }
}
