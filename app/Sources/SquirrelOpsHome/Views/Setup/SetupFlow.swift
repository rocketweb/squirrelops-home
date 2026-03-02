import SwiftUI

/// The setup onboarding flow for first-time sensor pairing.
///
/// On first launch the flow attempts to detect a local sensor (installed by the
/// .pkg) before falling back to mDNS network scanning.
public struct SetupFlow: View {
    @Environment(\.colorScheme) private var colorScheme
    let pairingManager: PairingManager
    var onPaired: (PairingManager.PairedSensor) -> Void

    @State private var selectedSensor: PairingManager.DiscoveredSensor?
    @State private var pairingComplete = false
    /// `nil` = still checking for local sensor, `true` = local check done (no sensor found)
    @State private var localCheckComplete: Bool?

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
            } else if localCheckComplete == true {
                // Local sensor not found — fall back to mDNS network scan
                ScanningView(pairingManager: pairingManager) { sensor in
                    selectedSensor = sensor
                }
            } else {
                // First step: try to find the local sensor and auto-pair
                LocalSensorSetupView(pairingManager: pairingManager) { sensor in
                    // Auto-pair failed — fall back to manual code entry
                    selectedSensor = sensor
                } onAutoPaired: {
                    // Auto-paired successfully — skip straight to completion
                    pairingComplete = true
                } onFallbackToScan: {
                    localCheckComplete = true
                }
            }
        }
        .frame(minWidth: 480, minHeight: 400)
        .background(Theme.background(colorScheme))
    }
}

// MARK: - LocalSensorSetupView

/// First setup step: detect the local sensor installed by the .pkg.
///
/// Checks `localhost:8443` for a running sensor. If found, automatically
/// pairs via the localhost-only code endpoint. If not, checks whether the
/// LaunchDaemon is installed and offers to retry or fall back to network scanning.
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
    @State private var retryCount = 0

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
        .task {
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

            Text("Detecting the local sensor on this device...")
                .font(Typography.body)
                .foregroundStyle(Theme.textSecondary(colorScheme))
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)

            ProgressView()
                .controlSize(.large)
                .padding(.top, Spacing.md)
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

            Text("Auto-Pairing Failed")
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
                    retryCount += 1
                    Task { await detectAndPair() }
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
                    Text("Enter Code")
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
                    retryCount += 1
                    Task { await detectAndPair() }
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

            Text("No sensor is installed on this device. You can search the network for a remote sensor instead.")
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
        // Check localhost health endpoint
        if let sensor = await pairingManager.detectLocalSensor() {
            // Sensor found — auto-pair immediately
            detectionState = .autoPairing(sensor)
            do {
                _ = try await pairingManager.autoLocalPair(sensor: sensor)
                onAutoPaired()
            } catch {
                detectionState = .autoPairFailed(sensor, error.localizedDescription)
            }
            return
        }

        // Sensor didn't respond — check if it's at least installed
        if PairingManager.isLocalSensorInstalled {
            // Installed but not responding — maybe still starting after pkg install.
            // Wait a few seconds and retry once automatically.
            if retryCount == 0 {
                try? await Task.sleep(for: .seconds(3))
                if let sensor = await pairingManager.detectLocalSensor() {
                    detectionState = .autoPairing(sensor)
                    do {
                        _ = try await pairingManager.autoLocalPair(sensor: sensor)
                        onAutoPaired()
                    } catch {
                        detectionState = .autoPairFailed(sensor, error.localizedDescription)
                    }
                    return
                }
            }
            detectionState = .notRunning
        } else {
            detectionState = .notInstalled
        }
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
