import SwiftUI

/// The setup onboarding flow for first-time sensor pairing.
public struct SetupFlow: View {
    @Environment(\.colorScheme) private var colorScheme
    let pairingManager: PairingManager
    var onPaired: (PairingManager.PairedSensor) -> Void

    @State private var selectedSensor: PairingManager.DiscoveredSensor?
    @State private var pairingComplete = false

    public init(pairingManager: PairingManager, onPaired: @escaping (PairingManager.PairedSensor) -> Void) {
        self.pairingManager = pairingManager
        self.onPaired = onPaired
    }

    public var body: some View {
        Group {
            if pairingComplete {
                PairingCompleteView(pairingManager: pairingManager) {
                    // When user clicks Continue, trigger the connection
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
            } else {
                ScanningView(pairingManager: pairingManager) { sensor in
                    selectedSensor = sensor
                }
            }
        }
        .frame(minWidth: 480, minHeight: 400)
        .background(Theme.background(colorScheme))
    }
}

// MARK: - ScanningView

/// Step 1: Searching for sensors on the local network.
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

            Text("Make sure your SquirrelOps sensor is running and connected to the same network.")
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
