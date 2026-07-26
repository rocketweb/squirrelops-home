import SwiftUI

struct HelpGuideSection: Identifiable, Sendable {
    let id: String
    let title: String
    let symbol: String
    let summary: String
    let blocks: [HelpGuideBlock]
}

struct HelpGuideBlock: Sendable {
    let heading: String
    let body: String
    let bullets: [String]

    init(_ heading: String, _ body: String, bullets: [String] = []) {
        self.heading = heading
        self.body = body
        self.bullets = bullets
    }
}

enum HelpGuideContent {
    static let sections: [HelpGuideSection] = [
        .init(
            id: "getting-started",
            title: "Getting Started",
            symbol: "play.circle",
            summary: "Pair the Mac app with your SquirrelOps sensor and confirm monitoring.",
            blocks: [
                .init(
                    "Pair the app",
                    "Keep the sensor and Mac on the same trusted network. Launch SquirrelOps Home, select the detected sensor, enter its one-time setup key, and complete pairing. The resulting credentials are stored in the macOS Keychain."
                ),
                .init(
                    "Find the packaged Mac setup key",
                    "Open Terminal and run:\n\nsudo -u _squirrelops /Library/SquirrelOps/sensor/python/bin/python3 -m squirrelops_home_sensor --config /Library/SquirrelOps/sensor/config.yaml --show-pairing-code\n\nmacOS asks for an administrator password. The 20-character key expires after 10 minutes or after it is used. If it expired, run sudo launchctl kickstart -k system/com.squirrelops.sensor, then retrieve it again."
                ),
                .init(
                    "Confirm monitoring",
                    "A green Monitoring Active status means the app has a live authenticated connection. Initial learning may take time while SquirrelOps builds a baseline.",
                    bullets: [
                        "Open the menu bar squirrel at any time to see connection and unread-alert status.",
                        "If the sensor is disconnected, open the dashboard for the specific repair message.",
                        "Resource Profile controls how much scanning and analysis the sensor performs.",
                    ]
                ),
            ]
        ),
        .init(
            id: "dashboard",
            title: "Dashboard",
            symbol: "rectangle.3.group",
            summary: "Read network health, device totals, alert counts, and learning status.",
            blocks: [
                .init(
                    "Use the overview",
                    "The Dashboard summarizes the current sensor state. Select a card or use the sidebar to move into Devices, Alerts, Decoys, Scouts, or Settings."
                ),
                .init(
                    "Menu bar access",
                    "Choose Open Dashboard from the menu bar icon. If the dashboard already exists, SquirrelOps restores it, brings it in front of other apps, and gives it keyboard focus."
                ),
            ]
        ),
        .init(
            id: "devices",
            title: "Devices and Trust",
            symbol: "desktopcomputer",
            summary: "Identify devices and decide which network identities belong.",
            blocks: [
                .init(
                    "Review discovered devices",
                    "Use names, vendor data, IP and MAC addresses, open services, and fingerprint history together. Hostnames can be incomplete or reused, so do not trust a device from its name alone."
                ),
                .init(
                    "Set trust deliberately",
                    "Approve devices you recognize, reject identities that should not be present, and leave uncertain devices Unknown while investigating.",
                    bullets: [
                        "A changed MAC address or fingerprint can produce a new review item.",
                        "Custom names and notes help preserve your reasoning.",
                        "Offline means not recently observed; it does not delete the device history.",
                    ]
                ),
            ]
        ),
        .init(
            id: "alerts-notifications",
            title: "Alerts and Notifications",
            symbol: "bell.badge",
            summary: "Review detections in the app and receive native macOS notifications.",
            blocks: [
                .init(
                    "Understand alert states",
                    "Unread alerts appear in the menu bar and Alerts view. Opening an alert shows its evidence and available response actions. Clearing an alert marks the represented event as reviewed; clearing history permanently removes stored alert and incident history."
                ),
                .init(
                    "macOS notifications",
                    "Enable macOS Notifications in Settings and choose a minimum severity. The first time, macOS asks for permission. New qualifying alerts appear as standard Notification Center banners with sound, even while the dashboard is behind other windows.",
                    bullets: [
                        "Click a SquirrelOps notification to open the Alerts view.",
                        "Silence for 1 Hour suppresses menu-bar escalation, critical dialogs, and macOS notifications.",
                        "If banners do not appear, check System Settings → Notifications → SquirrelOps Home.",
                    ]
                ),
                .init(
                    "Critical alert dialog",
                    "Critical and high alerts can also appear inside the dashboard. Review opens the full alert list without marking the batch read; Clear marks the displayed batch read."
                ),
            ]
        ),
        .init(
            id: "decoys",
            title: "Decoys",
            symbol: "shield.lefthalf.filled",
            summary: "Deploy believable local services and investigate unexpected connections.",
            blocks: [
                .init(
                    "Choose a decoy",
                    "Host listeners expose a selected service on the sensor Mac. Fake hosts create a separate virtual network address with one or more service decoys. Use names that resemble your environment without copying credentials or sensitive production data."
                ),
                .init(
                    "Understand the counts",
                    "Active decoy deployments are fake hosts plus host listeners. Service decoys are the individual ports nested inside fake hosts, so they are shown separately and are not added to the deployment total. Lite supports no fake hosts, Standard supports up to 5, and Full supports up to 10; eligible discovered services determine how many can actually deploy."
                ),
                .init(
                    "Hostnames",
                    "Mimic hostnames may be a bare name, end in .local, or end in .localdomain. The app stores the hostname you enter and applies it to every service belonging to that virtual host."
                ),
                .init(
                    "Respond to a trip",
                    "A decoy connection is suspicious because ordinary users and devices should not need it. Check the source IP, time, repeated connections, credentials used, and related device history before isolating a device."
                ),
            ]
        ),
        .init(
            id: "scouts",
            title: "Squirrel Scouts",
            symbol: "binoculars",
            summary: "Extend visibility to supported remote or segmented network locations.",
            blocks: [
                .init(
                    "Deploy and monitor",
                    "Use Scouts to create the enrollment command, install it only on a system you administer, and confirm the scout becomes healthy. A scout reports observations to the paired sensor; it does not replace the sensor."
                ),
                .init(
                    "Troubleshoot",
                    "Confirm the scout can reach the sensor, its enrollment has not expired, system time is correct, and the service is running. Revoke a scout that is retired or no longer trusted."
                ),
            ]
        ),
        .init(
            id: "home-assistant",
            title: "Home Assistant",
            symbol: "house",
            summary: "Connect SquirrelOps to a Home Assistant instance you control.",
            blocks: [
                .init(
                    "Connect",
                    "Create a long-lived access token in the Home Assistant profile, enter the full Home Assistant URL, paste the token, enable the integration, save, and run Test Connection.",
                    bullets: [
                        "Use the URL reachable from the sensor, not necessarily the URL reachable only from this Mac.",
                        "Include http:// or https:// and the port when it is not the default.",
                        "A successful test reports the number of visible Home Assistant devices.",
                    ]
                ),
                .init(
                    "If connection fails",
                    "Verify the token is current, the sensor can route to the URL, DNS resolves from the sensor, and TLS certificates are valid. For a local self-signed deployment, prefer a trusted local CA rather than disabling verification."
                ),
            ]
        ),
        .init(
            id: "llm",
            title: "Optional AI Device Classification and Decoy Naming",
            symbol: "brain",
            summary: "Identify otherwise unknown devices and make some new fake-host names fit your network.",
            blocks: [
                .init(
                    "What AI does",
                    "Local signatures always run first. If they cannot identify a newly discovered device, the configured model may suggest its manufacturer, device type, model, and confidence. The sensor saves the accepted classification. AI does not analyze alerts, inspect packet contents, choose deployment targets, or take autonomous action."
                ),
                .init(
                    "How decoy naming works",
                    "New fake hosts normally use simple home and business names such as files, media, office, backup, printer, and automation. SquirrelOps avoids generic numbered or hexadecimal suffixes unless several real hostnames show that your network uses host identifiers. When AI is enabled, it reviews a bounded sample of existing hostnames and may suggest names for part of a new decoy batch. Every suggestion is validated locally, cannot collide with a real hostname, and never renames an existing decoy."
                ),
                .init(
                    "Choose a provider",
                    "None uses only deterministic local classification and naming. LM Studio and Ollama can run on this Mac or your private network. OpenRouter and Fireworks.ai require an API key. Custom supports another OpenAI-compatible endpoint. AI failures fall back locally and do not interrupt monitoring or decoy deployment."
                ),
                .init(
                    "Data sent to the provider",
                    "Device classification can send the MAC vendor prefix, sanitized DNS and mDNS names, open port numbers, detected service names, DHCP option codes, mDNS service types, and available UPnP name, manufacturer, model, and server metadata. It does not send fingerprint hashes, connection destinations, device IP addresses, full MAC addresses, packet contents, alert history, or credentials. Decoy naming sends a bounded, sanitized sample of existing hostnames. With a cloud provider, review its retention terms before enabling these features."
                ),
            ]
        ),
        .init(
            id: "settings",
            title: "Settings",
            symbol: "gearshape",
            summary: "Control resources, alerts, integrations, appearance, and updates.",
            blocks: [
                .init(
                    "Resource profiles",
                    "Lite minimizes resource use, Standard balances coverage and load, and Full enables the broadest supported analysis. Apply a profile only when the sensor has enough CPU and memory."
                ),
                .init(
                    "Alert methods",
                    "Configure macOS notifications, menu bar alerts, and an optional Slack webhook independently. Minimum Severity limits each method. Enabling device identifiers for Slack sends those identifiers outside your network."
                ),
                .init(
                    "Updates",
                    "The Home distribution, macOS app, and sensor have independent versions. Settings shows all three. Compatibility uses the sensor API protocol rather than requiring matching version numbers. Check for Updates compares the installed Home distribution with the latest home-v release. Verify downloaded packages and release attestations before installation."
                ),
            ]
        ),
        .init(
            id: "troubleshooting",
            title: "Troubleshooting",
            symbol: "wrench.and.screwdriver",
            summary: "Work from connection state and exact error messages.",
            blocks: [
                .init(
                    "Sensor disconnected",
                    "Confirm the sensor is running, the Mac is on the correct network, and firewalls allow the sensor connection. If Authentication Failed appears, use Repair Pairing and verify the new pairing code rather than bypassing certificate checks."
                ),
                .init(
                    "Dashboard or menu issues",
                    "Open Dashboard restores an existing window. If the menu bar icon is absent, relaunch SquirrelOps Home and check that the app is running in Activity Monitor."
                ),
                .init(
                    "Notifications missing",
                    "Confirm macOS Notifications is enabled in SquirrelOps Settings, the alert meets the selected severity, alerts are not silenced, and macOS Focus or Notification settings are not suppressing banners."
                ),
                .init(
                    "Get useful diagnostics",
                    "Record the installed app version, sensor version, exact timestamp, affected IP or alert ID, and the full visible error. Do not share API keys, pairing credentials, certificates, or Home Assistant tokens."
                ),
            ]
        ),
        .init(
            id: "privacy-security",
            title: "Privacy and Security",
            symbol: "lock.shield",
            summary: "Understand what remains local and what can leave your network.",
            blocks: [
                .init(
                    "Local-first operation",
                    "Core discovery, device history, decoys, and deterministic classification run on systems you control. Pairing uses authenticated encrypted connections and macOS Keychain storage."
                ),
                .init(
                    "Explicit external services",
                    "Slack, OpenRouter, Fireworks.ai, a custom remote AI provider, and externally hosted Home Assistant can transmit data beyond the local sensor. AI decoy naming can include a sanitized sample of observed hostnames. These services are optional and should be configured only with endpoints you trust."
                ),
                .init(
                    "Safe response",
                    "Treat alerts as evidence to investigate, not proof of compromise. Preserve logs before making destructive changes and avoid blocking infrastructure until you understand the effect."
                ),
            ]
        ),
        .init(
            id: "updates-verification",
            title: "Updates and Verification",
            symbol: "checkmark.seal",
            summary: "Verify the package, release record, and publisher before upgrading.",
            blocks: [
                .init(
                    "Verify a release",
                    "Download only from the official SquirrelOps release. Compare the package SHA-256 with the published release metadata and website, verify the GitHub artifact attestation, and confirm the Developer ID signature and notarization."
                ),
                .init(
                    "Homebrew",
                    "A Homebrew Cask install should resolve to the same release URL and SHA-256 as the verified package. If those values differ, stop and investigate before installing."
                ),
            ]
        ),
    ]
}

struct HelpGuideView: View {
    @State private var selection = HelpGuideContent.sections.first?.id

    var body: some View {
        NavigationSplitView {
            List(HelpGuideContent.sections, selection: $selection) { section in
                Label(section.title, systemImage: section.symbol)
                    .tag(section.id)
            }
            .navigationTitle("SquirrelOps Help")
            .navigationSplitViewColumnWidth(min: 210, ideal: 240)
        } detail: {
            if let section = selectedSection {
                ScrollView {
                    VStack(alignment: .leading, spacing: 24) {
                        Label(section.title, systemImage: section.symbol)
                            .font(.largeTitle.bold())
                        Text(section.summary)
                            .font(.title3)
                            .foregroundStyle(.secondary)

                        ForEach(Array(section.blocks.enumerated()), id: \.offset) { _, block in
                            VStack(alignment: .leading, spacing: 8) {
                                Text(block.heading)
                                    .font(.title2.bold())
                                Text(block.body)
                                    .textSelection(.enabled)
                                ForEach(block.bullets, id: \.self) { bullet in
                                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                                        Text("•")
                                        Text(bullet)
                                            .textSelection(.enabled)
                                    }
                                }
                            }
                        }
                    }
                    .frame(maxWidth: 720, alignment: .leading)
                    .padding(32)
                }
            }
        }
    }

    private var selectedSection: HelpGuideSection? {
        HelpGuideContent.sections.first(where: { $0.id == selection })
            ?? HelpGuideContent.sections.first
    }
}

struct SquirrelOpsHelpCommands: Commands {
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(replacing: .help) {
            Button("SquirrelOps Home Help") {
                WindowActivationController.present(.help) {
                    openWindow(id: AppWindow.help.rawValue)
                }
            }
            .keyboardShortcut("?", modifiers: .command)
        }
    }
}
