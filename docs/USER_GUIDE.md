# SquirrelOps Home User Guide

## What is SquirrelOps Home?

SquirrelOps Home scans the selected IPv4 LAN, maintains a device inventory,
and deploys decoy services. It records decoy interactions and raises alerts
for unexpected activity, recognized credential use, and scan-derived security findings.

**How it works:**

1. A lightweight **sensor** scans your network and builds a device inventory
2. The sensor selects **classic HTTP decoys** from discovered ports: file-directory, dev-server, and Home Assistant-style presentations
3. **Squirrel Scouts** probe real devices to build fake hosts with one service decoy per observed port, a shared virtual IP, and an editable hostname. Their HTTP samples and banners provide partial service emulation.
4. Unexpected decoy activity raises a High alert and is retained as forensic evidence. Protocol-defined automatic printer discovery is logged without an intrusion alert. Operator tests and legitimate scanners can also trip a decoy.
5. Scans refresh the device inventory and flag risky services and ambiguous ARP ownership. Passive DHCP collection and automatic connection-baseline learning are not active in this runtime.

**What stays local:** Inventory, alerts, and decoy evidence use local SQLite.
Configuration uses local YAML and an encrypted secret store; the app keeps
pairing keys in macOS Keychain. Core operation requires no cloud service.
Cloud AI, Slack, and manually configured APNs relay delivery are optional;
update checks contact GitHub when requested.

This guide describes [Home 2.1.1](https://github.com/rocketweb/squirrelops-home/releases/tag/home-v2.1.1),
published on October 3, 2026, with macOS app 2.1.0 and sensor 2.1.1. Use the
attested release document for package verification and installation. The
[publication-readiness record](testing/2026-10-01-publication-readiness.md) and
[documentation claim audit](testing/2026-10-02-documentation-claims.md) retain
their dated evidence and test limits; they are not current publication status.

---

## System Requirements

### Docker on Linux/NAS (publication on hold)

- Docker Engine and Docker Compose v2
- Linux ARM64 or x86_64 development targets; published hardware support and
  real-LAN acceptance remain pending
- Network access: the unprivileged sensor stays on a private bridge; only the
  constrained network-helper sidecar uses host networking with
  `NET_RAW`/`NET_ADMIN`
- Do not use the v1.1.14 installer for a new deployment. A compromised sensor
  would inherit broad authority over the host network.

### macOS Native Sensor

- Apple Silicon (ARM64) Mac
- macOS 14 (Sonoma) or later
- Local network access permission

### macOS App (control plane)

- Apple Silicon (ARM64) Mac
- macOS 14 (Sonoma) or later
- Download from [GitHub Releases](https://github.com/rocketweb/squirrelops-home/releases)

Intel Macs are not supported. This applies to both the app and the native
sensor, including Home 2.1. Linux x86_64 requirements above are separate from
macOS support; Linux publication remains on hold.

---

## Installation

The supported release installation is the signed macOS package.

### Path A: Docker on Linux/NAS

Linux release installation is paused. The source architecture now isolates
host networking and network-administration capabilities in a constrained
network-helper companion; the sensor itself is unprivileged. Publication
remains blocked pending independent review and real-LAN acceptance of that
boundary. Its presence in source does not mean a Linux release is approved.
Existing experimental operators should stop the container when it is not
needed and follow [Release security](RELEASE_SECURITY.md) before upgrading.

### Path B: macOS App and Native Sensor

If you don't have a separate always-on device, install the signed and
notarized `.pkg`. It includes the macOS app, a locked sensor runtime, and the
privileged helper. It runs the sensor as a dedicated system account. macOS
Installer asks for one administrator approval for the complete local package.
The app does not ask for a second approval during setup.

The package verifies that launchd owns a stable sensor process before Installer
finishes. On an upgrade with persisted mimic decoys, conflict-safe network
restoration can continue in that background process after the progress bar
completes. This keeps Installer within macOS's package-script limit instead of
showing "less than a minute" for several minutes and then failing. The app
retries the local sensor every three seconds and connects automatically when
restoration finishes. It shows exact elapsed time instead of inventing a
remaining-time estimate for network conflict checks.

Download the versioned `.pkg` and its checksum from a pinned release, then
verify both the checksum and Apple signature before opening it:

```bash
shasum -a 256 -c SquirrelOpsHome-X.Y.Z.pkg.sha256
pkgutil --check-signature SquirrelOpsHome-X.Y.Z.pkg
spctl --assess --type install --verbose=2 SquirrelOpsHome-X.Y.Z.pkg
open SquirrelOpsHome-X.Y.Z.pkg
```

For current immutable Home releases, first download and attest
`RELEASE-VERIFICATION.md`, then use the commands in that canonical asset. The
README includes a [verified Home 2.1.1 example](../README.md#macos-app-and-sensor).
GitHub's release description is editable and is only a pointer. The legacy
standalone `install-macos.sh` release asset is not supported because a
standalone copy cannot carry the locked source project it installs.

The package will:

1. Verify its signed payload through macOS Installer
2. Install the app in `/Applications`
3. Install the locked sensor under `/Library/SquirrelOps/sensor`
4. Create the `_squirrelops` service account and private data directories
5. Install and start the sensor and privileged helper services

On first launch, choose **Build Local Sensor**. The app detects the packaged
sensor and enrolls automatically. No setup key or command-line step is needed
during normal setup.

An explicit ad-hoc local-test package is different from a release. Its signing
identity changes on each rebuild. Each test package therefore uses a new,
isolated Keychain namespace and enrolls again instead of asking repeatedly for
access to private keys created by an earlier build. This isolation does not
weaken the stable Keychain access policy used by signed releases.

### Privileged Helper (required for macOS)

On macOS, ARP network scanning, virtual IP aliases, and port forwarding require root privileges. Rather than running the entire sensor as root, these operations are handled by a lightweight privileged helper daemon (`com.squirrelops.helper`) that runs in the background.

**If you install via the .pkg installer (recommended):** The helper is bundled
inside the signed macOS app and installed by the package. It persists across
reboots. Source-checkout development installs do not have privileged helper
access unless the helper is built and installed separately.

**Helper file locations:**

| Item | Path |
|------|------|
| Binary | `/Library/PrivilegedHelperTools/com.squirrelops.helper` |
| Launchd plist | `/Library/LaunchDaemons/com.squirrelops.helper.plist` |
| Socket | `/var/run/squirrelops-helper.sock` |
| Logs | `/var/log/com.squirrelops.helper.log` |

### Path C: macOS App for a Remote Sensor

For a sensor already running on another device, choose the remote connection
flow in the macOS app. Choosing that flow does not install services or request
administrator approval. The supported `.pkg` itself includes local services;
a source-built app can be used separately (see [Development](DEVELOPMENT.md)).
On first launch:

1. Choose **Connect to Another Sensor**
2. Select the discovered sensor
3. Enter its one-time setup key

---

## Initial Setup

### Pairing Your Sensor

Every sensor must be paired with the macOS app before use. Pairing establishes
a mutual TLS connection so all communication is encrypted and authenticated.
You only need to do this once per sensor.

**Local packaged sensor:**

1. Open the app and choose **Build Local Sensor**
2. The app detects the sensor on localhost
3. The signed app creates its private key in macOS Keychain and requests a
   client certificate through the packaged helper
4. The app proves possession of that key over mutual TLS
5. The sensor activates the pairing and the dashboard opens

This flow does not expose or copy a setup key. The app, sensor, and root helper
remain separate processes with narrow permissions.

**Remote sensor:**

1. Open the app and choose **Connect to Another Sensor**
2. The app discovers sensors via mDNS
3. Select a sensor and enter its one-time setup key
4. The app and sensor exchange TLS certificates
5. The setup key is invalidated and the authenticated connection opens

### Finding Your Setup Key

Remote pairing and local recovery use a 20-character, 100-bit setup key. The
key expires after **10 minutes** or after successful use. Five failed proofs
close that pairing session without rotating the key, which prevents an
unauthenticated device from forcing repeated key changes.

**Docker sensor (Path A):**

The setup key appears in the container logs as a large banner. View it with:

```bash
docker compose -f /opt/squirrelops/docker-compose.yml logs | grep "Setup Key"
```

Or view the full banner by scrolling through recent logs:

```bash
docker compose -f /opt/squirrelops/docker-compose.yml logs --tail 50
```

**Packaged macOS sensor (Path B):**

You do not need a setup key for normal packaged setup. If automatic enrollment
cannot finish, choose **Use Setup Key** in the app and retrieve the recovery
key with the administrator-only CLI. The key is stored mode `0600` inside the
private sensor data directory, never in `/tmp`:

```bash
sudo -u _squirrelops \
  /Library/SquirrelOps/sensor/python/bin/python3 \
  -m squirrelops_home_sensor \
  --config /Library/SquirrelOps/sensor/config.yaml \
  --show-pairing-code
```

If the key has expired, restart the sensor to generate a new one. For Docker,
use `docker compose restart`. For packaged macOS, use
`sudo launchctl kickstart -k system/com.squirrelops.sensor`.

After successful pairing, the app stores the sensor's TLS certificate in your macOS Keychain. All subsequent connections are authenticated automatically.

### Help Menu

Choose **Help > SquirrelOps Home Help** to open the guide at its current topic.
Every guide topic also appears directly in the Help menu, including Devices and
Trust, Alerts and Notifications, Decoys, Squirrel Scouts, Settings,
Troubleshooting, Privacy and Security, and Updates and Verification.

### Pairing and Local Trust Configuration

Packaged production enables automatic enrollment with this setting:

```yaml
pairing:
  local_enrollment_enabled: true
```

The app authenticates to the root helper through a macOS XPC Mach service that
requires the SquirrelOps app identifier, release Team ID, and current console
user. The app also verifies the helper's SquirrelOps identifier, release Team
ID, and Apple signing identity before it sends the request. The helper forwards
only a bounded certificate request to a sensor Unix socket that accepts root.
The sensor creates a short-lived pending pairing, then activates it only after
the app presents the matching certificate over mutual TLS. The app private key
never leaves Keychain.

An explicitly enabled local-test package is bound to the exact code hash of
the root-owned app installed by that package, and the app binds to the exact
code hash of the root-owned helper. It does not accept another ad-hoc app or
helper with the same bundle identifier. Normal releases continue to require
the SquirrelOps Developer ID signatures.

Production still does not start the older local setup-key socket. Peer
credentials identify the process that connected, but cannot prove which
process later uses a passed file descriptor. That socket remains only as an
explicit source-development escape hatch:

```yaml
pairing:
  socket_path: null
  allow_unsigned_local: false
```

Set `allow_unsigned_local: true` only for source development. It permits any
process running as the logged-in user to retrieve the setup key. Remote
pairing continues to use the one-time setup key, isolated challenge sessions,
encrypted certificate exchange, and mutual TLS.

`--no-tls` is also development-only. It always forces the API to bind to loopback, and non-TLS bearer or fingerprint authentication is rejected for non-loopback peers.

### Learning status and current limits

The source includes baseline storage, an anomaly detector, a learning-status
API, and dashboard progress UI with a configurable 48-hour duration. Learning
is disabled by default. The production startup and scan loop do not collect
connection destinations, invoke the baseline collector or anomaly detector,
or automatically start or complete a training period.

Changing the learning-status configuration does not activate behavioral
monitoring. Decoy detection and scan-derived security alerts operate without
waiting for training. Device discovery covers reachable hosts on the selected
IPv4 LAN; sleeping devices, other VLANs, and unidentified devices can be missed.

### Resource Profile Selection

The sensor auto-detects your hardware and recommends a profile. You can change it anytime in Settings.

| Profile | Scan Interval | Host-listener Ceiling | Fake-host Ceiling | Classification | Best For |
|---------|--------------|----------------|-------------------|----------------|----------|
| **Lite** | 15 min | 3 | Disabled | Local signature DB only | Raspberry Pi 3, low-resource devices |
| **Standard** | 5 min | 3 | Up to 5 | Optional configured AI | Raspberry Pi 4, NAS, most setups |
| **Full** | 1 min | 3 | Up to 10 | Optional configured AI | Dedicated server, power users |

The ceiling applies to fake hosts, not service rows. Scouts creates at most one
active fake host per eligible real source device. A fake host with several open
ports has one service-decoy row for each port, so its service count can exceed
the fake-host count. Full mode raises the ceiling; it does not create repeated
copies of the same source merely to reach the profile ceiling.

---

## Dashboard Overview

The macOS app uses a sidebar navigation with six sections: **Dashboard**, **Devices**, **Alerts**, **Decoys**, **Squirrel Scouts**, and **Settings**.

### Dashboard (Home)

The home view shows two things at a glance:

**System Health** — Connection status, resource profile, and key metrics:
- Connection indicator: green (live), yellow (syncing), blue (connecting), gray (disconnected)
- Counts for discovered devices, active decoy deployments, and unread alerts
- A deployment breakdown that keeps fake hosts, their nested service decoys, and host listeners separate
- Sensor version and uptime
- Learning-status progress when explicitly enabled; it does not indicate active baseline collection

**Network Map** — A categorized grid of all discovered devices, grouped by type:
- Infrastructure (routers, switches)
- Computers
- Servers
- Phones
- Media devices
- IoT devices
- Unknown devices

Each device tile shows its name, IP address, and online/offline status.

### Menu Bar

When the app is running, a menu bar icon indicates system status:

| Icon | Meaning |
|------|---------|
| Green dot | Sensor connected, monitoring active, no unread alerts |
| Yellow dot | Sensor connected, unread alerts present |
| Red dot | Active critical or high alert |
| Gray dot | Sensor disconnected or not configured |

---

## Managing Devices

### Device Inventory

The **Devices** tab shows all discovered devices in a searchable, sortable list. You can sort by:
- Name
- IP Address
- Last Seen
- Trust Status

Use the search bar to filter by device name, hostname, IP address, MAC address, or vendor.

### Device Trust Status

Every device has a trust status:

| Status | Meaning |
|--------|---------|
| **Approved** | Recorded as a recognized device; decoy and security findings can still generate alerts |
| **Rejected** | Recorded as unauthorized for operator review; automatic reappearance alerts are not connected to this runtime |
| **Unknown** | No explicit trust decision has been recorded; this differs from an unknown device classification |

### Device Detail View

Click any device to open its detail sheet, which shows:

- **Network Info** — IP address, MAC address, hostname, vendor, device type, model, area, first seen, last seen
- **Open Ports** — List of discovered open ports with service names and risk levels
- **Fingerprint History** — Composite fingerprint records showing MAC addresses, mDNS hostnames, confidence scores, and signal counts. This is how the sensor tracks devices across MAC address changes (e.g., iPhone Private Wi-Fi Address)
- **Actions:**
  - **Approve Device** — Add to known devices list
  - **Reject Device** — Flag as unauthorized
  - **Reset to Unknown** — Remove approval or rejection
  - **Request Verification** — Trigger a fingerprint re-check

### Editing a Device

Click **Edit** in the device detail view to change:
- **Name** — Set a friendly name (e.g., "Sarah's iPhone")
- **Type** — Override the auto-classified device type (computer, phone, tablet, router, smart_home, media, printer, camera, other)
- **Model** — Set a model name (e.g., "iPhone 15 Pro")
- **Area** — Set a location (e.g., "Living Room", "Office")

---

## Decoy Management

### Decoy Grid

The **Decoys** tab shows all deployed deception. Traditional honeypots appear as
individual cards. Service decoys copied from the same source are grouped into
one fake-host card with a shared virtual IP and hostname.

Pull down at the top of the list until **Release to refresh** appears, then
release to reload decoys and their startup status. Short pulls and ordinary
scrolling within the list do not refresh it.
You can also press **Command-R** while Decoys is open, or right-click the list
and choose **Refresh Decoys**. These actions also work when the list is empty.
After both the list and status load successfully, **Updated just now** appears
above the list for three seconds, then fades away without moving the cards.
This confirms the refresh even when nothing has changed. VoiceOver receives a
“Decoys updated” announcement; Reduce Motion disables the fade. Failed refreshes
show an error instead, and background updates do not show the confirmation.
The message area appears only for startup progress or useful diagnostic notes;
routine active, stopped, and disabled states do not need a permanent banner.

With macOS **Keyboard navigation** enabled, use Tab and Shift-Tab to move
between controls. Space on **View Details** opens the decoy sheet; Escape
closes it and returns focus to the link. If an already-open window still skips
buttons after changing the macOS setting, reopen the app. VoiceOver names
detail links by service and address, and enable switches by the fake host or
listener they control.

- Decoy name and type icon
- Bind address and advertised service ports
- Status badge (Active, Degraded, Stopped)
- One fake-host enable/disable control
- Connection count and credential trip count

**Decoy types:**

| Type | Icon | Description |
|------|------|-------------|
| Dev Server | `</>` | Python HTTP server with a static React-style page, `/api/health`, and `/.env`; Express-style headers, no Express, Next.js, or Flask runtime |
| Home Assistant | House | Static HTTP login form and fixed authentication-error routes; no running Home Assistant instance |
| File Share | Folder | HTTP directory listing with an nginx-style banner, `passwords.txt`, and `/.ssh/id_rsa`; no SMB or AFP service |
| Mimic | Device-specific | A fake host grouped from one source's observed ports, HTTP samples, banners, local TLS identity, and mDNS records; partial protocol emulation |
| Studio Build Mac | Desktop Mac | Real OpenSSH/SFTP and Samba in a disposable Linux guest with macOS-shaped content, plus synthetic model and MCP APIs in the sensor |

Classic decoys are selected from observed service categories: dev-server ports,
Home Assistant port 8123, and SMB/AFP ports select their corresponding HTTP
presentations. If none matches, a file-directory decoy is the fallback. The
sensor avoids duplicate classic decoy types and respects stopped rows; it
can emulate a category that already exists on a real device. Mimics and Studio
appear alongside classic listeners in the Decoys grid.

### Studio Build Mac

With the required macOS 2.1 runtime, guest artifacts, profile, and helper,
SquirrelOps can deploy one deep decoy named `studio-mini.local`. Its Linux
guest presents macOS-shaped files and commands for a synthetic FieldKit iOS
build environment. Detailed OS fingerprinting can reveal the underlying Linux guest.

- OpenSSH provides the `buildbot` shell and SFTP access.
- Samba provides writable `Builds`, `Engineering`, and `Time Machine Backups`
  shares using Apple's SMB extensions.
- Synthetic Ollama, OpenAI-compatible, and MCP endpoints expose the same project,
  runbooks, model setup, build history, and synthetic credentials.
- Shell history, Git metadata, Fastlane logs, Cursor, Claude, and Codex files
  all come from the same persona and remain stable across sensor restarts.

The model endpoints do not run inference, and MCP tools return synthetic
results without executing commands or contacting real infrastructure.
Samba advertises Apple's Time Machine extensions, but a complete Time Machine
backup and restore has not been verified. Opaque SSH/SMB relays record
connections and relay outcomes; they do not detect login success, credential
use, shell commands, or individual SMB reads and writes.

SSH and SMB run inside a fresh memory-only guest. It has no network adapter,
host folders, clipboard, disk image, Keychain access, camera, microphone, or
graphics device. The guest disappears when the deep decoy stops. Files a
visitor writes stay in guest memory and are lost with that guest.

The five service cards are grouped under one host and share one lifecycle
control. The hostname and persona are release-managed so the surfaces cannot
drift apart. If the signed runtime, architecture-matched guest, packet-filter
isolation, virtual address, or Bonjour records cannot be established, the host
is shown as **Degraded** and its public ports remain closed.

The agent-facing APIs keep a source-specific narrative. Basic discovery stays
ordinary. Requests for credentials, model tools, build runbooks, or deployment
details reveal progressively deeper parts of the same synthetic world. The
sensor never sends a visitor to a real repository, service, customer, or
deployment.

### Safely test the Studio Build Mac

If Studio has no service cards, a **Studio Build Mac** notice at the top of
Decoys shows startup progress or an actionable diagnostic reason. Normal stopped
and disabled states stay quiet. Pull down on the list or press **Command-R** to
reload that evidence; refreshing does not bypass startup checks or restart the guest. An enabled
host whose startup failed is retried on a later network scan, no more often
than once per minute. An intentionally stopped host stays stopped.

Restarting or upgrading the sensor preserves the Studio host's saved state.
Its five services do not count against the separate classic host-listener
limit. Changing that limit must not stop Studio or turn its SSH/SMB services
into HTTP listeners.

An earlier 2.1 test build could incorrectly mark Studio services stopped during
startup. The ownership fix prevents this but does not automatically enable
previously stopped hosts. If your test installation was affected, keep it
stopped until its saved state and backup have been reviewed. Do not bulk-enable
stopped rows or change firewall rules to work around this issue.

OpenAI-compatible chat supports `stream: true` with SSE. Ollama chat streams
NDJSON by default; use `stream: false` for one JSON response. Streaming and
non-streaming replies describe the same synthetic workspace, and one request
still produces one connection event.

Ordinary HTTP File Share decoys provide parseable, unencrypted RSA key bait.
Those keys are not authorized on the sensor Mac or any real service. On restart
or upgrade, a file share replaces invalid legacy key bait for serving while
retaining the original credential rows and trip history. Downloading a key is
recorded as a connection, not proof that the key was successfully used elsewhere.

Only run these tests against a SquirrelOps decoy you own or are authorized to
test. Use the virtual IP shown on the Studio Build Mac card. Do not substitute
the sensor Mac's normal address, another household device, or a public target.
Run the network tests from a second device on the same LAN. Host-local traffic
on the sensor Mac does not exercise the proxy ARP and packet-filter ingress
path.

The examples below use an environment variable so the target remains visible
in every command:

```bash
DECOY_IP=192.168.1.203
```

Replace the example address with the address shown in the app.

#### 1. Confirm the route and advertised ports from Linux

```bash
ip route get "$DECOY_IP"
ip neigh show "$DECOY_IP"

IFACE=$(ip route get "$DECOY_IP" | awk '/dev/ {for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}')
printf 'LAN interface: %s\n' "$IFACE"
sudo arping -I "$IFACE" -c 3 "$DECOY_IP"

nc -w 3 -vz "$DECOY_IP" 22
nc -w 3 -vz "$DECOY_IP" 445
nmap -Pn -sT -sV -T3 --reason -p 22,445,1234,8765,11434 "$DECOY_IP"
```

`ip neigh` should show a MAC address instead of `INCOMPLETE` or `FAILED`.
OpenSSH should answer on port 22 and Samba on port 445. The version scan may
make several TCP connections, and every accepted connection should increase
the corresponding counter in **Decoys > Studio Build Mac**.

On another Mac, use these equivalents:

```bash
route -n get "$DECOY_IP"
arp -n "$DECOY_IP"
nc -G 3 -vz "$DECOY_IP" 22
nc -G 3 -vz "$DECOY_IP" 445
nmap -Pn -sT -sV -T3 --reason -p 22,445,1234,8765,11434 "$DECOY_IP"
```

#### 2. Exercise real SSH

First verify negotiation without authenticating:

```bash
ssh -vvv -o ConnectTimeout=5 \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  "buildbot@$DECOY_IP"
```

Reaching a password prompt proves that TCP, OpenSSH negotiation, key exchange,
and the guest relay are working. Press Control-C if you only want a connection
test.

For an authorized authenticated test, retrieve the install-specific synthetic
password on the sensor Mac. This query reads only the SquirrelOps database and
does not reveal a real account credential:

```bash
sudo -u _squirrelops /usr/bin/sqlite3 -readonly \
  /Library/SquirrelOps/sensor/data/squirrelops.db \
  "SELECT credential_value FROM planted_credentials WHERE planted_location='SSH buildbot login' ORDER BY id DESC LIMIT 1;"
```

Then connect from the second device and enter that synthetic password at the
prompt:

```bash
TEST_KNOWN_HOSTS=$(mktemp)
ssh -o UserKnownHostsFile="$TEST_KNOWN_HOSTS" \
  -o StrictHostKeyChecking=accept-new \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  "buildbot@$DECOY_IP"
```

Inside the synthetic shell, inspect the coherent persona:

```bash
sw_vers
id
hostname
ls -la /Users/buildbot
find /Users/buildbot -maxdepth 3 -type f | sort | head -50
cat /Users/buildbot/Projects/fieldkit-ios/README.md
```

The guest has no network device or access to the sensor Mac's files. Everything
under `/Users/buildbot` is synthetic and disappears when the deep decoy stops.

#### 3. Exercise SFTP read and write behavior

Create a harmless local probe file on the second device:

```bash
printf 'SquirrelOps authorized acceptance test\n' > /tmp/squirrelops-acceptance.txt
sftp -o UserKnownHostsFile="$TEST_KNOWN_HOSTS" \
  -o StrictHostKeyChecking=accept-new \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  "buildbot@$DECOY_IP"
```

At the `sftp>` prompt:

```text
get /Users/buildbot/Projects/fieldkit-ios/README.md /tmp/fieldkit-readme.md
put /tmp/squirrelops-acceptance.txt /Users/buildbot/Builds/squirrelops-acceptance.txt
get /Users/buildbot/Builds/squirrelops-acceptance.txt /tmp/squirrelops-roundtrip.txt
rm /Users/buildbot/Builds/squirrelops-acceptance.txt
quit
```

#### 4. Exercise real SMB

Anonymous share discovery confirms Samba negotiation but does not grant share
access:

```bash
smbclient -L "//$DECOY_IP" -N -m SMB3
```

Authenticate to the synthetic Engineering share with user `buildbot`. Enter
the same install-specific synthetic password when prompted:

```bash
smbclient "//$DECOY_IP/Engineering" -U buildbot -m SMB3
```

At the `smb: \\>` prompt:

```text
ls
cd fieldkit-ios
get README.md /tmp/fieldkit-smb-readme.md
put /tmp/squirrelops-acceptance.txt squirrelops-acceptance.txt
get squirrelops-acceptance.txt /tmp/squirrelops-smb-roundtrip.txt
del squirrelops-acceptance.txt
quit
```

These writes occur only in the memory-only synthetic guest.

#### 5. Exercise the agent bait and a credential trip

Basic discovery should return internally consistent synthetic model and build
data:

```bash
curl --max-time 5 --fail-with-body \
  "http://$DECOY_IP:1234/v1/models" | python3 -m json.tool

curl --max-time 5 --fail-with-body \
  "http://$DECOY_IP:11434/api/tags" | python3 -m json.tool

curl --max-time 5 --fail-with-body \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_secrets","arguments":{"query":"OPENAI_API_KEY"}}}' \
  "http://$DECOY_IP:8765/mcp" | python3 -m json.tool
```

The MCP response reveals a synthetic API key. To verify the Critical
Credential Trip path without writing the key into shell history, read it into a
temporary variable and submit it back to the decoy:

```bash
read -rsp 'Paste the synthetic API key: ' DECOY_API_KEY; printf '\n'
curl --max-time 5 --fail-with-body \
  -H "Authorization: Bearer $DECOY_API_KEY" \
  "http://$DECOY_IP:1234/v1/models" | python3 -m json.tool
unset DECOY_API_KEY
```

#### 6. Verify evidence in SquirrelOps

Expected results:

1. **Decoys > Studio Build Mac** shows increasing per-service connection
   counters for SSH, SMB, Inference, Ollama, and MCP.
2. The first connection from the test device creates one High Decoy Activity
   alert.
3. Further connections from the same source update that active alert. The
   prompt and alert row show the total and a per-service breakdown such as
   `10 connections · SSH 4 · SMB 6`.
4. Opening the alert shows first and last seen times plus the 50 most recent
   connection records. Every connection remains in the per-decoy forensic log,
   even when the active alert is folded.
5. Touching two or more decoy services promotes the alert to Port Scan
   Detected.
6. Submitting the synthetic API key produces a separate Critical Credential
   Trip and increments the credential trip counter.
7. **Clear** acknowledges the current active alert. The next connection then
   creates a new alert. **History** shows previously acknowledged alerts.

SSH and SMB are opaque encrypted relays. Successful SSH or SMB authentication
creates connection evidence, but it cannot produce a Credential Trip because
the sensor does not inspect encrypted protocol contents. Use the agent API test
above to verify the explicit credential-detection path.

New SSH/SMB records in **Recent Connections** also show whether the guest was
connected, was at capacity, failed to connect, or timed out. A rejected attempt
still increments the counter and triggers or updates the alert: it reached a
decoy even though no guest session opened. Older records have no outcome label
because they did not distinguish admission. **Guest connected** means the
relay opened, not that the visitor authenticated.

The guest supports 16 simultaneous SSH/SMB relays in total. Silent relays close
after five minutes without progress; after one direction closes, the remaining
direction gets 30 seconds without progress. Transfers that keep moving data
continue. A guest-connect timeout stops the unhealthy runtime and leaves the
host degraded; check its status before restarting it.

If ARP resolution fails, confirm both devices are on the same non-isolated LAN.
If ARP resolves but the advertised ports time out, inspect the sensor Mac's
packet-filter forwarding. If the ports answer but counters do not change, the
failure is in guest telemetry. If counters change but no alert appears, check
the active alert, **History**, and notification settings before treating it as
an alert pipeline failure.

### Decoy Status

| Status | Meaning |
|--------|---------|
| **Active** | Running and listening for connections |
| **Degraded** | The intended decoy is not fully operational. For Studio Build Mac this also covers a missing or rejected guest/runtime or incomplete Bonjour publication. |
| **Stopped** | Disabled by user |

For degraded decoys, a **Restart** button appears on the card. Restart, stop,
remove, and hostname changes apply to the whole fake host rather than one
service row.

### Decoy Detail Sheet

Click a decoy card to open its detail sheet:

- **Decoy Info** — Type, address, connection count, credential trip count, failure count, creation date
- **Configuration:** View and edit ordinary decoy-specific configuration values. The Studio Build Mac persona is release-managed and read-only.
- **Connection Log** — Chronological list of all connections to this decoy, showing source IP, request path, timestamp, and whether a credential was used (highlighted with a "CREDENTIAL" label)

---

## Squirrel Scouts

Squirrel Scouts is an advanced reconnaissance and deception subsystem that makes your network defenses significantly more convincing. It's available on **Standard** and **Full** profiles.

### How Squirrel Scouts Works

1. The **Scout Engine** probes open ports on discovered devices to collect bounded HTTP samples, TLS certificate metadata, protocol banners, and mDNS service types
2. **Fake-host templates** group the services observed on one source device under one virtual IP and hostname. Every port remains a separate service-decoy record with its own behavior and evidence.
3. **Virtual IPs** are allocated from verified-free addresses in your subnet and published with proxy ARP. On macOS, the privileged helper independently limits candidates to offsets 200 through 250 from the observed network base. Custom sensor ranges outside that root-enforced pool fail closed.

> **Router setup:** Exclude or reserve the helper-owned `.200`–`.250` pool
> from DHCP before enabling mimic decoys. The helper rejects an address when it
> can see an active occupant, but a sleeping or offline device with a live DHCP
> lease cannot answer the occupancy probe and can later collide.

4. **Port Forwarding** (pfctl on macOS, iptables on Linux) transparently redirects privileged ports to the mimic servers
5. **mDNS Services** are registered under persistent, device-appropriate hostnames. You can edit a fake host's hostname, and the change applies to every service sharing its IP.

The result is a set of grouped fake hosts whose advertised service samples
resemble systems already present on the network. Supported HTTP bait routes
record decoy trips when requested. Critical alerts require recognized credential
submission in a supported request, not merely downloading a bait file.

On macOS, proxy-ARP virtual IPs share the Mac's physical-interface MAC address.
The macOS helper selects a physical Ethernet or Wi-Fi LAN. If a VPN owns the
global default route, it checks physical interfaces in macOS network service
order and verifies a private, directly connected gateway. The sensor uses that
same interface, subnet, address, and gateway for scanning and decoy publication;
it does not use the VPN tunnel's address. Automatic network settings stay
automatic when saved. An explicit interface or subnet that conflicts with the
helper-selected LAN is rejected before publication. This selection does not
disable a VPN, change system routes, or override a VPN's local-network blocking.

A reverse-DNS scan can also report the Mac's real hostname for those addresses.
These are known Layer 2 limitations of this architecture. The fake services are
designed to withstand ordinary service discovery, but this release does not
claim that a virtual IP is indistinguishable from a separate physical device.

### Squirrel Scouts Tab

The **Squirrel Scouts** tab in the sidebar has three sections:

#### Scout Engine

Shows the status of the reconnaissance engine:

- **Profiles** — Total service profiles collected across all devices
- **Fake Hosts** — Currently deployed fake hosts out of the profile ceiling
- **Service Decoys** — Individual per-port decoy records across those hosts
- **Interval** — Time between automated scout cycles
- **Status** — Whether a scout cycle is currently running or idle
- **Last Scout** — Local timestamp of the most recent scout cycle, shown as `YYYY-MM-DD HH:MM:SS`

The **Run Scout** button triggers an immediate scout cycle (useful after adding new devices to your network).

#### Virtual Network

Shows all deployed fake hosts in a card grid. Each card displays:

- **Name:** An ordinary generated hostname, such as `automation.local`, with optional validated AI naming for some new hosts
- **Status badge** — Active, Stopped, or Degraded
- **Virtual IP** — The allocated IP address on your subnet
- **Services** — Every observed port and protocol advertised by the fake host
- **Hits** — Connection count (highlighted in yellow when > 0, meaning something probed the mimic)
- **Category** — Device type being mimicked (Smart Home, Camera, NAS, Media, Printer, Router, Dev Server)
- **Hostname** — The persistent, editable hostname used by all services in the group

Each card has host-level **Remove** and, for stopped hosts, **Restart** buttons.
Editing the hostname updates every service row sharing the virtual IP and
persists across sensor restarts. A hostname can be a bare label such as
`fileserver`, or end in `.local` or `.localdomain`. The suffix is preserved
exactly. Bonjour still advertises the corresponding single label under
`.local`, because mDNS does not advertise the `.localdomain` namespace.

The **Fill Capacity** button deploys one fake host for each eligible source that
is not represented yet, up to the active profile ceiling. It does not create
repeated clones of already represented sources simply to fill every slot.

#### Service Profiles

Lists all collected service fingerprints in a scrollable table:

- **IP:Port** — The device and port that was probed
- **Service name** — Identified service (HTTP, SSH, etc.)
- **Server header** — The HTTP `Server:` header value, if present
- **Protocol version** — SSH/SMTP version strings, if present
- **HTTP status** — Response code from the probe
- **TLS** — Certificate CN if TLS was detected (shown with a lock icon)

### Fake-host credential routes

The mimic system adds synthetic bait files to one observed HTTP service per
host. Without a supported HTTP route, no credential bait is planted. A generic
mimic's SSH banner does not implement SSH negotiation or authentication;
Studio's separate guest provides real SSH/SFTP and SMB.

| Category | Credential Strategy |
|----------|-------------------|
| Smart Home | HA-style token at the generated token's bait-file path |
| NAS / File Share | `passwords.txt` and `/.ssh/id_rsa` bait routes |
| Dev Server | `.env` files with API keys |
| Camera | Password pairs in `passwords.txt`; recognized when submitted through supported authentication requests |
| Generic, Media, Printer, Router | Password pairs in `passwords.txt` on a supported HTTP service |

These are added text-file routes; the runtime does not insert secrets into the
copied source page's login form, camera configuration, or JSON error response.
Classic `.env` detection compares the generated credential value, which is
the whole file; reuse of an individual key from that file is not guaranteed
to be recognized. Use the exact supported bait/request format when testing.

---

## Alerts & Incidents

### Alert Feed

The **Alerts** tab shows stored alerts. Retention defaults to 90 days; active
incidents and their linked alerts are preserved beyond that age. By default,
only **active (undismissed) alerts** are shown. Choose **Actions → Show History**
to include previously dismissed alerts.

All timestamps in the app use local system time in
`YYYY-MM-DD HH:MM:SS` format.

### High and Critical Alert Prompt

New High and Critical alerts open a prompt over the dashboard:

- **Review** closes the prompt, opens the Alerts panel, and leaves the presented
  alerts unread so you can inspect them individually.
- **Clear** acknowledges only the batch represented by the prompt and removes
  it from the unread count. The alert records remain available in the Alerts
  panel and are not deleted from the database.

Several decoy connections from the same source are coalesced into one active
alert instead of creating one alert row per socket. The prompt and alert row
show the total connection count and per-service breakdown. Opening the alert
shows first and last seen times plus a bounded recent-connection timeline.
Every individual connection is still retained in the decoy's forensic log.

**Alert types:**

| Type | Severity | Meaning |
|------|----------|---------|
| Credential Trip | Critical | A supported HTTP decoy recognized submitted planted credentials; guest SSH/SMB login is not inspected |
| Decoy Trip | High | Unexpected decoy activity; automatic printer discovery is retained without an intrusion alert |
| Security Insight | Medium–High | A risky port or service is open on one or more devices (e.g., SSH, VNC, unencrypted admin interfaces) |
| ARP Ownership Conflict | High | The scan cannot establish a unique IP/MAC owner |
| Sensor Disconnected | Medium | The Mac app has been disconnected for five minutes; this alert is local to the app |

New-device, MAC-change, and verification events exist in the sensor, but there
is no runtime subscriber turning them into alert-feed rows. Behavioral anomaly,
learning-complete, vendor-advisory, and review-reminder types or standalone
classes are also present without active runtime producers. Rejected-device
reappearance is not an implemented alert type. These definitions are not
promises of automatic notifications.

### Grouped Security Alerts

Security insight alerts are **grouped by issue type** rather than per-device. For example, if four devices on your network have SSH open, you'll see a single alert titled "SSH open on 4 devices" instead of four separate alerts. Each grouped alert includes:

- **Risk description** — an explanation of why this is a security concern
- **Remediation steps** — actionable guidance on how to fix the issue
- **Affected devices list** — every device with the issue, showing name, IP address, port, and MAC address

Grouped alerts update automatically: if a new device appears with the same issue, the existing alert's device count increases and the alert becomes active again (even if previously dismissed). If a device resolves the issue (port closed), it is removed from the group.

Click any grouped alert to open its **Alert Detail View**, which shows the full risk description, remediation guidance, and a table of all affected devices.

### Filtering Alerts

The toolbar provides multiple filtering dimensions:

- **Severity menu**: All, Critical, High, Medium, Low
- **Type menu**: All Types, Decoy Trip (including credential trips), New Device, MAC Changed, Security, System
- **Dates**: Click the calendar button to filter by date range (From/To)
- **Search**: Free-text search across alert titles, source IPs, and alert types
- **Actions → Show History**: Show or hide previously dismissed alerts

All filters combine (AND logic). The menus display the selected filters; a note appears when history is included.

### Alert Detail View

Click any alert in the feed to open a detail sheet showing the full context of the alert:

- **Header** — Severity indicator, title, alert type badge (e.g., "Decoy Activity", "Port Scan Detected", "Credential Accessed"), severity label, and timestamp
- **Source** — IP address, MAC address (if the device was identified), hostname, vendor, and device ID
- **Intrusion Details** — Folded connection count, per-service totals, latest destination port, protocol, first and last seen times, request path (for HTTP-based detections), and detection method
- **Recent Connections** — Up to 50 timestamped service and port entries represented by a folded decoy alert
- **Credential Use** (only for credential trip alerts): Which planted value was recognized in the submitted request and the request path
- **Decoy** — Which decoy was tripped, with name and ID

Click **Done** to close the detail sheet.

### Incidents

Related alerts from the same source are grouped into **incidents**. Click any incident-type alert in the feed to open the incident detail view, which shows:

- Incident ID, severity, and status (Active or Closed)
- Source IP and MAC address
- Time span (first alert to last alert)
- Summary description
- **Child alerts** — Expandable list of all alerts in the incident

Use **Dismiss All** to acknowledge all alerts in an incident at once.

### Exporting Alerts

Choose **Actions → Export…** in the alert feed toolbar to save alerts as JSON:

1. Choose a date range or click **Export All** for the entire retention window
2. Select a save location in the standard macOS save dialog
3. The export file is named `squirrelops-alerts-YYYY-MM-DD.json`

This is useful for preserving alert history beyond the 90-day retention window.

### Dismissing Alerts

There are several ways to dismiss alerts:

- **Dismiss button**: Each active alert has a dismiss button (×) on its right side, available without hovering
- **Context menu** — Right-click any alert and select **Dismiss**
- **Detail view** — Open a grouped alert's detail view and click the **Dismiss** button
- **Bulk dismiss**: Choose **Actions → Dismiss All** to acknowledge all active alerts, including ones hidden by the current filters

Dismissed alerts are hidden from the default feed view but remain accessible via **Actions → Show History**. The unread count badge on the Alerts sidebar item updates automatically.

Dismissing a grouped security alert is like saying "I've seen this, I know about it." If the situation changes — for example, a new device appears with the same risky port — the alert automatically becomes active again so you don't miss the change.

---

## Settings

The Settings tab contains the following configuration sections.

### Appearance

Choose between **System** (follows macOS setting), **Light**, and **Dark** appearance modes. Default is System.

### Resource Profile

Switch between **Lite**, **Standard**, and **Full** profiles. Each profile shows
its scan interval, host-listener ceiling, fake-host ceiling, and classification
method. Changes take effect immediately. Switching from Lite to Standard/Full
enables Squirrel Scouts. The ceiling does not guarantee that many fake hosts;
the available count is limited by eligible, uniquely represented source
devices and verified-free virtual IPs.

### Alert Methods

Configure how alerts are delivered. Each method has an enable/disable toggle and a minimum severity picker (All, Medium+, High+, Critical only):

**macOS Notifications:** Local Notification Center banners and sounds, subject
to macOS permission and Focus settings. The paired app must be running.

APNs sender and relay source is present for manual sensor configuration with
an enabled delivery method, relay URL, relay credentials, and device token.
The app does not register an APNs token, and this repository contains no iPhone
app. APNs delivery is not a ready-to-enable iPhone/Mac feature in Settings.

**Menu Bar Alerts** — The menu bar icon changes color to indicate alert status.

**Slack Webhook** — Posts alert summaries to a Slack channel via an incoming webhook URL.

When Slack is enabled, additional options appear:
- **Webhook URL** — Your Slack incoming webhook URL
- **Minimum Severity** — Which alerts trigger a Slack message
- **Include Device Identifiers** — When enabled, MAC addresses and device IDs are included in Slack messages. A warning reminds you that this data will leave your local network.

### Device Matching (Fingerprint Threshold)

Controls how strictly devices must match their composite fingerprint to be auto-approved when they reconnect with a different MAC address:

| Setting | Threshold | Behavior |
|---------|-----------|----------|
| **Relaxed** | 0.60 | More permissive, with fewer verification-needed events and a higher chance of misidentification |
| **Standard** | 0.75 | Default — balanced between convenience and security |
| **Strict** | 0.90 | More restrictive, requiring a closer fingerprint match for auto-approval |

When a returning device's fingerprint confidence falls between 0.50 and the
threshold, the device manager publishes a verification-needed event instead of
auto-approval. This runtime does not convert that event into an alert-feed row;
review device identity and trust in Devices.

### Credential Decoys

Set the credential filename for new **HTTP File Share** decoys. The default is
`passwords.txt`; examples include `credentials.env` and `secrets.txt`. The sensor
reads this setting at startup, so a saved change applies to newly created HTTP
File Share decoys after a sensor restart. Existing decoys retain their stored
filenames. This setting does not change Studio Build Mac's real SMB shares or
SSH files, which use their own persona content and synthetic credentials.

Synthetic credentials are exposed on supported HTTP decoy routes. Requesting
`/.env` or `/passwords.txt` records ordinary decoy activity. A **Critical**
credential alert requires a supported handler to recognize a planted value
submitted in the request. Banner-only services do not implement authentication;
Studio's opaque SSH/SMB relays do not inspect credential use.

### DNS Canary Status

DNS canaries are not available in this release. The sensor does not plant or
monitor DNS canary hostnames. Legacy `decoys.dns_canaries` settings are ignored
at startup with a warning, and runtime attempts to configure them are rejected.
Credential alerts fire when a planted file or credential endpoint on a decoy is
accessed.

### Optional AI Device Classification and Decoy Naming

This section appears only when the resource profile is **Standard** or **Full**.

Choose **None**, **LM Studio**, **Ollama**, **OpenRouter**,
**Fireworks.ai**, or another OpenAI-compatible endpoint.

- LM Studio defaults to `http://localhost:1234/v1`.
- Ollama defaults to `http://localhost:11434/v1`.
- OpenRouter uses its fixed HTTPS API. Enter a model slug such as
  `provider/model` and your OpenRouter key.
- Fireworks.ai uses its fixed HTTPS API. Enter a model name such as
  `accounts/account/models/model` and your Fireworks key.
- A custom provider requires its OpenAI-compatible base URL.

Cloud keys are sent only to the selected provider's canonical HTTPS endpoint.
Changing providers clears the previous provider's saved key before the new
configuration is activated. Provider changes take effect immediately without
restarting the sensor.

To check the connection:

1. Choose the provider and enter its endpoint and API key, if required. Changes
   save automatically. The checks wait for the current save to finish.
2. Click **Connect and load models**. Choose a model from the searchable
   **Choose model** list, or enter its ID manually. **Refresh models** reloads
   the catalog without generating text. A successful catalog request does not
   prove that the key has generation permission, credits, or access to a model.
3. Click **Test model**. The sensor sends two small synthetic requests using
   the same classification and naming prompts and response parsers used during
   normal operation. The result reports success, elapsed time, or a specific
   connection, authentication, quota, model, or response-format problem.

These checks run on the **sensor**, not the dashboard Mac. `localhost` therefore
means the sensor's computer. Tests never use real device data or create decoys.
Cloud providers may charge for the two generation requests; local providers may
load the selected model into memory. Opening Settings does not run either check.
Each test request caps output at 512 tokens, and the whole check has a 50-second
deadline. A slow model load or a reasoning model that exhausts that budget can
fail this bounded test even if a longer request could succeed.

LM Studio, Ollama, OpenRouter, and compatible custom servers use their models
endpoint. LM Studio's catalog depends on its just-in-time loading setting.
Fireworks uses its account-scoped catalog: the account in an entered
`accounts/account/models/model` ID, or `fireworks` if none is provided. A listed
Fireworks model may still require a deployment; enter a deployment-specific ID
manually when needed. Unsupported discovery does not prevent manual entry or
testing. Known non-text model types are excluded when the provider identifies
them; unknown capabilities remain selectable and require testing.

Changing the provider, endpoint, key, or model clears the previous test result.
Results are temporary and describe only the configuration tested at that time.
Both the app and sensor must include the AI setup controls; an older sensor
cannot serve the new checks.

The sensor uses AI device classification only when the local signature database
cannot fully classify a newly discovered device. It waits until the scan's port
and discovery enrichment is complete, then the prompt can include the device's
OUI prefix, sanitized DNS and mDNS names, open TCP port numbers, detected
service names, mDNS service types, and available UPnP name,
manufacturer, model, and server metadata. It does not include fingerprint
hashes, connection destinations, the device's full MAC address, or any device
IP address. An accepted response supplies manufacturer, device type, model,
and confidence. AI does not analyze alerts, inspect packet contents, choose
decoy targets, or take autonomous action.

The classifier can accept DHCP option codes when supplied, but the current
scan loop does not collect them.

Fake hosts use simple home and business names such as `files`, `media`,
`office`, `backup`, `printer`, and `automation`. SquirrelOps does not add a
generic numeric or hexadecimal host identifier unless several real hostnames
show that the network uses terminal identifiers. When AI is configured, the
sensor sends a bounded, sanitized sample of observed real-device hostnames and
asks for pattern-aware suggestions for half of a new deployment batch, rounded up.
Suggestions are validated locally, cannot reuse real or sensor hostnames, and
never rename an existing fake host. A failed or invalid suggestion falls back
to deterministic naming without interrupting deployment.

### Sensor

Displays sensor information:
- Sensor name and URL
- Software version
- Sensor ID

### Updates

Shows the installed Home distribution and sensor versions with a **Check for Updates** button. The app queries published `home-v*` releases on GitHub only when you click the button. Update checks and installations are never automatic.

---

## Troubleshooting

### Sensor Not Discovered During Pairing

**Symptoms:** The macOS app doesn't find the sensor on the network.

**Possible causes:**
- The sensor hasn't finished starting — wait 30 seconds after running the install script, then check logs
- The Mac and sensor are on different subnets/VLANs — they must be on the same Layer 2 network for mDNS discovery
- mDNS traffic is being blocked — check your router's firewall settings for multicast DNS (port 5353)

**Docker sensor:**
```bash
docker compose -f /opt/squirrelops/docker-compose.yml logs -f
```

**macOS sensor:**
```bash
tail -f /Library/SquirrelOps/sensor/logs/squirrelops-sensor.log
```

### Can't Find the Setup Key

**Symptoms:** The app is asking for a setup key but you don't know where to find it.

Normal local package setup enrolls automatically and does not ask for a setup
key. The key is needed for a remote sensor or when you choose **Use Setup Key**
after automatic local enrollment cannot finish. See
[Finding Your Setup Key](#finding-your-setup-key) for detailed instructions.
The quickest methods are:

- **Docker:** `docker compose -f /opt/squirrelops/docker-compose.yml logs | grep "Setup Key"`
- **Packaged macOS:** use the packaged CLI command in
  [Finding Your Setup Key](#finding-your-setup-key)

If neither works, the sensor may not be running. Check the sensor status first.

### Setup Key Expired

**Symptoms:** The code was rejected even though you entered it correctly.

The setup key expires after 10 minutes or successful use. Restart the sensor to generate a fresh key:

- **Docker:** `docker compose -f /opt/squirrelops/docker-compose.yml restart`
- **macOS:** `sudo launchctl kickstart -k system/com.squirrelops.sensor`

Then retrieve the new code using the methods above.

### App Shows "Disconnected" (Gray Dot)

**Symptoms:** Menu bar icon is gray, dashboard shows "Disconnected."

**Possible causes:**
- The sensor process has stopped
- Network connectivity between the Mac and sensor device is broken
- The sensor crashed and hasn't restarted
- A decoy-heavy packaged upgrade is still restoring persisted virtual IPs and
  listeners under launchd

**For Docker sensor:** Check if the container is running:
```bash
docker compose -f /opt/squirrelops/docker-compose.yml ps
```

If it's stopped, start it:
```bash
docker compose -f /opt/squirrelops/docker-compose.yml up -d
```

**For macOS sensor:** Check if the service is loaded:
```bash
sudo launchctl print system/com.squirrelops.sensor
```

If it is not running, restart it:
```bash
sudo launchctl kickstart -k system/com.squirrelops.sensor
```

If the service is running immediately after an upgrade, allow restoration to
finish. Standard and Full profiles can take several minutes because every
persisted virtual IP is quarantined, checked for a physical-network conflict,
and restored before its listener is exposed. Do not rerun Installer while that
same stable sensor process is still initializing. Build Local Sensor keeps
checking automatically for 20 minutes and shows how long it has waited. The
Sensor Not Responding screen appears only after that recovery window expires.

The app reconnects automatically on a 30-second interval. After five minutes
of disconnection, it adds a Medium-severity **Sensor Disconnected** alert to
the local app view; this is not a sensor-persisted alert.

### No Alerts Appearing

**Symptoms:** Sensor is connected but no alerts show up.

**Possible causes:**
- **Unsupported alert expectation:** Automatic behavioral, new-device, and rejected-device-reappearance alerts are not connected to the runtime. Check Devices for inventory changes.
- **Decoys haven't been deployed** — Check the Decoys tab. If no decoys are deployed, the sensor may not have found suitable ports or addresses.

### Decoy Shows "Degraded"

**Symptoms:** A decoy card shows a "Degraded" status badge.

**What happened:** The service could not be fully started or published. Causes
include unavailable networking, helper failure, missing Studio artifacts,
packet-filter checks, or Bonjour registration failure. A Degraded badge does
not establish that a decoy crashed three times.

**What to do:**
1. Click the **Restart** button on the decoy card
2. If it degrades again, check the sensor logs for the underlying error
3. Classic listeners saved as degraded are retried after scans; enabled Studio
   startup failures have their separate scan-driven retry. Classic periodic
   crash checks and the standalone 30-minute recovery method are not scheduled
   by this runtime.

### Sensor Shows 0 Devices (macOS)

**Symptoms:** Dashboard shows 0 devices, sensor logs show no ARP scan results.

**Cause:** The privileged helper (`com.squirrelops.helper`) isn't running. On macOS, ARP scanning requires the helper daemon for raw socket access.

**What to do:**
1. Reinstall the signed SquirrelOps Home package if the helper is missing
2. Verify the helper is running: `sudo launchctl print system/com.squirrelops.helper`
3. Check helper logs: `tail -f /var/log/com.squirrelops.helper.log`
4. Restart the sensor after the helper is running

### Mimic Decoys Not Deploying

**Symptoms:** The Virtual Network section in Squirrel Scouts is empty, or Fill Capacity returns an error.

**Possible causes:**
- **Helper not running (macOS):** Fill Capacity returns a "Privileged helper is not running" error. The helper is required for creating isolated virtual IPs. Reinstall the signed package, or see the [helper documentation](#privileged-helper-required-for-macos) above.
- **Scouts haven't run yet** — Click **Run Scout** to refresh service profiles and fill available mimic capacity
- **Profile is Lite** — Mimic decoys require Standard or Full profile. Switch profiles in Settings.
- **No suitable candidates** — The scout engine needs eligible real devices with observed service ports. It creates one fake host per source, so a Full profile can legitimately have fewer than 10 fake hosts.
- **Virtual IPs exhausted** — On macOS, the privileged helper always enforces offsets 200 through 250 from the observed network base. Every address is checked on the physical LAN before use; real devices are skipped, so fewer slots may be available.

**macOS 27 recovery testing:** If a mimic briefly appears and then disappears,
logs reporting the Mac's own Ethernet MAC as an IP conflict can indicate the
Python interface-identity redaction issue. The recovery build reads identities
through the authenticated helper. A `decoy_hosts.bind_address` uniqueness error
is separate: stopped Studio hosts still reserve their addresses, and new mimics
must skip those reservations. Do not delete the database or history to work
around either issue. Classic listeners also need to bind to the selected LAN,
not a VPN's default-route address. See the
[September 25 recovery report](testing/2026-09-25-macos27-decoy-recovery.md)
for the candidate's exact verification status and remaining acceptance steps.

### Settings Won't Save

**Symptoms:** Error messages appear when changing settings.

**Possible causes:**
- The sensor is disconnected — changes are sent to the sensor via the API and require an active connection
- Check the sensor logs for API errors

### Cloud AI Classification or Decoy Naming Not Working

**Symptoms:** Devices show as "Unknown Device" even in Standard mode.

**Possible causes:**
- No API key configured — go to Settings > Optional AI Device Classification and Decoy Naming and enter your API key
- Invalid API key — the sensor falls back silently to the local signature database
- No model configured — enter the provider's exact model identifier
- The cloud AI endpoint is unreachable — check your internet connection

The sensor always falls back to local classification and deterministic decoy names if AI is unavailable. No alert is generated for provider failures.

### Recovering Legacy macOS Network State

An upgrade from a pre-2.0 installation stops if it cannot prove that every old
SquirrelOps loopback alias, proxy-ARP publication, and PF rule is gone. This is
intentional: the installer will not treat the sensor-writable legacy database
as trusted root instructions.

First inspect the recorded legacy rows and the live state. These commands do
not change the system:

```bash
sudo sqlite3 -separator ' | ' \
  /Library/SquirrelOps/sensor/data/squirrelops.db \
  'SELECT DISTINCT ip_address, interface FROM virtual_ips WHERE released_at IS NULL;'
sudo /sbin/pfctl -a com.apple/squirrelops -sr
sudo /sbin/pfctl -a com.apple/squirrelops -sn
/sbin/ifconfig lo0 | /usr/bin/awk '$1 == "inet" { print }'
/usr/sbin/arp -an | /usr/bin/grep -i published
```

Review every reported IP and interface. Do not remove an address assigned to a
physical interface, and do not delete a published ARP entry owned by another
application. If the database is missing or corrupt, or ownership is unclear,
stop and request support rather than guessing.

For each IP that you have independently confirmed is a stale SquirrelOps
virtual IP, run the following with its exact recorded interface:

```bash
IP=192.168.1.200
INTERFACE=en0
sudo /usr/sbin/arp -d "$IP" pub ifscope "$INTERFACE"
sudo /sbin/ifconfig lo0 inet "$IP" -alias
```

After every confirmed SquirrelOps alias and proxy entry is absent, clear only
the dedicated SquirrelOps PF anchor and verify the result:

```bash
sudo /sbin/pfctl -a com.apple/squirrelops -F all
sudo /sbin/pfctl -a com.apple/squirrelops -sr
sudo /sbin/pfctl -a com.apple/squirrelops -sn
/sbin/ifconfig lo0 | /usr/bin/awk '$1 == "inet" { print }'
/usr/sbin/arp -an | /usr/bin/grep -i published || true
```

The two PF queries should print no rules, the stale `/32` alias should be gone
from `lo0`, and no stale SquirrelOps entry should be marked `published`. Then
run the 2.0 package again.

### Uninstalling

**Docker sensor:**
```bash
docker compose -f /opt/squirrelops/docker-compose.yml down -v
sudo rm -rf /opt/squirrelops
```

**macOS sensor:**
```bash
sudo bash /Library/SquirrelOps/sensor/uninstall.sh
```

The uninstaller stops the services and asks before deleting the private sensor
data. It also removes installer-created backups that can contain pairing
material.

---

## Privacy & Security

### What Stays on Your Network

Device inventory, alert history, scan results, and decoy evidence use local
SQLite. Non-secret configuration uses local YAML, configuration credentials
use an encrypted secret store, and the app's pairing keys use macOS Keychain.
After pairing, app management traffic uses mutual TLS over your local network.

### What Can Leave Your Network (Only If You Enable It)

| Feature | Data Sent | Destination | How to Disable |
|---------|-----------|-------------|----------------|
| **Manually configured APNs relay** | Device token, alert title/body, type, and severity | Your configured relay and Apple Push Notification Service | Disable the sensor's `alert_methods.push` or `alert_methods.apns` configuration; token registration is not implemented in the app |
| **Cloud AI Classification and Decoy Naming** | Classification: OUI prefix, sanitized DNS and mDNS names, open port numbers, detected services, mDNS service types, and available UPnP metadata. DHCP option codes are supported if supplied, but are not collected by the current scanner. Naming: a bounded, sanitized hostname sample. No fingerprint hashes, connection destinations, device IPs, full MAC addresses, packet contents, alerts, or credentials. | Your selected cloud or custom AI provider, using your own API key | Choose **None** or switch to Lite |
| **Slack Webhooks** | Alert severity, type, summary, timestamp. Device identifiers only if you enable "Include Device Identifiers." | Your Slack workspace | Toggle off in Settings > Alert Methods |
| **Update Checks** | Standard request metadata, such as your public IP address and HTTP headers | GitHub Releases API | Don't click "Check for Updates" |

With LM Studio or Ollama on the local network, classification and naming data
stay on that network.

### Certificate Pinning

After pairing, the macOS app checks the sensor's TLS certificate against its
saved SHA-256 fingerprint and rejects a substituted certificate. Mutual TLS
also requires each peer to prove possession of its corresponding private key.

### What the Sensor Does NOT Do

- **No passive packet inspection:** The sensor does not capture unrelated devices' traffic. Scout probes read bounded service samples; decoys inspect HTTP requests sent to them. Studio SSH/SMB relays observe connection metadata without parsing those protocols.
- **Decoy forwarding:** Packet-filter rules publish and isolate owned virtual
  decoy addresses. The product does not implement a general device-blocking
  policy. Reserve its address pool and investigate reported IP conflicts.
- **No scanning beyond your network** — The sensor only monitors subnets it has direct Layer 2 adjacency to.
- **No product analytics:** There is no usage-analytics sender. Optional cloud
  classification and alert delivery send the specific data listed above.
- **No auto-updates** — The sensor never updates itself without your explicit confirmation.

### Virtual IP Safety

Virtual IPs used by mimic and Studio Build Mac decoys are:
- Allocated from helper-enforced offsets 200 through 250 from the observed network base on macOS. Reserve that pool outside DHCP; occupancy checks cannot detect sleeping lease holders.
- Excluded from the sensor's own scan loop to prevent false device discoveries
- Scheduled for evacuation if an active real device claims the same IP. The
  affected fake host stops and its alias is withdrawn when cleanup succeeds;
  failed cleanup retains isolation rules rather than authorizing exposure.

On macOS, the virtual IPs are published through proxy ARP and therefore share
the sensor Mac's physical MAC address. The sensor advertises distinct mDNS
services and an editable hostname, but it cannot override every client's
reverse-DNS view. Distinct virtual MAC addresses require a different virtual
Ethernet or VM-style network architecture.

### Port Forwarding Safety

On macOS, the sensor uses pfctl packet filter rules (loaded into a dedicated `com.apple/squirrelops` anchor) to redirect privileged ports to mimic servers. These rules:
- Only affect traffic destined for virtual IPs (never your real devices)
- Are removed during orderly sensor shutdown when cleanup succeeds; failed alias removal retains isolation rules for safety
- Do not modify the system's `pf.conf` or interfere with existing firewall rules

### Credential Safety

The `planted_credentials` table contains generated deception bait. Separately,
operator-supplied Home Assistant tokens, AI keys, Slack webhook URLs, and APNs
delivery secrets are stored in the encrypted secret store and redacted from
configuration responses. Pairing and TLS keys are also retained locally.
Synthetic bait must never be replaced with real service credentials.
