# SquirrelOps Home User Guide

## What is SquirrelOps Home?

SquirrelOps Home is a local-first home network security platform. It passively monitors your network, learns what "normal" looks like, and deploys realistic decoy services (honeypots) that generate zero-false-positive alerts when anything touches them.

**How it works:**

1. A lightweight **sensor** scans your network and builds a device inventory
2. The sensor deploys **decoys** — fake services like file shares, dev servers, and Home Assistant instances — that no legitimate device should ever contact
3. **Squirrel Scouts** probe real devices to build mimic decoys that clone their exact responses, deployed across virtual IPs with spoofed mDNS hostnames
4. When something connects to a decoy, you get an alert. No tuning, no false positives.
5. The sensor also monitors for **new devices** joining your network and **behavioral anomalies** after a 48-hour learning period

**What stays local:** All data is stored in a local SQLite database on the sensor. No telemetry. No cloud dependency. The only things that leave your network are the ones you explicitly enable (push notifications, cloud LLM classification, Slack webhooks, update checks).

---

## System Requirements

### Docker on Linux/NAS (recommended for always-on monitoring)

- Docker Engine and Docker Compose v2
- Linux ARM64 (Raspberry Pi 3/4/5) or x86_64 (NAS, general Linux)
- Network access: the container runs with host networking and `NET_RAW`/`NET_ADMIN` capabilities

### macOS Native Sensor

- macOS 14 (Sonoma) or later
- Python 3.11+
- Local network access permission

### macOS App (control plane)

- macOS 14 (Sonoma) or later
- Download from [GitHub Releases](https://github.com/rocketweb/squirrelops-home/releases)

---

## Installation

There are three installation paths. Choose the one that fits your setup.

### Path A: Docker on Linux/NAS

This is the recommended path if you have an always-on Linux device (Raspberry Pi, NAS, server). The sensor runs as a Docker container with host networking.

```bash
curl -fsSL https://get.squirrelops.io/install.sh | sudo bash
```

The script will:
1. Verify Docker and Docker Compose v2 are installed
2. Detect your architecture (ARM64 or x86_64)
3. Create `/opt/squirrelops/` with a `docker-compose.yml`
4. Pull `ghcr.io/rocketweb/squirrelops-sensor:latest`
5. Start the sensor container

After installation, view the sensor logs (including your pairing code) with:

```bash
docker compose -f /opt/squirrelops/docker-compose.yml logs -f
```

**Useful commands:**

| Action | Command |
|--------|---------|
| View logs | `docker compose -f /opt/squirrelops/docker-compose.yml logs -f` |
| Stop sensor | `docker compose -f /opt/squirrelops/docker-compose.yml down` |
| Update sensor | Re-run the install script |

### Path B: macOS Native Sensor

If you don't have a separate always-on device, the sensor can run directly on your Mac as a background launchd service.

```bash
curl -fsSL https://get.squirrelops.io/install-macos.sh | bash
```

The script will:
1. Find Python 3.11+ on your system
2. Create `~/.squirrelops/sensor/` with data, config, and log directories
3. Create a Python virtual environment and install the sensor package
4. Generate a default `config.yaml` (Standard profile, 5-minute scan interval, 90-day retention)
5. Install and load a launchd plist at `~/Library/LaunchAgents/com.squirrelops.sensor.plist`

The sensor starts automatically on login and restarts if it crashes.

**Useful commands:**

| Action | Command |
|--------|---------|
| View logs | `tail -f ~/.squirrelops/sensor/logs/squirrelops-sensor.log` |
| Check status | `launchctl print gui/$(id -u)/com.squirrelops.sensor` |
| Stop sensor | `launchctl bootout gui/$(id -u)/com.squirrelops.sensor` |
| Start sensor | `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.squirrelops.sensor.plist` |

**File locations:**

| Item | Path |
|------|------|
| Install directory | `~/.squirrelops/sensor/` |
| Configuration | `~/.squirrelops/sensor/config/config.yaml` |
| Data (SQLite) | `~/.squirrelops/sensor/data/` |
| Logs | `~/.squirrelops/sensor/logs/squirrelops-sensor.log` |
| Python venv | `~/.squirrelops/sensor/venv/` |
| launchd plist | `~/Library/LaunchAgents/com.squirrelops.sensor.plist` |

### Privileged Helper (required for macOS)

On macOS, ARP network scanning, virtual IP aliases, and port forwarding require root privileges. Rather than running the entire sensor as root, these operations are handled by a lightweight privileged helper daemon (`com.squirrelops.helper`) that runs in the background.

**If you install via the .pkg installer (recommended):** The helper is bundled inside the macOS app. On first launch, the app prompts for your admin password and installs the helper automatically via macOS system services. It persists across reboots.

**If you install the sensor standalone (Path B):** You also need the macOS app (Path C below) to install the helper. Without it, the sensor can start but cannot perform ARP scans (no device discovery), deploy mimic decoys, or set up port forwarding.

**Helper file locations:**

| Item | Path |
|------|------|
| Binary | `/Library/PrivilegedHelperTools/com.squirrelops.helper` |
| Launchd plist | `/Library/LaunchDaemons/com.squirrelops.helper.plist` |
| Socket | `/var/run/squirrelops-helper.sock` |
| Logs | `/var/log/com.squirrelops.helper.log` |

### Path C: macOS App (control plane)

Download the macOS app from [GitHub Releases](https://github.com/rocketweb/squirrelops-home/releases). On first launch, the app will:

1. Prompt for your admin password to install the privileged helper
2. Guide you through sensor pairing (see [Finding Your Pairing Code](#finding-your-pairing-code) below)

---

## Initial Setup

### Pairing Your Sensor

Every sensor — whether on a remote device (Path A) or the same Mac (Path B) — must be paired with the macOS app before use. Pairing establishes a mutual TLS connection so all communication is encrypted and authenticated. You only need to do this once per sensor.

**The pairing flow:**

1. Open the macOS app — it automatically discovers the sensor via mDNS on your local network
2. The app shows the setup screen and asks for a **6-digit pairing code**
3. Enter the code (see [Finding Your Pairing Code](#finding-your-pairing-code) below)
4. The app and sensor exchange TLS certificates
5. You're connected — you won't need the pairing code again

### Finding Your Pairing Code

When the sensor starts, it generates a 6-digit pairing code and displays it prominently. The code expires after **10 minutes** or **5 failed attempts**, then a new code is generated automatically.

**Docker sensor (Path A):**

The pairing code appears in the container logs as a large banner. View it with:

```bash
docker compose -f /opt/squirrelops/docker-compose.yml logs | grep "Pairing Code"
```

Or view the full banner by scrolling through recent logs:

```bash
docker compose -f /opt/squirrelops/docker-compose.yml logs --tail 50
```

**macOS native sensor (Path B):**

The simplest way to retrieve the pairing code is to read it from a well-known file that the sensor writes at startup:

```bash
cat /tmp/squirrelops-pairing-code
```

Alternatively, use the built-in CLI command:

```bash
~/.squirrelops/sensor/venv/bin/python -m squirrelops_home_sensor --show-pairing-code
```

The code also appears in the sensor log file:

```bash
grep "Pairing Code" ~/.squirrelops/sensor/logs/squirrelops-sensor.log
```

**If the code has expired:** Simply restart the sensor to generate a new code. For Docker, use `docker compose restart`. For macOS, use `launchctl kickstart gui/$(id -u)/com.squirrelops.sensor`.

After successful pairing, the app stores the sensor's TLS certificate in your macOS Keychain. All subsequent connections are authenticated automatically.

### Learning Mode (48 hours)

When the sensor starts for the first time, it enters **Learning Mode** for 48 hours. During this period:

- The sensor scans your network and discovers devices
- It collects behavioral baselines (which devices connect where)
- It deploys decoys immediately — decoy trip alerts still fire during learning
- **Anomaly alerts are suppressed** until learning completes, preventing false positives while the sensor establishes what "normal" looks like

The dashboard shows a progress bar with time remaining. After 48 hours, the sensor begins generating anomaly alerts for new connection patterns it hasn't seen before.

### Resource Profile Selection

The sensor auto-detects your hardware and recommends a profile. You can change it anytime in Settings.

| Profile | Scan Interval | Max Decoys | Max Mimics | Classification | Best For |
|---------|--------------|------------|------------|---------------|----------|
| **Lite** | 15 min | 3 | Disabled | Local signature DB only | Raspberry Pi 3, low-resource devices |
| **Standard** | 5 min | 8 | 10 | Cloud LLM (your API key) | Raspberry Pi 4, NAS, most setups |
| **Full** | 1 min | 16 | 10+ | Local LLM (LM Studio/Ollama) | Dedicated server, power users |

---

## Dashboard Overview

The macOS app uses a sidebar navigation with six sections: **Dashboard**, **Devices**, **Alerts**, **Decoys**, **Squirrel Scouts**, and **Settings**.

### Dashboard (Home)

The home view shows two things at a glance:

**System Health** — Connection status, resource profile, and key metrics:
- Connection indicator: green (live), yellow (syncing), blue (connecting), gray (disconnected)
- Counts for discovered devices, deployed decoys, and unread alerts
- Sensor version and uptime
- Learning mode progress bar (during the first 48 hours)

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
| **Approved** | Known device — future appearances won't generate alerts |
| **Rejected** | Flagged as unauthorized — all future appearances generate high-priority alerts |
| **Unknown** | Not yet classified — new alerts fire if the device reappears |

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

The **Decoys** tab shows a card grid of **all** deployed deception — both traditional honeypot decoys and mimic decoys from Squirrel Scouts. Each card displays:

- Decoy name and type icon
- Bind address and port
- Status badge (Active, Degraded, Stopped)
- Enable/disable toggle
- Connection count and credential trip count

**Decoy types:**

| Type | Icon | Description |
|------|------|-------------|
| Dev Server | `</>` | Fake development server (Express, Next.js, Flask) |
| Home Assistant | House | Fake Home Assistant login page and API |
| File Share | Folder | Fake SMB/AFP share with planted credentials |
| Mimic | Device-specific | Cloned from a real device via Squirrel Scouts — responds with realistic service fingerprints on a virtual IP |

Traditional honeypot decoys are automatically selected based on what real services exist on your network. The sensor deploys complementary decoys — it won't duplicate services already present. Mimic decoys are deployed by the Squirrel Scouts subsystem and appear in the grid alongside honeypots, giving you a single view of all deception deployed on your network.

### Decoy Status

| Status | Meaning |
|--------|---------|
| **Active** | Running and listening for connections |
| **Degraded** | Failed to restart after 3 crashes in 5 minutes — restart manually or wait for the 30-minute health check |
| **Stopped** | Disabled by user |

For degraded decoys, a **Restart** button appears on the card.

### Decoy Detail Sheet

Click a decoy card to open its detail sheet:

- **Decoy Info** — Type, address, connection count, credential trip count, failure count, creation date
- **Configuration** — View and edit decoy-specific configuration values (click **Edit Config** to modify)
- **Connection Log** — Chronological list of all connections to this decoy, showing source IP, request path, timestamp, and whether a credential was used (highlighted with a "CREDENTIAL" label)

---

## Squirrel Scouts

Squirrel Scouts is an advanced reconnaissance and deception subsystem that makes your network defenses significantly more convincing. It's available on **Standard** and **Full** profiles.

### How Squirrel Scouts Works

1. The **Scout Engine** probes every open port on every discovered device to capture exactly what an intruder would see — HTTP responses, headers, TLS certificates, SSH version strings, mDNS service types
2. **Mimic Templates** are generated from scout data — route configurations that replicate real device responses with planted credentials injected in realistic locations
3. **Virtual IPs** are allocated from unused addresses in your subnet (typically .200-.250) using interface aliases, so mimic decoys appear as distinct physical devices on the network
4. **Port Forwarding** (pfctl on macOS, iptables on Linux) transparently redirects privileged ports to the mimic servers
5. **mDNS Hostnames** are registered with device-appropriate names (e.g., `tapo-plug-A3F2`, `synology-ds-B1C8`) so network scanners see plausible device names

The result: a network scan from an intruder's perspective reveals more devices than actually exist, each responding with realistic service fingerprints and containing planted credentials that trigger alerts when used.

### Squirrel Scouts Tab

The **Squirrel Scouts** tab in the sidebar has three sections:

#### Scout Engine

Shows the status of the reconnaissance engine:

- **Profiles** — Total service profiles collected across all devices
- **Active Mimics** — Currently deployed mimic decoys out of the maximum allowed
- **Interval** — Time between automated scout cycles
- **Status** — Whether a scout cycle is currently running or idle
- **Last Scout** — Timestamp and duration of the most recent scout cycle

The **Run Scout** button triggers an immediate scout cycle (useful after adding new devices to your network).

#### Virtual Network

Shows all deployed mimic decoys in a card grid. Each mimic card displays:

- **Name** — Derived from the source device being mimicked (e.g., "Mimic: tp-link-plug")
- **Status badge** — Active, Stopped, or Degraded
- **Virtual IP** — The allocated IP address on your subnet
- **Port** — Primary listening port
- **Hits** — Connection count (highlighted in yellow when > 0, meaning something probed the mimic)
- **Category** — Device type being mimicked (Smart Home, Camera, NAS, Media, Printer, Router, Dev Server)
- **mDNS hostname** — The registered hostname visible via Bonjour (e.g., `tapo-plug-A3F2.local`)

Each card has **Remove** and (for stopped mimics) **Restart** buttons.

The **Deploy** button triggers the mimic evaluation and deployment pipeline, deploying new mimics for scouted devices that don't already have one.

#### Service Profiles

Lists all collected service fingerprints in a scrollable table:

- **IP:Port** — The device and port that was probed
- **Service name** — Identified service (HTTP, SSH, etc.)
- **Server header** — The HTTP `Server:` header value, if present
- **Protocol version** — SSH/SMTP version strings, if present
- **HTTP status** — Response code from the probe
- **TLS** — Certificate CN if TLS was detected (shown with a lock icon)

### Mimic Decoy Categories

The mimic system generates device-appropriate planted credentials:

| Category | Credential Strategy |
|----------|-------------------|
| Smart Home | Home Assistant-style tokens in API error responses + login forms |
| NAS / File Share | `passwords.txt` + SSH keys in directory listings |
| Dev Server | `.env` files with API keys |
| Camera | Basic auth credentials in camera config pages |
| Generic | API keys in JSON error responses |

---

## Alerts & Incidents

### Alert Feed

The **Alerts** tab shows a chronological feed of alerts within the 90-day retention window. By default, only **active (undismissed) alerts** are shown. Click the **History** toggle in the toolbar to include previously dismissed alerts.

**Alert types:**

| Type | Severity | Meaning |
|------|----------|---------|
| Credential Trip | Critical | A planted credential was used in an authentication attempt |
| Rejected Device Reappearance | Critical | A device you flagged as unauthorized has returned |
| Decoy Trip | High | Something connected to a decoy service |
| New Device | High | An unknown device joined your network |
| Security Insight | Medium–High | A risky port or service is open on one or more devices (e.g., SSH, VNC, unencrypted admin interfaces) |
| Device Verification | Medium | A device reconnected with a different MAC but partial fingerprint match |
| Behavioral Anomaly | Medium | A device deviated from its learned connection baseline |
| Port Risk | Medium | A device is exposing a potentially risky port (e.g., open telnet, unencrypted management interface) |
| Vendor Advisory | Medium | A device's manufacturer has a known security advisory |
| Sensor Offline | Low | The sensor service stopped or became unreachable |
| Learning Complete | Low | The 48-hour learning period has finished |
| Review Reminder | Low | Devices have been in "unknown" trust status for an extended period |

### Grouped Security Alerts

Security insight alerts are **grouped by issue type** rather than per-device. For example, if four devices on your network have SSH open, you'll see a single alert titled "SSH open on 4 devices" instead of four separate alerts. Each grouped alert includes:

- **Risk description** — an explanation of why this is a security concern
- **Remediation steps** — actionable guidance on how to fix the issue
- **Affected devices list** — every device with the issue, showing name, IP address, port, and MAC address

Grouped alerts update automatically: if a new device appears with the same issue, the existing alert's device count increases and the alert becomes active again (even if previously dismissed). If a device resolves the issue (port closed), it is removed from the group.

Click any grouped alert to open its **Alert Detail View**, which shows the full risk description, remediation guidance, and a table of all affected devices.

### Filtering Alerts

The toolbar provides multiple filtering dimensions:

- **Severity chips** — All, Critical, High, Medium, Low
- **Type chips** — All Types, Decoy Trip, Credential Trip, New Device, MAC Changed, Security, System
- **Date Range** — Click the calendar button to filter by date range (From/To)
- **Search** — Free-text search across alert titles, source IPs, and alert types
- **History toggle** — Show or hide previously dismissed alerts

All filters combine (AND logic). Active filters appear highlighted.

### Alert Detail View

Click any alert in the feed to open a detail sheet showing the full context of the alert:

- **Header** — Severity indicator, title, alert type badge (e.g., "Port Scan Detected", "Credential Accessed"), severity label, and timestamp
- **Source** — IP address, MAC address (if the device was identified), hostname, vendor, and device ID
- **Intrusion Details** — Destination port, protocol, request path (for HTTP-based detections), and detection method (HTTP Decoy, Mimic Decoy, DNS Canary)
- **Credential Access** (only for credential trip alerts) — Which planted credential was accessed and the request path used
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

Click **Export** in the alert feed toolbar to save alerts as JSON:

1. Choose a date range or click **Export All** for the entire retention window
2. Select a save location in the standard macOS save dialog
3. The export file is named `squirrelops-alerts-YYYY-MM-DD.json`

This is useful for preserving alert history beyond the 90-day retention window.

### Dismissing Alerts

There are several ways to dismiss alerts:

- **Hover dismiss** — Hover over any alert in the feed to reveal a dismiss button (×) on the right side
- **Context menu** — Right-click any alert and select **Dismiss**
- **Detail view** — Open a grouped alert's detail view and click the **Dismiss** button
- **Bulk dismiss** — Click **Dismiss All** in the toolbar to dismiss all visible alerts at once

Dismissed alerts are hidden from the default feed view but remain accessible via the **History** toggle. The unread count badge on the Alerts sidebar item updates automatically.

Dismissing a grouped security alert is like saying "I've seen this, I know about it." If the situation changes — for example, a new device appears with the same risky port — the alert automatically becomes active again so you don't miss the change.

---

## Settings

The Settings tab contains the following configuration sections.

### Appearance

Choose between **System** (follows macOS setting), **Light**, and **Dark** appearance modes. Default is System.

### Resource Profile

Switch between **Lite**, **Standard**, and **Full** profiles. Each profile shows a brief description of its scan interval, decoy limit, mimic limit, and classification method. Changes take effect immediately. Switching from Lite to Standard/Full enables Squirrel Scouts.

### Alert Methods

Configure how alerts are delivered. Each method has an enable/disable toggle and a minimum severity picker (All, Medium+, High+, Critical only):

**Push Notifications** — macOS system notifications for alerts even when the app is in the background.

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
| **Relaxed** | 0.60 | More permissive — fewer verification alerts, but slightly higher chance of misidentification |
| **Standard** | 0.75 | Default — balanced between convenience and security |
| **Strict** | 0.90 | More restrictive — more verification alerts, but stronger identity assurance |

When a returning device's fingerprint confidence falls between 0.50 and the threshold, you'll get a Device Verification Alert instead of auto-approval.

### Credential Decoys

Set the filename for the planted credential file served by decoy file shares. Default is `passwords.txt`. Change this if you want the credential artifact to look more natural for your network (e.g., `credentials.env`, `secrets.txt`).

Seven credential types are planted across decoy services. When an intruder accesses a credential via HTTP (e.g., by requesting `/.env` or `/passwords.txt` on a decoy), a **Critical** severity "Credential Accessed" alert fires immediately.

### DNS Canary Configuration

DNS canary hostnames are **disabled by default**. When enabled, unique hostnames are embedded in three credential types (AWS keys, GitHub PATs, Home Assistant tokens). If an intruder steals one of these credentials and attempts to use it, the resulting DNS lookup is detected by the sensor's local DNS monitor.

**Configuration** (in `config.yaml` or via environment variables):

```yaml
decoys:
  dns_canaries:
    enabled: false          # set to true to activate
    domain: "canary.local"  # the domain suffix for generated hostnames
```

Or via environment variables:

```bash
SQUIRRELOPS_DECOYS__DNS_CANARIES__ENABLED=true
SQUIRRELOPS_DECOYS__DNS_CANARIES__DOMAIN=canary.example.com
```

When enabled, credentials like AWS keys will contain hostnames in the format `{32-hex-chars}.{domain}` (e.g., `a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.canary.local`). The sensor's DNS monitor passively sniffs DNS traffic on the local network and matches queries against known canary hostnames. A match triggers a Critical "Credential Accessed" alert with `detection_method: dns_canary`.

**Important:** DNS canary detection is purely local and passive. No external server is contacted. However, to receive canary callbacks from credentials used *outside* your local network, you would need to set up a canary collection server. See [DNS Canary Setup](#dns-canary-setup) for details.

### LLM Configuration

This section appears only when the resource profile is **Standard** or **Full**.

**Standard mode (Cloud LLM):**
- Endpoint — Your LLM provider's API URL (e.g., `https://api.openai.com/v1`)
- Model — Model name (e.g., `gpt-4o-mini`, `claude-haiku-4-5-20251001`)
- API Key — Your provider's API key

**Full mode (Local LLM):**
- Endpoint — Your local LLM server URL (e.g., `http://localhost:1234/v1` for LM Studio, `http://localhost:11434` for Ollama)
- Model — Model name (e.g., `llama-3.2-3b`)
- API Key — Not required for local LLM servers

The sensor uses LLM classification only when the local signature database can't classify a device with confidence above 0.70. Only anonymized signals (manufacturer OUI, DHCP fingerprint hash, mDNS service types, open ports) are sent — no IP addresses, MAC addresses, or hostnames.

### Sensor

Displays sensor information:
- Sensor name and URL
- Software version
- Sensor ID

### Updates

Shows the current sensor version with a **Check for Updates** button. The sensor checks a version manifest for available updates. Updates are never automatic — you must confirm them.

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
tail -f ~/.squirrelops/sensor/logs/squirrelops-sensor.log
```

### Can't Find the Pairing Code

**Symptoms:** The app is asking for a 6-digit code but you don't know where to find it.

See [Finding Your Pairing Code](#finding-your-pairing-code) for detailed instructions. The quickest methods:

- **Docker:** `docker compose -f /opt/squirrelops/docker-compose.yml logs | grep "Pairing Code"`
- **macOS:** `cat /tmp/squirrelops-pairing-code`

If neither works, the sensor may not be running. Check the sensor status first.

### Pairing Code Expired

**Symptoms:** The code was rejected even though you entered it correctly.

The pairing code expires after 10 minutes or 5 failed attempts, then a new one is generated automatically. Restart the sensor to generate a fresh code:

- **Docker:** `docker compose -f /opt/squirrelops/docker-compose.yml restart`
- **macOS:** `launchctl kickstart gui/$(id -u)/com.squirrelops.sensor`

Then retrieve the new code using the methods above.

### App Shows "Disconnected" (Gray Dot)

**Symptoms:** Menu bar icon is gray, dashboard shows "Disconnected."

**Possible causes:**
- The sensor process has stopped
- Network connectivity between the Mac and sensor device is broken
- The sensor crashed and hasn't restarted

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
launchctl print gui/$(id -u)/com.squirrelops.sensor
```

If it's not running, reload it:
```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.squirrelops.sensor.plist
```

The app reconnects automatically on a 30-second interval. After 5 minutes of disconnection, it generates a Low-severity "Sensor Offline" alert.

### No Alerts Appearing

**Symptoms:** Sensor is connected but no alerts show up.

**Possible causes:**
- **Still in learning mode** — Anomaly alerts are suppressed during the first 48 hours. Decoy trip alerts still fire during learning. Check the dashboard for the learning mode progress bar.
- **No new devices have joined** — If your network is stable, New Device alerts won't fire.
- **Decoys haven't been deployed** — Check the Decoys tab. If no decoys are deployed, the sensor may not have found suitable ports or addresses.

### Decoy Shows "Degraded"

**Symptoms:** A decoy card shows a "Degraded" status badge.

**What happened:** The decoy crashed 3 times within 5 minutes. The sensor stopped trying to restart it automatically.

**What to do:**
1. Click the **Restart** button on the decoy card
2. If it degrades again, check the sensor logs for the underlying error
3. The sensor also retries degraded decoys automatically every 30 minutes during health checks

### Sensor Shows 0 Devices (macOS)

**Symptoms:** Dashboard shows 0 devices, sensor logs show no ARP scan results.

**Cause:** The privileged helper (`com.squirrelops.helper`) isn't running. On macOS, ARP scanning requires the helper daemon for raw socket access.

**What to do:**
1. Open the macOS app — it installs the helper automatically on first launch (prompts for admin password)
2. Verify the helper is running: `sudo launchctl print system/com.squirrelops.helper`
3. Check helper logs: `tail -f /var/log/com.squirrelops.helper.log`
4. Restart the sensor after the helper is running

### Mimic Decoys Not Deploying

**Symptoms:** The Virtual Network section in Squirrel Scouts is empty, or Deploy returns an error.

**Possible causes:**
- **Helper not running (macOS)** — Deploy returns a "Privileged helper is not running" error. The helper is required for creating virtual IP aliases. Open the macOS app to install it, or see the [helper documentation](#privileged-helper-required-for-macos) above.
- **Scouts haven't run yet** — Click **Run Scout** to trigger a manual scout cycle, then click **Deploy**
- **Profile is Lite** — Mimic decoys require Standard or Full profile. Switch profiles in Settings.
- **No suitable candidates** — The scout engine needs devices with open HTTP ports or protocol banners to generate mimic templates. If all devices only have encrypted services, fewer mimics will be available.
- **Virtual IPs exhausted** — The default range is .200-.250 (51 IPs). If many are in use or conflict with real devices, fewer slots are available.

### Settings Won't Save

**Symptoms:** Error messages appear when changing settings.

**Possible causes:**
- The sensor is disconnected — changes are sent to the sensor via the API and require an active connection
- Check the sensor logs for API errors

### Cloud LLM Classification Not Working

**Symptoms:** Devices show as "Unknown Device" even in Standard mode.

**Possible causes:**
- No API key configured — go to Settings > LLM Configuration and enter your API key
- Invalid API key — the sensor falls back silently to the local signature database
- The cloud LLM endpoint is unreachable — check your internet connection

The sensor always falls back to local classification if the LLM is unavailable. No alert is generated for LLM failures.

### Uninstalling

**Docker sensor:**
```bash
docker compose -f /opt/squirrelops/docker-compose.yml down -v
sudo rm -rf /opt/squirrelops
```

**macOS sensor:**
```bash
launchctl bootout gui/$(id -u)/com.squirrelops.sensor
rm ~/Library/LaunchAgents/com.squirrelops.sensor.plist
rm -rf ~/.squirrelops
```

All locally stored data (databases, configuration, logs, alert history) is deleted with the installation directory. No data persists elsewhere.

---

## DNS Canary Setup

DNS canary hostnames let the sensor detect when a stolen credential is *used* — not just accessed. This section explains how the feature works and how to set up a canary collection server if you want detection beyond your local network.

### How DNS Canaries Work

1. The sensor generates credentials with unique hostnames embedded in them (e.g., an AWS key whose secret references `a1b2...c5d6.canary.example.com`)
2. If an intruder steals the credential and tries to use it, their machine performs a DNS lookup for that hostname
3. Detection can happen in two ways:
   - **Local detection** (built-in): The sensor passively sniffs DNS queries on your LAN (UDP port 53) and matches them against known canary hostnames. This works when the intruder is still on your network.
   - **Remote detection** (requires your own server): If you control the DNS zone for the canary domain, queries from *anywhere on the internet* are logged by your authoritative DNS server and can be forwarded back to the sensor.

### Local-Only Setup (No External Server)

This is the simplest configuration. It detects credential use only while the intruder is on your local network.

1. Edit your sensor config (`config.yaml` or environment variables):

```yaml
decoys:
  dns_canaries:
    enabled: true
    domain: "canary.local"    # .local is fine for LAN-only detection
```

2. Restart the sensor. New decoys deployed after this point will have canary hostnames embedded in their AWS key, GitHub PAT, and HA token credentials.

3. Existing decoys are not retroactively updated. To regenerate credentials with canaries, disable and re-enable each decoy, or redeploy the sensor.

That's it. The sensor's DNS monitor will detect any DNS queries for `*.canary.local` on your LAN and create Critical alerts.

### Remote Detection Setup (External Canary Server)

To detect credential use after an intruder has left your network, you need:

1. **A domain you control** (e.g., `canary.example.com`)
2. **A VPS or cloud server** to run an authoritative DNS server for that domain
3. **DNS delegation** from your registrar pointing the canary subdomain to your server

#### Requirements

- A registered domain (or subdomain you can delegate)
- A server with a public IP address (any small VPS will do — minimal CPU/RAM needed)
- Ability to configure NS records at your domain registrar

#### Step 1: Configure DNS Delegation

At your domain registrar, create an NS record that delegates the canary subdomain to your server:

```
canary.example.com.  NS  ns1.canary.example.com.
ns1.canary.example.com.  A  <your-server-public-ip>
```

This tells the global DNS system that your server is authoritative for `*.canary.example.com`.

#### Step 2: Run a Logging DNS Server

On your server, run a DNS server that logs all incoming queries and responds with a valid (but meaningless) answer. A minimal Python implementation using `dnslib`:

```
pip install dnslib
```

Create `canary_dns.py`:

```python
"""Minimal authoritative DNS server that logs all queries to a canary zone."""

import datetime
import json
import sys

from dnslib import DNSRecord, RR, QTYPE, A
from dnslib.server import DNSServer, BaseResolver

ZONE = sys.argv[1] if len(sys.argv) > 1 else "canary.example.com"
LOG_FILE = sys.argv[2] if len(sys.argv) > 2 else "/var/log/canary-dns.jsonl"
# Respond with a routable but harmless IP (RFC 5737 TEST-NET)
ANSWER_IP = "192.0.2.1"


class CanaryResolver(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]
        source = handler.client_address[0]

        entry = {
            "ts": datetime.datetime.utcnow().isoformat() + "Z",
            "query": qname,
            "type": qtype,
            "source_ip": source,
        }

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

        print(f"[CANARY] {source} -> {qname} ({qtype})")

        if qname.endswith(ZONE) and qtype == "A":
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(ANSWER_IP), ttl=60))

        return reply


if __name__ == "__main__":
    print(f"Starting canary DNS server for zone: {ZONE}")
    print(f"Logging to: {LOG_FILE}")
    resolver = CanaryResolver()
    server = DNSServer(resolver, port=53, address="0.0.0.0")
    server.start()
```

Run it:

```bash
sudo python3 canary_dns.py canary.example.com /var/log/canary-dns.jsonl
```

Or run it as a systemd service for persistence:

```ini
# /etc/systemd/system/canary-dns.service
[Unit]
Description=Canary DNS Server
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/canary-dns/canary_dns.py canary.example.com /var/log/canary-dns.jsonl
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

#### Step 3: Configure the Sensor

Update your sensor config to use your domain:

```yaml
decoys:
  dns_canaries:
    enabled: true
    domain: "canary.example.com"
```

Restart the sensor. New credentials will now contain hostnames like `a1b2...c5d6.canary.example.com`.

#### Step 4: Monitor for Hits

Check your canary DNS server logs for queries:

```bash
tail -f /var/log/canary-dns.jsonl
```

Each line is a JSON object with the query name, type, source IP, and timestamp. Cross-reference the hex subdomain against your sensor's `planted_credentials` table to identify which credential was compromised.

#### Verification

To verify the setup is working end-to-end:

1. Deploy a decoy with canaries enabled
2. Access the decoy's credential endpoint (e.g., `curl http://<decoy-ip>:<port>/.env`)
3. Extract a canary hostname from the credential content
4. From a different machine, run `nslookup <canary-hostname>` or `dig <canary-hostname>`
5. Confirm the query appears in your canary DNS server logs
6. Confirm the sensor creates a Critical alert (for local LAN queries)

### Security Considerations

- The canary domain does not need to host any web content — it only needs to answer DNS queries
- The DNS server should be hardened: disable recursion, rate-limit responses, and restrict zone transfers
- Canary hostnames are random 32-character hex strings, making them unguessable
- The canary DNS server logs source IPs of queries, which can help attribute where stolen credentials were used
- Consider rotating canary domains periodically if you suspect an intruder has identified your canary infrastructure

---

## Privacy & Security

### What Stays on Your Network

Everything, by default. All device data, alert history, scan results, and configuration are stored in a local SQLite database on the sensor. The macOS app communicates with the sensor over your local network using TLS-encrypted connections with certificates exchanged during pairing.

### What Can Leave Your Network (Only If You Enable It)

| Feature | Data Sent | Destination | How to Disable |
|---------|-----------|-------------|----------------|
| **Push Notifications** | Alert title and body text | Apple Push Notification Service (via relay) | Toggle off in Settings > Alert Methods |
| **Cloud LLM Classification** (Standard mode) | Manufacturer OUI, DHCP fingerprint hash, mDNS service types, open port list. No IPs, MACs, or hostnames. | Your configured LLM provider (Anthropic or OpenAI), using your own API key | Switch to Lite or Full profile |
| **Slack Webhooks** | Alert severity, type, summary, timestamp. Device identifiers only if you enable "Include Device Identifiers." | Your Slack workspace | Toggle off in Settings > Alert Methods |
| **Update Checks** | Current version number and platform identifier | SquirrelOps update endpoint | Don't click "Check for Updates" |
| **DNS Canaries** (if enabled with external domain) | Canary hostnames appear in DNS queries initiated by intruders using stolen credentials. Your external canary DNS server receives these queries. | Your own canary DNS server | Set `decoys.dns_canaries.enabled: false` (this is the default) |

In **Full mode** with a local LLM, no classification data leaves your network.

**Note on DNS canaries:** When disabled (the default), no canary hostnames are generated and no DNS-related data leaves your network. When enabled with a `.local` domain, detection is purely local. Only when you configure an external domain and run your own canary DNS server do DNS queries from stolen credentials leave your network — and those queries go to a server *you* control, not to any third party.

### Certificate Pinning

After pairing, the macOS app pins the sensor's TLS certificate by SHA-256 fingerprint. This prevents man-in-the-middle attacks on your local network — even if someone could intercept traffic between the app and sensor, they can't impersonate the sensor without the original certificate.

### What the Sensor Does NOT Do

- **No deep packet inspection** — Traffic analysis is limited to connection metadata (source, destination, port, protocol, byte count). Payload content is never inspected.
- **No traffic modification** — The sensor never blocks, throttles, or modifies real network traffic. It is a detection system, not a firewall.
- **No scanning beyond your network** — The sensor only monitors subnets it has direct Layer 2 adjacency to.
- **No telemetry** — No usage data, device inventories, or analytics are sent anywhere.
- **No auto-updates** — The sensor never updates itself without your explicit confirmation.

### Virtual IP Safety

Virtual IPs used by mimic decoys are:
- Allocated from the high end of your subnet (typically .200-.250) to avoid DHCP conflicts
- Excluded from the sensor's own scan loop to prevent false device discoveries
- Automatically evacuated if a real device claims the same IP — the mimic is stopped, the alias is removed, and the IP is reallocated

### Port Forwarding Safety

On macOS, the sensor uses pfctl packet filter rules (loaded into a dedicated `com.apple/squirrelops` anchor) to redirect privileged ports to mimic servers. These rules:
- Only affect traffic destined for virtual IPs (never your real devices)
- Are automatically cleaned up on sensor shutdown
- Do not modify the system's `pf.conf` or interfere with existing firewall rules

### Credential Safety

The only credentials the sensor stores are **synthetic credentials it generates for deception**. These are clearly marked as synthetic in the database (`planted_credentials` table with `credential_type` and `planted_location` columns). The sensor never stores your real service credentials.

When DNS canaries are enabled, canary hostnames are stored alongside the credential in the `canary_hostname` column. These hostnames are random hex strings that do not contain any identifying information about your network, devices, or real credentials.
