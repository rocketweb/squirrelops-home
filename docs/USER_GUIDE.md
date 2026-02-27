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

### Path C: macOS App (control plane)

Download the macOS app from [GitHub Releases](https://github.com/rocketweb/squirrelops-home/releases). On first launch, the app will guide you through setup.

If you installed the sensor locally on the same Mac (Path B), the app connects via localhost automatically — no pairing required.

---

## Initial Setup

### Pairing with a Remote Sensor

When you run the sensor on a separate device (Path A), you need to pair it with the macOS app:

1. Start the sensor on your Linux/NAS device using the install script
2. Open the macOS app — it will show the setup flow
3. Select **"Set up remote sensor"**
4. The app discovers the sensor automatically via mDNS (`_squirrelops._tcp`)
5. The sensor displays a **6-digit pairing code** in its terminal/logs
6. Enter this code in the macOS app

After successful pairing, the app and sensor exchange TLS certificates. All subsequent communication is encrypted and authenticated — you won't need the pairing code again.

### Learning Mode (48 hours)

When the sensor starts for the first time, it enters **Learning Mode** for 48 hours. During this period:

- The sensor scans your network and discovers devices
- It collects behavioral baselines (which devices connect where)
- It deploys decoys immediately — decoy trip alerts still fire during learning
- **Anomaly alerts are suppressed** until learning completes, preventing false positives while the sensor establishes what "normal" looks like

The dashboard shows a progress bar with time remaining. After 48 hours, the sensor begins generating anomaly alerts for new connection patterns it hasn't seen before.

### Resource Profile Selection

The sensor auto-detects your hardware and recommends a profile. You can change it anytime in Settings.

| Profile | Scan Interval | Max Decoys | Max Mimics | Scout Interval | Classification | Best For |
|---------|--------------|------------|------------|----------------|---------------|----------|
| **Lite** | 15 min | 3 | 0 | Disabled | Local signature DB only | Raspberry Pi 3, low-resource devices |
| **Standard** | 5 min | 8 | 10 | 60 min | Cloud LLM (your API key) | Raspberry Pi 4, NAS, most setups |
| **Full** | 1 min | 16 | 30 | 30 min | Local LLM (LM Studio/Ollama) | Dedicated server, power users |

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

The **Decoys** tab shows a card grid of all deployed decoys. Each card displays:

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

Decoys are automatically selected based on what real services exist on your network. The sensor deploys complementary decoys — it won't duplicate services already present.

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

The **Alerts** tab shows a chronological feed of all alerts within the 90-day retention window.

**Alert types:**

| Type | Severity | Meaning |
|------|----------|---------|
| Credential Trip | Critical | A planted credential was used in an authentication attempt |
| Rejected Device Reappearance | Critical | A device you flagged as unauthorized has returned |
| Decoy Trip | High | Something connected to a decoy service |
| New Device | High | An unknown device joined your network |
| Device Verification | Medium | A device reconnected with a different MAC but partial fingerprint match |
| System (sensor offline, learning complete) | Medium/Low | Sensor status changes |

### Filtering Alerts

The toolbar provides multiple filtering dimensions:

- **Severity chips** — All, Critical, High, Medium, Low
- **Type chips** — All Types, Decoy Trip, New Device, MAC Changed, System
- **Date Range** — Click the calendar button to filter by date range (From/To)
- **Search** — Free-text search across alert titles, source IPs, and alert types

All filters combine (AND logic). Active filters appear highlighted.

### Incidents

Related alerts from the same source are grouped into **incidents**. Click any alert in the feed to open the incident detail view, which shows:

- Incident ID, severity, and status (Active or Closed)
- Source IP and MAC address
- Time span (first alert to last alert)
- Summary description
- **Child alerts** — Expandable list of all alerts in the incident. Click any alert row to expand it and see full details: alert type, source IP/MAC, device ID, decoy ID, read/actioned timestamps, and any additional detail metadata

Use **Mark All Read** to acknowledge all alerts in an incident at once.

### Exporting Alerts

Click **Export** in the alert feed toolbar to save alerts as JSON:

1. Choose a date range or click **Export All** for the entire retention window
2. Select a save location in the standard macOS save dialog
3. The export file is named `squirrelops-alerts-YYYY-MM-DD.json`

This is useful for preserving alert history beyond the 90-day retention window.

### Acknowledging Alerts

Right-click any alert in the feed to **Mark as Read**. The unread count badge on the Alerts sidebar item updates automatically.

---

## Settings

The Settings tab contains eight configuration sections.

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

The app reconnects automatically on a 30-second interval. After 5 minutes of disconnection, it generates a Medium-severity "Sensor Disconnected" alert.

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

### Mimic Decoys Not Deploying

**Symptoms:** The Virtual Network section in Squirrel Scouts is empty.

**Possible causes:**
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

In **Full mode** with a local LLM, no classification data leaves your network.

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

The only credentials the sensor stores are **synthetic credentials it generates for deception**. These are clearly marked as synthetic in the database. The sensor never stores your real service credentials.
