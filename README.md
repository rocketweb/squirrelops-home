# SquirrelOps Home

**Local-first home network security with high-signal deception.**

- **Honeypots that blend in** — auto-deploys realistic decoy services (file shares, dev servers, Home Assistant instances) based on what's actually on your network
- **Squirrel Scouts** — service fingerprinting that builds coherent fake hosts from real devices, with one decoy service per observed port and a shared virtual IP and hostname for services copied from the same source
- **High-confidence decoy alerts** — a connection to an isolated decoy is inherently suspicious and is kept separate from lower-confidence behavioral detections
- **Device fingerprinting** — identifies every device on your network using MAC OUI, mDNS, SSDP, DHCP, and port signatures, with optional LLM-powered classification
- **Behavioral baselines** — learns normal connection patterns during a 48-hour training period, then alerts on anomalies
- **Credential canaries** — plants realistic-looking credentials (AWS keys, SSH keys, .env files, database URIs, GitHub PATs, Home Assistant tokens) that trigger critical alerts when accessed through a decoy
- **Local by default** — inventory, alerts, and configuration stay in local SQLite. Optional cloud classification and notification integrations are explicit opt-ins.
- **Push notifications** — optional APNs alerts to your iPhone/Mac when a decoy is tripped
- **Home Assistant integration** — enriches device data with names, areas, and types from your HA instance

## How It Works

SquirrelOps Home runs a sensor on your network that does three things:

1. **Discovers and fingerprints** every device on your LAN using ARP scanning, port probing, mDNS/SSDP discovery, and IEEE OUI lookups
2. **Deploys decoy services** that mimic real things on your network — a fake NAS, a fake Home Assistant, a fake dev server — placed on unused ports and IPs
3. **Watches and alerts** when anything touches a decoy or deviates from learned behavioral baselines

The macOS app is your control plane: pair it with the sensor, view your device inventory, manage decoys, configure alerts, and respond to incidents.

```
┌─────────────────────┐         TLS + WebSocket         ┌──────────────────────┐
│   macOS App          │◄──────────────────────────────►│   Sensor              │
│   (SwiftUI)          │         REST API               │   (Python/FastAPI)    │
│                      │                                 │                       │
│  • Dashboard         │                                 │  • ARP/port scanning  │
│  • Device inventory  │                                 │  • Device fingerprint │
│  • Decoy management  │                                 │  • Decoy orchestrator │
│  • Squirrel Scouts   │                                 │  • Squirrel Scouts    │
│  • Alert feed        │                                 │  • Behavioral baseline│
│  • Settings          │                                 │  • Event bus + SQLite │
└─────────────────────┘                                  └──────────────────────┘
```

## Architecture

The sensor is made up of three internal engines:

- **PingTing** — passive network monitoring, device discovery, behavioral baselines
- **ClownPeanuts** — active deception engine, decoy lifecycle management, credential canary deployment
- **Squirrel Scouts** — deep service reconnaissance, mimic decoy generation, virtual network expansion

Communication between the app and sensor uses mutual TLS with certificates exchanged during an on-device pairing flow (challenge-response with ECDSA P-256).

### Decoy Types

| Type | What It Mimics | Planted Credentials |
|------|---------------|---------------------|
| File Share | nginx-served directory with sensitive-looking files | `passwords.txt` (username:password pairs), SSH private key |
| Dev Server | Express/Next.js dev server with debug endpoints | `.env` file with API keys, DB URLs, tokens |
| Home Assistant | HA login page and API with realistic error responses | Long-lived access token |
| **Mimic** | **A fake host assembled from a real device's observed ports, sanitized HTTP behavior, service banners, TLS metadata, and mDNS services** | Synthetic credentials exposed by supported HTTP routes |

### Credential Types

Seven credential types are generated and planted across decoy services:

| Credential | Format |
|------------|--------|
| Password pairs | `username:AdjNoun1234!` (8-12 per decoy) |
| AWS Access Key | `AKIA` + 16 alphanumeric chars |
| Database URI | `postgresql://user:pass@host:5432/db` |
| SSH Private Key | PEM-formatted RSA key (~1600 bytes) |
| HA Token | 183-char base64-like string |
| .env File | Multi-line config with mixed secrets |
| GitHub PAT | `ghp_` + 36 alphanumeric chars |

### Squirrel Scouts

Squirrel Scouts is an optional subsystem that makes the deception layer significantly more convincing:

1. **Scout Engine** probes open ports on discovered devices to collect bounded HTTP samples, TLS certificate metadata, protocol banners, and mDNS service types
2. **Fake-host templates** group every observed service from one source device under one virtual IP and hostname. Each port remains a separate service decoy so its behavior and evidence stay protocol-specific.
3. **Virtual IPs** are allocated from verified-free addresses in your subnet (.200-.250 range), published with scoped proxy ARP, and bound as isolated loopback /32 addresses so they cannot expose unrelated sensor-host ports
4. **Port Forwarding** (pfctl on macOS, iptables on Linux) redirects privileged ports (22, 80, 443) to high ports where the unprivileged mimic servers bind
5. **mDNS Services** are registered via zeroconf under a persistent, editable, device-appropriate hostname. HTTPS services use a persistent certificate generated for the fake host rather than copying a real device's private identity.

The result is a set of internally consistent fake hosts whose ports resemble real systems already present on the network. Supported HTTP credential routes trigger alerts when accessed.

On macOS, these virtual IPs use proxy ARP through the Mac's physical interface. They therefore share its Layer 2 MAC address, and a reverse-DNS lookup may still return the Mac's real hostname. This release improves service-level realism but does not claim to be indistinguishable from a separate physical device to an advanced Layer 2 scan.

### Resource Profiles

The sensor adapts to available resources:

| Profile | Scan Interval | Classic Decoys | Fake-host Ceiling | Classification |
|---------|--------------|----------------|-------------------|----------------|
| **Lite** | 15 min | 3 | Disabled | Local signature DB only |
| **Standard** | 5 min | 3 | Up to 10 | Cloud LLM (your API key) |
| **Full** | 1 min | 3 | Up to 30 | Local LLM (LM Studio/Ollama) |

The ceiling counts fake hosts, not service rows. Squirrel Scouts deploys at most one fake host for each eligible real source device, so a network with six eligible sources produces at most six fake hosts even in Full mode. A multi-port host has one service-decoy row per observed port and can therefore contribute several rows.

## Installation

### Sensor — Linux/NAS (Docker)

Install from a pinned release and verify its checksum before running it, rather than piping an unverified script straight into a root shell. Each release publishes `install.sh` and `install.sh.sha256` on the [Releases page](https://github.com/rocketweb/squirrelops-home/releases).

```bash
VERSION=v1.1.14   # pick a released version
base="https://github.com/rocketweb/squirrelops-home/releases/download/${VERSION}"
curl -fsSLO "${base}/install.sh"
curl -fsSLO "${base}/install.sh.sha256"
shasum -a 256 -c install.sh.sha256   # must print: install.sh: OK
less install.sh                      # review before running
sudo bash install.sh
```

Installs the sensor only on any Linux host with Docker (ARM64 and x86_64). The dashboard/control plane is the macOS app and is installed separately on a Mac. The sensor exposes port 8443 with TLS.

### Sensor — macOS (launchd)

Same verify-then-run flow. Requires Python 3.11+. Installs as a launchd agent under `~/.squirrelops/sensor/`.

```bash
VERSION=v1.1.14
base="https://github.com/rocketweb/squirrelops-home/releases/download/${VERSION}"
curl -fsSLO "${base}/install-macos.sh"
curl -fsSLO "${base}/install-macos.sh.sha256"
shasum -a 256 -c install-macos.sh.sha256   # must print: install-macos.sh: OK
less install-macos.sh                       # review before running
bash install-macos.sh
```

Prefer a notarized, code-signed `.pkg` from the Releases page when available, since macOS verifies its signature automatically.

### macOS App

Download from [GitHub Releases](https://github.com/rocketweb/squirrelops-home/releases), or build from source:

```bash
cd app && bash build-app.sh
open .build/arm64-apple-macosx/debug/SquirrelOpsHome.app
```

Requires Swift 6.0 and macOS 14+ (Sonoma).

## Pairing

The app discovers the sensor via mDNS (`_squirrelops._tcp`) and pairs using a one-time 100-bit setup key. The pairing flow:

1. App discovers sensor on the local network
2. Sensor generates a setup key at startup. It is shown in the startup banner and stored as `pairing-key` inside the private sensor data directory (`--show-pairing-code` retrieves it)
3. User enters the setup key in the app, or the installed local app retrieves it through a peer-verified Unix socket
4. App and sensor perform a versioned HMAC-SHA256 transcript proof, then derive a session key with HKDF
5. App generates a CSR, sensor issues a client certificate signed by its CA
6. All subsequent communication uses mutual TLS. The one-time setup key is invalidated after use

The production local-pairing socket accepts only the configured installed SquirrelOps executable after validating both its signature and designated code requirement. `pairing.allow_unsigned_local: true` exists for source development only and reduces the local trust boundary to the logged-in user.

## Development

### Build & Test

```bash
# App (Swift 6, macOS 14+)
cd app && swift build
cd app && swift test

# Sensor (Python 3.11+)
cd sensor && uv run pytest     # 1,669 tests in v1.1.14

# Docker
docker compose -f sensor/docker-compose.yml build
```

### Project Structure

```
app/          SwiftUI macOS app + privileged helper
sensor/       Python sensor and test suite
relay/        APNs push notification relay (Vercel Edge Function)
site/         Distribution site (get.squirrelops.io)
scripts/      Install scripts and tooling
docs/         User guide and documentation
```

### Sensor Module Layout

```
sensor/src/squirrelops_home_sensor/
├── alerts/        Alert dispatch, decoy/device handlers, incident grouping, retention
├── api/           FastAPI routers (8 routers), WebSocket, DI
├── config/        YAML config with env var overrides
├── db/            SQLite schema (v9), migrations
├── decoys/        Decoy orchestrator + types (dev_server, home_assistant, file_share, mimic)
├── devices/       Device manager, classifier, signatures, OUI
├── events/        Pub/sub event bus with audit log
├── fingerprint/   Multi-signal compositor and matcher
├── network/       Virtual IP allocation, port forwarding
├── privileged/    macOS Swift helper RPC, Linux direct ops
├── scanner/       ARP/port/mDNS/SSDP scanning
├── scouts/        Scout engine, scheduler, mimic orchestrator, templates, mDNS
├── secrets/       Keychain, encrypted file storage
└── security/      Port risk analysis, security insights
```

## Design Principles

- **Detection only** — never blocks, throttles, or modifies real network traffic
- **No deep packet inspection** — analysis limited to connection metadata
- **Local-first** — all data in local SQLite, only exceptions are optional APNs/Slack/LLM integrations
- **Decoys never collide** — decoy services avoid real ports and don't respond to broadcast discovery
- **Virtual IPs avoid conflicts** — allocated from high end of subnet, excluded from scan loop, evacuated if a real device claims the IP
- **48-hour learning** — behavioral anomaly alerts are suppressed during learning; decoy trip alerts fire immediately

## License

All rights reserved. Source available for review.
