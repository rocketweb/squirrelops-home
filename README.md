# SquirrelOps Home

**Local-first home network security with zero-false-positive deception.**

- **Honeypots that blend in** — auto-deploys realistic decoy services (file shares, dev servers, Home Assistant instances) based on what's actually on your network
- **Squirrel Scouts** — deep service fingerprinting that builds mimic decoys cloned from real devices, deployed across virtual IPs with spoofed mDNS hostnames so your network looks bigger and more diverse to intruders
- **Zero false positives** — legitimate devices never touch decoys, so every alert means something
- **Device fingerprinting** — identifies every device on your network using MAC OUI, mDNS, SSDP, DHCP, and port signatures, with optional LLM-powered classification
- **Behavioral baselines** — learns normal connection patterns during a 48-hour training period, then alerts on anomalies
- **Credential canaries** — plants realistic-looking credentials (AWS keys, SSH keys, .env files, database configs) that trigger alerts when accessed
- **Completely local** — all data stays in a local SQLite database. No cloud. No telemetry. No accounts.
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

| Type | What It Mimics |
|------|---------------|
| File Share | SMB/NFS share with enticing filenames |
| Home Assistant | Fake HA instance with realistic API responses |
| Dev Server | Node.js/Python dev server with debug endpoints |
| **Mimic** | **Cloned from real devices — same HTTP responses, headers, TLS certs, protocol banners, mDNS hostnames** |
| DNS Canary | Internal DNS records that resolve to monitored IPs |
| Credential Artifacts | AWS keys, SSH keys, .env files, kubeconfig, database URIs, GitHub tokens, Docker registry creds |

### Squirrel Scouts

Squirrel Scouts is an optional subsystem that makes the deception layer significantly more convincing:

1. **Scout Engine** probes every open port on every discovered device to capture what an intruder would see — HTTP responses, TLS certificates, SSH version strings, mDNS service types
2. **Mimic Templates** are generated from scout data: route configs that replicate real device responses with planted credentials injected into realistic locations
3. **Virtual IPs** are allocated from unused addresses in your subnet (.200-.250 range) using interface aliases, so mimic decoys appear as distinct physical devices
4. **Port Forwarding** (pfctl on macOS, iptables on Linux) redirects privileged ports (22, 80, 443) to high ports where the unprivileged mimic servers bind
5. **mDNS Hostnames** are registered via zeroconf with device-appropriate names (e.g., `tapo-plug-A3F2`, `synology-ds-B1C8`), so Bonjour/mDNS discovery shows plausible device names

The result: a network scan from an intruder's perspective reveals more devices than actually exist, each responding with realistic service fingerprints and containing planted credentials that trigger alerts when used.

### Resource Profiles

The sensor adapts to available resources:

| Profile | Scan Interval | Max Decoys | Max Mimics | Scout Interval | Classification |
|---------|--------------|------------|------------|----------------|----------------|
| **Lite** | 15 min | 3 | 0 | Disabled | Local signature DB only |
| **Standard** | 5 min | 8 | 10 | 60 min | Cloud LLM (your API key) |
| **Full** | 1 min | 16 | 30 | 30 min | Local LLM (LM Studio/Ollama) |

## Installation

### Sensor — Linux/NAS (Docker)

```bash
curl -fsSL https://get.squirrelops.io/install.sh | sh
```

Runs on any Linux host with Docker (ARM64 and x86_64). Exposes port 8443 with TLS.

### Sensor — macOS (launchd)

```bash
curl -fsSL https://get.squirrelops.io/install-macos.sh | sh
```

Requires Python 3.11+. Installs as a launchd user agent at `~/.squirrelops/sensor/`.

### macOS App

Download from [GitHub Releases](https://github.com/rocketweb/squirrelops-home/releases), or build from source:

```bash
cd app && bash build-app.sh
open .build/arm64-apple-macosx/debug/SquirrelOpsHome.app
```

Requires Swift 6.0 and macOS 14+ (Sonoma).

## Pairing

The app discovers the sensor via mDNS (`_squirrelops._tcp`) and pairs using a 6-digit code displayed on the sensor. The pairing flow:

1. App discovers sensor on the local network
2. Sensor displays a pairing code
3. App and sensor perform HKDF key derivation with challenge-response
4. App generates a CSR, sensor issues a client certificate signed by its CA
5. All subsequent communication uses mutual TLS

## Development

### Build & Test

```bash
# App (Swift 6, macOS 14+)
cd app && swift build
cd app && swift test           # 245 tests

# Sensor (Python 3.11+)
cd sensor && uv run pytest     # 730 tests

# Docker
docker compose -f sensor/docker-compose.yml build
```

### Project Structure

```
app/          SwiftUI macOS app + privileged helper (53 Swift files)
sensor/       Python sensor (86 source files, 40 test files)
relay/        APNs push notification relay (Vercel Edge Function)
site/         Distribution site (get.squirrelops.io)
scripts/      Install scripts and tooling
docs/         User guide and documentation
```

### Sensor Module Layout

```
sensor/src/squirrelops_home_sensor/
├── alerts/        Alert dispatch, incident tracking, retention
├── api/           FastAPI routers (8 routers), WebSocket, DI
├── config/        YAML config with env var overrides
├── db/            SQLite schema (v6, 18 tables), migrations
├── decoys/        Decoy orchestrator + types (dev_server, home_assistant, file_share, mimic)
├── devices/       Device manager, classifier, signatures, OUI
├── events/        Pub/sub event bus with audit log
├── fingerprint/   Multi-signal compositor and matcher
├── network/       Virtual IP allocation, port forwarding
├── privileged/    macOS Swift helper RPC, Linux direct ops
├── scanner/       ARP/port/mDNS/SSDP/DNS scanning
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
