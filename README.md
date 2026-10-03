# SquirrelOps Home

**Local-first home network security with high-signal deception.**

This README describes the Home 2.1.0 source merged into `main`. The latest published Home
release verified on October 3, 2026 is [2.0.3](https://github.com/rocketweb/squirrelops-home/releases/tag/home-v2.0.3).
The 2.1 guest and UI features below are not included in that released package.

- **Network-aware honeypots:** automatically selects HTTP file-directory, development-server, and Home Assistant-style decoys from discovered service ports, with a file-directory fallback
- **Squirrel Scouts:** probes discovered services and builds fake hosts with one service decoy per observed port, sharing a virtual IP and hostname. HTTP samples and protocol banners provide partial service emulation.
- **Studio Build Mac:** a macOS-shaped target with real OpenSSH and Samba in a disposable Linux guest with no network adapter or host file access, plus synthetic Ollama, OpenAI-compatible, and MCP endpoints
- **Decoy alerts:** unexpected decoy activity produces High alerts; recognized planted-credential use produces Critical alerts. Automatic printer discovery is retained as evidence without an intrusion alert.
- **Device fingerprinting:** discovers reachable devices on the selected IPv4 LAN using ARP, MAC OUI, TCP port probes, and mDNS/SSDP or optional Home Assistant enrichment, with optional AI classification for unresolved devices
- **Believable decoy naming:** fake hosts use ordinary home and business names by default, with optional AI suggestions informed by observed hostname patterns
- **Security insights:** flags risky exposed services and ambiguous ARP ownership, with affected devices grouped by issue
- **Credential bait:** plants synthetic passwords, SSH keys, tokens, and .env files that may contain AWS keys, database URIs, and GitHub PATs. Supported requests that submit recognized bait trigger Critical alerts; downloading a bait file alone produces ordinary decoy activity.
- **Local by default:** inventory and alerts stay in local SQLite; configuration stays in local YAML and an encrypted secret store. Cloud AI and external alert delivery require explicit configuration.
- **macOS notifications:** native Notification Center alerts, menu-bar status, and High/Critical prompts in the paired Mac app, with optional Slack delivery from the sensor
- **Home Assistant integration:** matches HA registry devices by MAC address to enrich names, areas, manufacturers, and models

Passive DHCP capture and automatic connection-baseline learning are not active in
this runtime. APNs sender and relay code exists, but app token registration and an
iPhone client are not implemented. See the [claim verification record](docs/testing/2026-10-02-documentation-claims.md).

## How It Works

SquirrelOps Home runs a sensor on your network that does three things:

1. **Discovers and fingerprints** reachable devices on the selected IPv4 LAN using ARP scanning, TCP port probing, discovery metadata, and IEEE OUI lookups
2. **Deploys decoy services** on available host ports or checked virtual IPs, using HTTP presentations, service samples, and Studio's real SSH/SMB guest
3. **Records decoy activity and raises alerts** for unexpected interactions, recognized credential use, and security findings from scans

The macOS app is your control plane: pair it with the sensor, view your device inventory, manage decoys, configure alerts, and respond to incidents.

```
┌──────────────────────────┐       TLS + WebSocket       ┌──────────────────────────┐
│  macOS App               │◄───────────────────────────►│  Sensor                  │
│  (SwiftUI)               │           REST API          │  (Python/FastAPI)        │
│                          │                             │                          │
│  • Dashboard             │                             │  • ARP/port scanning     │
│  • Device inventory      │                             │  • Device fingerprinting │
│  • Decoy management      │                             │  • Decoy orchestrator    │
│  • Squirrel Scouts       │                             │  • Squirrel Scouts       │
│  • Alert feed            │                             │  • Deep-decoy runtime    │
│  • Settings              │                             │  • Event bus + SQLite    │
└──────────────────────────┘                             └──────────────────────────┘
```

## Architecture

The Python sensor combines active device scanning and classification, a
ClownPeanuts HTTP emulator for classic decoys, Scout fingerprinting and mimic
orchestration, and Studio's synthetic API listeners. A separate unprivileged
Virtualization.framework runtime hosts Studio's OpenSSH and Samba guest.

After pairing, the app and sensor communicate using mutual TLS. Packaged local
enrollment uses the signed helper's XPC service and a Keychain-backed P-256 key;
remote setup-key pairing uses HMAC-SHA256 and HKDF before issuing the client certificate.

The documented trust boundaries and intentional exceptions are in the
[security model](docs/SECURITY_MODEL.md).

### Decoy Types

| Type | What It Mimics | Credential Behavior |
|------|---------------|---------------------|
| File Share | Python-served HTTP directory listing with an nginx-style banner; no SMB or AFP server | `passwords.txt` and a generated RSA private key |
| Dev Server | Static React-style page, `/api/health` JSON, and `/.env`, with Express-style headers | A synthetic `.env` file |
| Home Assistant | Static login form, `/api/` authentication error, and `/auth/token` rejection; no running HA instance | A generated HA-style token recognized if submitted |
| Mimic | Observed HTTP samples, banners, local TLS identity, and mDNS records grouped by source device; partial protocol emulation | Generated bait files on one supported HTTP service per host |
| Studio Build Mac | Real SSH/SFTP and Samba shares in a disposable Linux guest with macOS-shaped content; synthetic model/MCP APIs run in the sensor | Install-specific guest login, API, and source tokens |

The classic decoys do not run nginx, Express, Next.js, or Home Assistant.
Mimic SSH banners do not provide SSH negotiation or a shell. Studio's SSH and
SMB services implement those real protocols. Its Time Machine share advertises
Samba's Apple extensions; a complete Time Machine backup/restore is unverified.
Studio's model and MCP APIs return synthetic data and do not run inference or execute tools.

### Credential Types

The classic credential generator supports these seven formats. Default
deployment uses passwords and SSH keys for File Share, an `.env` file for Dev
Server, and a token detector for Home Assistant. The `.env` file contains a
random subset of secret-like settings; each listed format is not guaranteed
to appear in every deployment.

| Credential | Format |
|------------|--------|
| Password pairs | `username:AdjNoun1234!` (8-12 per decoy) |
| AWS Access Key | `AKIA` + 16 alphanumeric chars |
| Database URI | `postgresql://user:pass@host:5432/db` |
| SSH Private Key | Parseable PEM-formatted RSA-2048 key |
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

The result is a set of grouped fake hosts whose service samples resemble systems
already present on the network. HTTP bait retrieval records a decoy trip;
recognized credential submission raises a Critical alert.

On macOS, these virtual IPs use proxy ARP through the Mac's physical interface. They therefore share its Layer 2 MAC address, and a reverse-DNS lookup may still return the Mac's real hostname. This release improves service-level realism but does not claim to be indistinguishable from a separate physical device to an advanced Layer 2 scan.

### Resource Profiles

The sensor adapts to available resources:

| Profile | Scan Interval | Host-listener Ceiling | Fake-host Ceiling | Classification |
|---------|--------------|----------------|-------------------|----------------|
| **Lite** | 15 min | 3 | Disabled | Local signature DB only |
| **Standard** | 5 min | 3 | Up to 5 | Optional configured AI |
| **Full** | 1 min | 3 | Up to 10 | Optional configured AI |

The ceiling counts fake hosts, not service rows. Squirrel Scouts deploys at most one fake host for each eligible real source device, so a network with six eligible sources produces at most six fake hosts even in Full mode. A multi-port host has one service-decoy row per observed port and can therefore contribute several rows.

## Installation

### Sensor: Linux/NAS (Docker)

Linux publication is currently on hold. The 2.0 tree separates the
unprivileged sensor from a constrained `network-helper` companion. The sensor
uses a private bridge, a fixed non-root identity, a read-only root filesystem,
and no Linux capabilities. Only the helper receives host networking,
`NET_RAW`, and `NET_ADMIN` through a peer-authenticated, allow-listed Unix
socket API.

The separate Sensor publication workflow remains blocked pending that review.
The Home workflow publishes macOS artifacts only. See
[Release security](docs/RELEASE_SECURITY.md).

### macOS App and Sensor

Requires macOS 14 (Sonoma) or later on Apple Silicon (ARM64). Intel Macs are
not supported. This applies to both the macOS app and the native sensor,
including the Home 2.1 release.

Use the signed and notarized `.pkg`. It contains the app, sensor, locked Python
dependencies, and privileged helper. Do not use the old standalone
`install-macos.sh` release asset. That script could fall back to an unpinned
package index when it was separated from the source tree.

```bash
RELEASE_TAG=home-v2.0.3
base="https://github.com/rocketweb/squirrelops-home/releases/download/${RELEASE_TAG}"
curl -fsSLO "${base}/RELEASE-VERIFICATION.md"
gh release verify "$RELEASE_TAG" --repo rocketweb/squirrelops-home
gh attestation verify RELEASE-VERIFICATION.md \
  --repo rocketweb/squirrelops-home \
  --signer-workflow rocketweb/squirrelops-home/.github/workflows/release.yml \
  --signer-digest eb2d87af5e24d924204afb4f2c0bcbd7403ac559 \
  --source-digest eb2d87af5e24d924204afb4f2c0bcbd7403ac559 \
  --source-ref refs/heads/main
```

Then follow the verified document to download the package and checksum, verify
the package attestation, Developer ID signature and notarization, and install.
The published 2.0.3 metadata and GitHub asset digest agree on package SHA-256
`252bd6bd559b4dbf578410aa959611675d3b627163ee885f404857cb67ab23f8`.
GitHub's release description is editable and is only a convenience pointer.

The source-checkout-only `scripts/install-macos.sh` remains available for
development. It requires the local `sensor/uv.lock`, exact `uv` version, and
fails closed if the locked source project is absent.

### macOS App

Download from [GitHub Releases](https://github.com/rocketweb/squirrelops-home/releases), or build from source:

```bash
cd app && bash build-app.sh
open "$(bash build-app.sh --print-bundle-path)"
```

For the supported Apple Silicon (ARM64) build, use Swift 6.0 and macOS 14+
(Sonoma). The source build options do not extend the supported Mac hardware.
Use the same SDK and scratch-directory options for building and querying the
bundle. See the [documented macOS 27 toolchain caveat](docs/DEVELOPMENT.md#macos-27-development-tool-caveat).

To use Studio Build Mac from source, first build its ARM64 guest with Docker
Buildx as described in [Studio Mini guest setup](docs/DEVELOPMENT.md#studio-mini-guest).
A debug app can build without the guest, but Studio will be unavailable;
release builds require the validated guest bundle.

## Pairing

Packaged local setup normally enrolls through the signed helper without a setup
key. Remote sensors are discovered via mDNS (`_squirrelops._tcp`) and use a
one-time 100-bit setup key. The remote pairing flow:

1. App discovers sensor on the local network
2. Sensor generates a setup key at startup. It is shown in the startup banner and stored as `pairing-key` inside the private sensor data directory (`--show-pairing-code` retrieves it)
3. User retrieves the setup key with the administrator-only packaged command and enters it in the app
4. App and sensor perform a versioned HMAC-SHA256 transcript proof, then derive a session key with HKDF
5. App generates a CSR, sensor issues a client certificate signed by its CA
6. All subsequent communication uses mutual TLS. The one-time setup key is invalidated after use

Packaged installs do not expose the setup key over a local socket. Process
identity checks cannot prove which process is using a connected descriptor
after file-descriptor passing. `pairing.allow_unsigned_local: true` enables a
source-development-only socket and reduces the local trust boundary to the
logged-in user.

## Development

### Build & Test

```bash
# App (Swift 6, macOS 14+)
(cd app && swift build && swift test)

# Sensor (Python 3.11+)
(cd sensor && uv run pytest)

# Docker source build; Linux publication remains blocked
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
├── api/           FastAPI HTTP routers, WebSocket, dependency injection
├── config/        YAML config with env var overrides
├── db/            SQLite schema (v12), migrations
├── decoys/        Classic, mimic, and isolated deep-decoy orchestration
├── devices/       Device manager, classifier, signatures, OUI
├── events/        Pub/sub event bus with audit log
├── fingerprint/   Multi-signal compositor and matcher
├── network/       Virtual IP allocation, port forwarding
├── privileged/    macOS helper RPC and constrained Linux sidecar RPC
├── scanner/       ARP/port/mDNS/SSDP scanning
├── scouts/        Scout engine, scheduler, mimic orchestrator, templates, mDNS
├── secrets/       Keychain, encrypted file storage
└── security/      Port risk analysis, security insights
```

## Design Principles

- **Detection:** scans and decoys help investigate activity without blocking real devices
- **Bounded observation:** no passive inspection of unrelated traffic; Scout probes read service samples and decoys inspect requests sent to them
- **Local storage:** SQLite inventory and evidence, YAML configuration, and encrypted configuration secrets
- **Scoped listeners:** classic decoys use available host ports; fake hosts publish mDNS services on isolated virtual addresses
- **Conflict handling:** virtual addresses are checked before allocation, excluded from inventory, and evacuated when an active real device claims them. Reserve the pool outside DHCP; sleeping devices can still conflict.
- **Immediate decoy detection:** decoy alerts do not depend on a learning period; automatic baseline collection is not connected to the runtime

## License

SquirrelOps Home is source-available under the [PolyForm Noncommercial 1.0.0
license](LICENSE). Bundled third-party components retain their respective licenses;
see [third-party distribution notes](docs/THIRD_PARTY.md).
