# SquirrelOps Home — Development Guide

Local development setup for working on the sensor, macOS app, and privileged helper.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| macOS | 14 (Sonoma)+ | — |
| Xcode | 16+ | Mac App Store or `xcode-select --install` |
| Python | 3.11+ | `brew install python@3.11` |
| uv | latest | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |

---

## Repository Structure

```
squirrelops-home/
├── app/            Swift macOS app + privileged helper (Package.swift)
├── sensor/         Python sensor package (pyproject.toml)
├── scripts/        Build, install, and signing scripts
├── docs/           Documentation
├── site/           Update site and manifest
└── VERSION         Single source of truth for version number
```

---

## First-Time Setup

### 1. Install the Privileged Helper

The packaged sensor delegates privileged operations to a Swift helper daemon that runs as root. The helper accepts RPC only from root and the dedicated `_squirrelops` service account. A sensor run directly as your login user cannot use the helper, so ARP scanning, virtual IP aliases, and port forwarding are unavailable in that mode and are reported as unavailable.

```bash
sudo bash scripts/dev-install-helper.sh
```

This builds the helper from `app/` via Swift Package Manager and installs it as a system launchd daemon for root-level RPC testing. Full end-to-end helper testing requires the `.pkg` service account setup:

| Item | Path |
|------|------|
| Binary | `/Library/PrivilegedHelperTools/com.squirrelops.helper` |
| Launchd plist | `/Library/LaunchDaemons/com.squirrelops.helper.plist` |
| Socket | `/var/run/squirrelops-helper.sock` |
| Logs | `/var/log/com.squirrelops.helper.log` |

The helper starts immediately and persists across reboots (`KeepAlive: true`).

To update after changing helper source code:

```bash
sudo bash scripts/dev-install-helper.sh
```

To remove:

```bash
sudo bash scripts/dev-install-helper.sh --uninstall
```

### 2. Install Sensor Dependencies

```bash
cd sensor
uv sync
```

---

## Running Locally

### Sensor

```bash
cd sensor
uv run python -m squirrelops_home_sensor --port 8443
```

The sensor uses the config at `sensor/data/config.yaml` and stores its SQLite database in `sensor/data/`.

Useful flags:

| Flag | Description |
|------|-------------|
| `--port 8443` | API port (default 8443) |
| `--config path/to/config.yaml` | Custom config file |
| `--no-tls` | Disable TLS and force a loopback-only bind (for quick testing) |

### macOS App

```bash
cd app
bash build-app.sh
open .build/$(uname -m)-apple-macosx/debug/SquirrelOpsHome.app
```

> **Note:** Debug builds skip `SMAppService` helper registration (requires code signing). Use `dev-install-helper.sh` instead — see [First-Time Setup](#1-install-the-privileged-helper).

### Running Tests

```bash
cd sensor
uv run pytest tests/ -q    # ~1258 tests
```

Run a specific test file or class:

```bash
uv run pytest tests/unit/test_mimic_server.py -q
uv run pytest tests/unit/test_scout_engine.py::TestGetMimicCandidates -q
```

---

## Architecture: Privileged Helper

The helper (`SquirrelOpsHelper`) is a Swift binary that runs as root via launchd. It listens on a Unix domain socket and speaks JSON-RPC 2.0.

```
┌──────────────────────┐         JSON-RPC / Unix socket
│  Python Sensor       │ ─────────────────────────────────►  ┌──────────────────┐
│  (runs as _squirrelops)│  /var/run/squirrelops-helper.sock │  SquirrelOpsHelper│
│                      │ ◄─────────────────────────────────  │  (runs as root)  │
└──────────────────────┘                                     └──────────────────┘
```

**RPC methods:**

| Method | Purpose |
|--------|---------|
| `runARPScan` | Discover devices on the subnet via ARP |
| `addIPAlias` | Publish an isolated virtual IP with a loopback /32 and scoped proxy ARP |
| `removeIPAlias` | Remove virtual IP alias |
| `setupPortForwards` | Configure pfctl rdr rules for privileged ports |
| `clearPortForwards` | Remove pfctl rules |

**Why a helper?** macOS requires root for raw sockets (ARP), `ifconfig` alias manipulation, and `pfctl` rules. Rather than running the entire sensor as root, only the helper runs privileged. Its socket is `root:_squirrelops` mode `0660`, and peer credentials are checked again after connection.

TCP service scanning on macOS uses bounded, unprivileged connections directly
from the Python sensor. Passive DNS capture is not currently supported on
macOS and is not advertised by the helper.

**On Linux/Docker**, the sensor runs as root with `CAP_NET_RAW` and `CAP_NET_ADMIN`, so it performs these operations directly using scapy and iptables. No helper needed.

---

## Debugging

### Helper not responding

```bash
# Check if the daemon is loaded
sudo launchctl print system/com.squirrelops.helper

# Check if the socket exists
ls -la /var/run/squirrelops-helper.sock

# View helper logs
tail -f /var/log/com.squirrelops.helper.log

# Restart the helper
sudo launchctl kickstart -k system/com.squirrelops.helper

# Reinstall from source
sudo bash scripts/dev-install-helper.sh
```

### Test helper connectivity manually

```bash
echo '{"jsonrpc":"2.0","method":"runARPScan","params":{"subnet":"192.168.1.0/24"},"id":1}' \
  | sudo nc -U /var/run/squirrelops-helper.sock
```

### Sensor shows 0 devices

The helper isn't running or isn't reachable. Check the socket and helper logs as above.

### Fill Capacity returns `{"deployed": 0}` or 503

- **503 with "Privileged helper is not running"**: Helper isn't installed. Run `dev-install-helper.sh`.
- **200 with `{"deployed": 0}`**: No eligible unrepresented source devices. Run scouts first to refresh service profiles, then use Fill Capacity.

### Sensor warnings about virtual IP alias failures

```
Failed to add IP alias 192.168.1.200 on en0
```

The helper isn't running or can't execute `ifconfig`. Reinstall and check logs.

---

## Build Pipeline

### Local builds

| Target | Command |
|--------|---------|
| Sensor (editable) | `cd sensor && uv sync` |
| App (debug) | `cd app && bash build-app.sh` |
| App (release) | `cd app && BUILD_CONFIG=release bash build-app.sh` |
| Installer (.pkg) | `bash scripts/build-pkg.sh` |

### Release workflow

Releases are triggered by pushing a `v*` tag. The GitHub Actions workflow (`.github/workflows/release.yml`) handles:

1. Verifying the tag, `VERSION`, sensor package version, and install-script version agree
2. Building and publishing the multi-architecture sensor container
3. Building the `.pkg` installer with the app, sensor, and privileged helper
4. Code signing, Apple notarization, stapling, and Gatekeeper verification
5. Creating the GitHub Release with the installer, checksums, and install scripts
6. Updating `site/public/manifest.json` for app and sensor update checks

Release builds fail closed if signing or notarization credentials are missing.
Before tagging a release:

```bash
# Update VERSION, sensor/pyproject.toml, sensor/uv.lock, scripts/install.sh,
# site/public/install.sh, PreviewData, documentation, and release notes.
git diff --check
cd sensor && uv lock --check && uv run pytest && uv run ruff check .
cd ../app && swift test
cd ..

# Confirm main is current, then create the immutable release tag.
git fetch origin
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
git tag -a vX.Y.Z -m "SquirrelOps Home X.Y.Z"
git push origin vX.Y.Z
```

After the workflow completes, verify the release assets, package digest,
notarization result, update manifest, and the published GHCR image before
announcing the release.
