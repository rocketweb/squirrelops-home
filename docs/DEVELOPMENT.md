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
├── VERSION         Home distribution version
└── APP_VERSION     macOS app version
```

The sensor version is independently authoritative in `sensor/pyproject.toml`.
Compatibility is determined by explicit API and helper protocol versions, not
by requiring component version strings to match.

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
open "$(bash build-app.sh --print-bundle-path)"
```

> **Note:** Debug builds skip `SMAppService` helper registration (requires code signing). Use `dev-install-helper.sh` instead — see [First-Time Setup](#1-install-the-privileged-helper).

### Running Tests

```bash
cd sensor
uv run pytest tests/ -q    # More than 2,100 tests
```

Run a specific test file or class:

```bash
uv run pytest tests/unit/test_mimic_server.py -q
uv run pytest tests/unit/test_scout_engine.py::TestGetMimicCandidates -q
```

---

## Architecture: Privileged Helper

The helper (`SquirrelOpsHelper`) is a Swift binary that runs as root via
launchd. It exposes two independent local channels:

| Caller | Channel | Authorization | Scope |
|--------|---------|---------------|-------|
| Python sensor | `/var/run/squirrelops-helper.sock` JSON-RPC | root or `_squirrelops` peer UID | Fixed privileged network operations |
| Signed macOS app | `com.squirrelops.helper.enrollment` XPC Mach service | Release app identifier, Team ID, Apple anchor, and console UID; exact root-installed app CDHash for explicit local tests | Forward one bounded CSR to the local sensor |

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

The app never receives access to the network-operation RPC channel. For local
enrollment it generates a Keychain-backed private key, sends a CSR through the
signed-app XPC service, and confirms the pending certificate over mutual TLS.
The app pins the helper's Developer ID requirement before resuming that XPC
connection; an explicit local-test package pins the exact root-installed helper
CDHash instead.
The sensor enrollment socket is not an HTTP or LAN listener and accepts only a
root peer. A source-built app cannot satisfy the production code-signing
requirement, so use the setup-key flow for ordinary source development. The
explicit local-test package is a separate controlled path: the package pins
its installed ad-hoc app requirement and assigns each build a fresh Keychain
namespace so it cannot trigger access prompts for an earlier build's private
keys.

TCP service scanning on macOS uses bounded, unprivileged connections directly
from the Python sensor. Passive DNS capture is not currently supported on
macOS and is not advertised by the helper.

PF development tests use injected command runners and `pfctl -n` for syntax
validation. They do not load rules. `PFListenerGuardTests` covers translation
tags, socket-owner UID checks, failed quarantine writes, state-cleanup retries,
and UID changes. The native CLT test runner needs an absolute test-bundle path
for app resource lookup. Current commands, results, and the separate live-PF
acceptance gate are in the [PF safety record](testing/2026-09-26-pf-safety-development.md).

**On Linux/Docker**, the source Compose configuration runs the sensor as an
unprivileged UID on a private bridge with all capabilities dropped. Only the
constrained `network-helper` sidecar uses host networking and
`CAP_NET_RAW`/`CAP_NET_ADMIN`. Linux publication remains blocked pending
independent review of that boundary; see [Release security](RELEASE_SECURITY.md).

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

#### macOS 27 development-tool caveat

On the reviewed macOS 27.0 build (26A428), the available CLT macOS 27 SDK
referenced an unavailable SwiftUI macro plugin. The installed macOS 26.5 SDK
successfully compiled the app, helper, guest runtime, and all test targets:

```bash
cd app
DEVELOPER_DIR=/Library/Developer/CommandLineTools swift build \
  --sdk /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
  --scratch-path .build/ui-refresh --build-tests \
  -Xswiftc -plugin-path \
  -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing
```

Both build scripts now resolve the output with `swift build --show-bin-path`
using the same configuration, architecture, SDK, and scratch directory as the
compilation. They do not fall back to an older output directory. To assemble a
release app with the SDK verified on this Mac, run from the repository root:

```bash
DEVELOPER_DIR=/Library/Developer/CommandLineTools \
SQUIRRELOPS_SWIFT_SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
SQUIRRELOPS_SWIFT_SCRATCH_PATH=.build/final-readiness-release \
BUILD_CONFIG=release bash app/build-app.sh
```

`SQUIRRELOPS_SWIFT_SDK` is optional; the selected toolchain's default SDK remains
the default. `SQUIRRELOPS_SWIFT_SCRATCH_PATH` defaults to `app/.build`; relative
values are resolved from `app/`. To query an existing build without rebuilding
or signing it, use the same environment with
`bash app/build-app.sh --print-bundle-path`. The package builder uses this query
and inherits both options. Preserve needed previous package artifacts before
running it: `build-pkg.sh` cleans `build/pkg`.

The local release app bundle was built successfully with these options. That
does not establish signed-installer or upgrade acceptance. Do not substitute a
stale app from another directory or disable package checks. See the
[2.1 readiness report](testing/2026-09-26-final-installer-readiness.md) for current
test evidence and remaining acceptance gates. Xcode license acceptance is a
separate operator action; these tests did not accept it.

### Studio Mini guest

The deep-decoy guest is an architecture-specific release input. Build it with
Docker Buildx, then pass the exact directory to the app builder:

```bash
bash guest/studio-mini/build-guest.sh "$(uname -m)"
python3 scripts/verify-guest-bundle.py \
  "guest/studio-mini/build/$(uname -m)" \
  --architecture "$(uname -m)"
SQUIRRELOPS_GUEST_BUNDLE="guest/studio-mini/build/$(uname -m)" \
  bash app/build-app.sh
```

Release builds additionally require `ALPINE_IMAGE` to use an exact image
digest. `guest/studio-mini/packages.lock` pins the complete installed package
inventory, and the build fails when either architecture resolves a different
version set. Update that inventory only after reviewing the repository change
and rebuilding both architectures from the same image digest. The Home release
workflow builds both ARM64 and x86_64 guest bundles on Linux, downloads them
into the macOS job, selects the package architecture, and validates the copied
app resource before signing.

For a local live acceptance, build the guest and the debug app as shown above,
then run the opt-in test. The debug app builder ad-hoc signs the nested runtime
with only `app/entitlements/deception-guest.entitlements`; release signing is a
separate Developer ID step.

```bash
cd sensor
SQUIRRELOPS_DECEPTION_RUNTIME="$(BUILD_CONFIG=debug bash ../app/build-app.sh --print-bundle-path)/Contents/Library/Helpers/com.squirrelops.deception-guest" \
SQUIRRELOPS_GUEST_BUNDLE=../guest/studio-mini/build/arm64 \
uv run pytest tests/integration/test_deep_deception_live_guest.py -q -s
```

When querying either bundle path, keep the same SDK, scratch directory,
architecture, and toolchain environment used for its build.

This opt-in test boots the real VM, authenticates an install-specific SSH
login, runs the macOS persona commands, exercises SFTP read and write behavior,
and uses a real SMB client to list shares and read, write, and delete a bounded
file through Samba. It also verifies that a host-only canary is absent, the
guest exposes no network interface beyond loopback, and both relayed protocols
emit connection telemetry. The SMB client is a development-only dependency and
does not enter the sensor distribution.

The same test checks SMB responses after a client write-side half-close,
repeated authenticated SSH and SMB close-and-reconnect cycles beyond the
16-slot pool size, and clean runtime exit while both protocol sockets are open. It uses loopback
listeners in a disposable VM, not the installed sensor or its virtual IPs.
`SocketRelayTests` separately exercises deterministic delayed workers,
exact-once descriptor/lease release, cancellation, and concurrent byte parity.
See the [relay/control fix report](testing/2026-09-26-relay-control-fixes.md)
for the current candidate's results and limitations.

Cross-device Finder and `smbutil` acceptance through the production virtual IP
and packet-filter rules, Time Machine discovery, Bonjour discovery from another
LAN device, and signed-package containment remain mandatory manual deception
review checks before a release is approved.

An explicit local-test package requires `SQUIRRELOPS_LOCAL_TEST_BUILD=1` and
the one-time root-owned opt-in printed by the builder. The build writes a UUID
into the app's local-test marker. That UUID is used only to isolate test
Keychain items. Release builds have no marker and continue to use the stable
`io.squirrelops.home` Keychain service.

The local-test marker also tells the helper to bind its enrollment Mach service
to the exact designated requirement of the root-owned app in `/Applications`.
The helper fails closed if that requirement is not a single ad-hoc `cdhash`, or
if the installed bundle or marker can be changed by a non-root user. Release
packages always use the fixed Developer ID requirement.

The sensor package postinstall allows up to 45 seconds to observe either two
valid health responses or one stable launchd-owned sensor PID. Persisted mimic
recovery can exceed macOS's 600-second component-script limit, so it continues
under launchd after that verified handoff. Do not increase the script wait to
cover decoy count. Doing so can make an otherwise healthy upgrade fail when
PackageKit terminates the script.

The Build Local Sensor setup view treats that handoff as initialization, not a
failure. It probes localhost every three seconds for up to 20 minutes, displays
exact elapsed time, and pairs as soon as the authenticated API is available.
Keep the timeout policy in `LocalSensorStartupPolicy` so setup tests can verify
the boundary without sleeping. The view must retain the remote-sensor path
while local recovery is in progress.

The source Linux Compose file deliberately has no guessed LAN. Set the directly
connected private CIDR explicitly before using it:

```bash
cd sensor
SQUIRRELOPS_SUBNET=192.168.1.0/24 docker compose up
```

### Release workflow

Releases are manual deployments from protected `main`. Pushing a tag does not
run publication code. The workflow requires the operator to enter an existing
protected tag and its full commit SHA, then verifies both against `main`.

Every publishing job uses the protected `release` environment. Component
identity and distribution releases are intentionally separate:

1. A protected `app-vX.Y.Z` tag identifies the exact app component source.
2. When Linux publication is independently approved, `Release Sensor` verifies
   `sensor-vX.Y.Z`, builds and attests the multi-architecture image, and publishes
   the digest-pinned Linux installer. Until then, the sensor tag identifies the
   component embedded in Home; it does not authorize Linux publication.
3. `Release Home Distribution` verifies `home-vX.Y.Z`, confirms that the
   embedded app and sensor source exactly match their existing component tags,
   and builds the signed and notarized macOS package.
4. Both paths check that their component version sources, GitHub-verified
   signed tag, commit, and protected `main` agree.
5. Both require release immutability, the pinned reviewed tag-ruleset revision,
   and the independently reviewed release environment
6. Each generates `SHA256SUMS`, component release metadata, canonical verification
   instructions, and, for Home releases, the exact
   `squirrelops-home.rb` Homebrew cask candidate
7. Each uploads and attests every asset on a draft release
8. Each verifies GitHub's asset digests and publishes the immutable release last

The workflow does not publish the source-only macOS installer, use PyPI, write
to `main`, update the website, or update a Homebrew tap. GitHub's editable
release description only points readers to the checksummed and attested
`RELEASE-VERIFICATION.md` asset. Website and Homebrew changes are separate
reviewed pull requests based on `release-metadata.json` and the attested cask
candidate.

Release builds fail closed if signing, notarization, immutability, or
environment approval is missing. Configure all controls in
[Release security](RELEASE_SECURITY.md) before tagging a release.

Before tagging:

```bash
# Update only the versions whose shipped components changed:
# VERSION (Home distribution), APP_VERSION, sensor/pyproject.toml,
# sensor/uv.lock, scripts/install.sh, PreviewData, documentation, and notes.
git diff --check
cd sensor && uv lock --check && uv run pytest && uv run ruff check .
cd ../app && swift test
cd ..

# Confirm main is current, then create the applicable protected signed tag.
git fetch origin
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
git tag -s app-vX.Y.Z -m "SquirrelOps Home App X.Y.Z"
git push origin app-vX.Y.Z
git tag -s sensor-vX.Y.Z -m "SquirrelOps Home Sensor X.Y.Z"
git push origin sensor-vX.Y.Z
# After applicable component identity and release gates are verified:
git tag -s home-vX.Y.Z -m "SquirrelOps Home X.Y.Z"
git push origin home-vX.Y.Z
```

Do not dispatch `Release Sensor` while Linux publication is blocked. The Home
workflow verifies both component tags but does not publish a Linux image.
When both publication paths are approved and needed, verify the Sensor release
before dispatching Home.
After publication, verify each immutable release and attestation. Verify the
package digest and notarization for Home releases and the GHCR digest for
sensor releases before opening website and Homebrew promotion pull requests.
