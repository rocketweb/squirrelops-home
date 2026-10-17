# macOS 27 sensor startup repair

Date: September 25, 2026. Host: Matt's arm64 Mac Studio, macOS 27.0 (26A428).

## Status

The installer-only recovery package installed successfully, but its sensor
exited before opening HTTPS. A second, runtime repair candidate is built and
locally tested. **The runtime repair is not installed or live-accepted yet.**
Installation approval was requested. Do not equate the passing tests below
with a working installed app or with second-machine decoy ingress.

## Confirmed cause

Privileged sensor logs show repeated startup exits:

```text
Auto-detected subnet: 100.96.4.0/24 (from local IP 100.96.4.79)
Could not verify the private IPv4 default route (route status 0)
RuntimeError: Could not install startup quarantine for persisted virtual IPs
```

The global IPv4 default points to VPN interface `utun12`, with no gateway in
the route response. The sensor's UDP-based Internet-route discovery selected
the VPN address. The helper correctly refused that route as LAN authority.
Startup then aborted before the HTTPS server, leaving both localhost address
families unreachable. App logs confirmed connection refusal, not a TLS or
pairing error. Importing the installed Python runtime and sensor succeeded.

Read-only physical-network checks found:

| Observation | Value |
| --- | --- |
| macOS first physical network service | Ethernet, `en0` |
| Interface-scoped IPv4 gateway | `192.168.1.1` |
| Physical LAN address | `192.168.1.18` |
| Physical LAN subnet | `192.168.1.0/24` |
| Additional physical interface | Wi-Fi, `en1`, `192.168.1.79` |

This proves a VPN/LAN-selection defect on this machine. It does not establish
that macOS 27 introduced the networking defect. The separate SQLite installer
failure and recovery are documented in `2026-09-25-macos27-installer-recovery.md`.

## Repair boundary

- The helper prefers an ordinary physical IPv4 default. If a VPN owns that
  default, it checks physical Ethernet/Wi-Fi interfaces in macOS service order.
  A fallback needs a matching scoped route, hardware address, RFC1918 address,
  unambiguous on-link gateway, and a subnet allowed by the existing ARP policy.
- A read-only, authenticated `getLANContext` RPC gives the sensor that same
  interface, address, subnet, and gateway before database/background startup.
- Scanning, classic/mimic decoy publication, allocation, and sensor mDNS use the
  verified physical LAN. Explicit conflicting configuration fails closed.
  Runtime discovery does not change persisted `auto` settings.
- Both privileged mutation checkpoints re-observe the selected LAN. Existing
  ownership, conflict, backend-listener, PF quarantine, and route-change checks
  remain in place. No VPN setting, system default route, bait, banner, protocol
  response, or guest isolation policy is changed.
- macOS 27 `pkgbuild --analyze` omits `BundleIsRelocatable`. The normal builder
  now uses `plutil -replace` to insert or replace that key with false. The old
  `PlistBuddy Set` failure was reproduced before this change.

## Verification

The engineering-constraints skill drove red-before-green regression testing.
Before the helper fix, the exact no-gateway VPN fixture threw the same error
as the installed sensor. An RFC1918 VPN gateway fixture incorrectly selected
the tunnel. Both pass after the repair; malformed/off-link cases fail closed.

- Full sensor suite: **2,229 passed, 1 skipped** in 83.75 seconds. The skip is
  the existing opt-in live guest test; this run is not guest/LAN acceptance.
- Helper suite: **111 tests passed**, including live read-only LAN observation.
  The new helper selected `en0`, `192.168.1.18`, `192.168.1.0/24`, gateway
  `192.168.1.1` while the VPN remained enabled.
- Tests against the exact extracted installer sensor: **199 passed**. This
  includes entry-point startup, settings routes, helper RPC, LAN-context,
  configuration persistence, package security, SQLite backup, and plist cases.
- Ruff, shell syntax, and `git diff --check` passed.
- Fresh package extraction matches staged app and sensor payload bytes.
  Extracted sensor source matches the worktree source (excluding Python caches).
  Strict deep app signature verification and guest manifest verification pass.

Evidence logs are under `build/test-artifacts/macos27-lan-*.log`.

Commands used from the candidate worktree:

```bash
cd sensor
.venv/bin/python -m pytest -q --tb=short
cd ../app
DEVELOPER_DIR=/Library/Developer/CommandLineTools \
  swift build --target SquirrelOpsHelperTests \
  -Xswiftc -plugin-path \
  -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing
SQUIRRELOPS_TEST_LIVE_LAN=1 \
DYLD_FRAMEWORK_PATH=/Library/Developer/CommandLineTools/Library/Developer/Frameworks \
DYLD_LIBRARY_PATH=/Library/Developer/CommandLineTools/Library/Developer/usr/lib \
/Library/Developer/CommandLineTools/usr/libexec/swift/pm/swiftpm-testing-helper \
  --test-bundle-path .build/out/Products/Debug/SquirrelOpsHelperTests.xctest/Contents/MacOS/SquirrelOpsHelperTests \
  --testing-library swift-testing
DEVELOPER_DIR=/Library/Developer/CommandLineTools \
  swift build --build-system native -c release --product SquirrelOpsHelper
```

The Command Line Tools can build and test the helper. They cannot build the
unchanged SwiftUI app here because the macOS 27 SDK references a missing
`SwiftUIMacros` plugin. Full Xcode also requests license acceptance; no license
was accepted. The full-app Swift suite therefore was not re-run. The standalone
helper test runner above avoids claiming that a partially failed all-target
Swift test invocation passed.

## Exact candidate

[SquirrelOpsHome-2.1.0-macos27-lan-repair-20260925-local-test.pkg](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/build/test-artifacts/SquirrelOpsHome-2.1.0-macos27-lan-repair-20260925-local-test.pkg)

- Version: 2.1.0, arm64, unsigned installer with ad-hoc-signed app components.
- SHA-256: `cedb1b1f0170e07e19447c2e8e82ebe849c42f478cffeeb5faaec5a5dc3b0c02`.
- Not notarized, publicly released, committed, or pushed.
- Contains a rebuilt helper and updated sensor `__main__.py`,
  `privileged/xpc.py`, and `privileged/helper.py`.
- Retains the prior app executable code, guest image/runtime, dependencies,
  fixed SQLite preinstall, and local-test credential namespace. App components
  are re-signed to seal the updated helper.
- Build recipe: `build/test-artifacts/build-macos27-lan-repair.sh`.

The package builder emits `write: Permission denied` warnings even when run
outside the sandbox. Both resulting payloads were fully compared with their
staging trees, and the extracted app passes strict deep signature verification.
Those checks pass, but successful installation is still a separate gate.

## Pending installed acceptance

1. Obtain permission to install this exact local test package. Preserve a copy
   of the installed app/helper before running the installer because the legacy
   app preinstall can remove the app before the sensor rollback snapshot exists.
2. Create the one-time root-owned local-test opt-in, run the installer, and
   record its exit status and private rollback snapshot location.
3. Leave the VPN enabled. Confirm startup logs select `en0`, the sensor stops
   crash-looping, and HTTPS is actually listening on port 8443.
4. Open the installed app and verify authenticated health plus successful
   Settings loading. Do not export pairing private keys to run API checks.
5. Confirm devices/history remain present and inspect Studio/decoy status.
   LAN SSH/SMB access and host-service isolation still need separate acceptance
   from a second authorized LAN machine; local unit tests cannot prove them.

No live installation, service restart, configuration edit, database edit, VPN
change, or global route change was performed while preparing this candidate.
