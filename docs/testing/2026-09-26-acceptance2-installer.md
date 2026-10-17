# Home 2.1 candidate 2: installer and test record

Date: 2026-09-26. Status: **built and locally verified for upgrade testing**.
Not installed, notarized, or published. This is not final public-release approval.

**Source has advanced since this package.** Neither the
[first code-review fix batch](2026-09-26-code-review-fixes.md) nor
[batch 2](2026-09-26-pf-safety-development.md) is included in
candidate 2. Its checksum and results below remain valid historical evidence
for that exact artifact, not verification of the newer source. A5's PF changes
still need live acceptance; no replacement installer was built in either pass.

## Exact installer

- File: [SquirrelOpsHome-2.1.0-acceptance2-20260926-local-test.pkg](../../build/test-artifacts/SquirrelOpsHome-2.1.0-acceptance2-20260926-local-test.pkg)
- SHA-256: `7d3c8cfb5f48d8090f529fb0d94484935a7c1d1305cc02b8ee80d03425fc6853`
- Size: 136,466,581 bytes, approximately 130 MiB.
- Distribution, app, and sensor: 2.1.0; Apple Silicon (ARM64).
- Built on macOS 27.0 (26A428) with Command Line Tools and the macOS 26.5 SDK.
- Unsigned installer with ad-hoc-signed executables. Not notarized and not a
  public release. Do not disable Gatekeeper globally to install it.
- Supersedes candidate 1, which does not contain the final gesture fixes.

The source is the existing dirty candidate worktree on
`feature/deception-depth-2.1.0-current`, based on
`6b6ef8b5fe3d694695a9bc74982cbe80d05baeb5`. The commit alone does not identify
these bytes. `build/test-artifacts/acceptance2-source-sha256.txt` identifies
411 source, test, configuration, and build inputs; its SHA-256 is
`195a2d0093b33b4f7c596e86fa060685342fdcc77acb79a955b45a4c1a4555c0`.
Every entry passed a post-build check. This local manifest is not a signed
release attestation. Documentation is recorded separately below.

The previous build staging directory was preserved as
`build/pkg-preserved-20260926-acceptance1`. The earlier installer remains
available under its candidate 1 filename. No installed files, services,
database, Keychain credentials, packet-filter rules, or network configuration
were changed during this build and verification pass.

## UI acceptance carried into this package

Matt accepted the final trackpad behavior with **“yes works”** in response to
the explicit short-pull/full-pull check. The final three physical gesture pairs
added one paired list/status request, from 4/4 to 5/5. The synthetic test
window's gesture source matches the packaged source byte-for-byte.

The gesture measures native visible overscroll, not accelerated wheel input.
Its threshold is 44 visible points, calibrated against captured full pulls of
47–52 points. Short pulls do not refresh; a full pull releases once. Foreground
replays also verified that pulls starting inside the list do not refresh.
The full-pull regression was observed failing before calibration, then passing.
See the [acceptance history](2026-09-26-installer-candidate-acceptance.md) for
the original short-pull defect, failing regressions, and replay limitations.

Previously completed foreground checks include keyboard traversal, opening and
closing details with focus return, spoken service/address detail-link labels,
and Matt's confirmation of the **Decoys updated** VoiceOver announcement.
Those checks used the isolated synthetic app. They are not an installed-package
or complete VoiceOver reading-order/custom-action audit.

## Fresh verification

| Check | Result |
| --- | --- |
| App tests | 383 tests in 36 suites passed, 15.703 seconds |
| Helper tests | 114 tests in 7 suites passed, 5.101 seconds; includes opt-in read-only physical LAN observation |
| Guest-runtime containment tests | 6 tests in 1 suite passed |
| Packaging regressions | 22 passed, 2.67 seconds; also included in the full sensor suite |
| Full extracted-sensor suite | 2,259 passed, one opt-in live-guest test skipped, 88.29 seconds |
| Ruff | `ruff check .` passed |
| Package builder | Completed with local-test mode and notarization credentials unset |
| Fresh extraction | `pkgutil --expand-full` succeeded |
| Extracted app versus signed build bundle | Exact directory parity |
| Both first-party Python packages versus source | Exact parity, excluding Python caches |
| Installer scripts, uninstall script, dependency/build locks | Exact parity |
| App strict signature verification | `codesign --verify --deep --strict` passed |
| Guest resources and entitlements | Manifest, architecture, digests, and exact entitlement plist verified |
| Embedded Python native signatures | All 48 native binaries passed strict verification |
| Architecture and versions | App/helper/guest/Python ARM64; app/sensor/distribution 2.1.0 |
| App relocation policy | Disabled; no relocatable bundle entries |
| Local-test isolation | Valid fresh UUID in app; installer opt-in marker present |
| Bundled Python runtime | Python 3.12.12, isolated imports of 19 packaged modules passed |
| Bundled dependency consistency | `pip check` passed; builder verified 39 locked runtime distributions |
| Source identity | All 411 manifest entries still match after build |
| Shell syntax and whitespace | `bash -n` and `git diff --check` passed |

The sensor suite used the development pytest runner with `PYTHONPATH` pointing
at the extracted package. Before starting pytest, it asserted and logged that
`squirrelops_home_sensor` came from `acceptance2-extracted`, not the editable
checkout. This does not test every case under the payload interpreter; its
own isolated imports and dependency checks are separate evidence above.
The opt-in live-guest case was not enabled in this run. Earlier disposable-guest
SSH/SFTP/SMB results are historical, not installed acceptance of this artifact.

The package is intentionally unsigned; `pkgutil --check-signature` reports
**no signature**, and Gatekeeper assessment fails as expected for this local
test. Build tools also emitted `write: Permission denied` messages while
creating package components, but completed successfully. Independent extraction,
payload parity, and signature checks passed. Existing CLT linker/arclite
warnings, a Scapy cryptography deprecation warning, and three test-suite
deprecation warnings for Starlette/WebSockets/Uvicorn remain. No dependency
upgrade, new vulnerability-feed audit, Intel execution, or remote CI claim is
included in this pass.

## Install when ready to test

These commands have not been run. Installing replaces the local app, sensor,
and helper and restarts their services. Keep a current machine backup and the
previous installer. The sensor preinstall creates a private verified durable
data snapshot under `/Library/SquirrelOps/backups/preinstall.*`; that snapshot
is not a complete executable rollback or proof of upgrade success.

From Terminal, verify the artifact first:

```bash
cd /Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current
shasum -a 256 -c build/test-artifacts/SquirrelOpsHome-2.1.0-acceptance2-20260926-local-test.pkg.sha256
```

For a single administrator authentication, the following command creates the
one-attempt local-test approval and installs this exact package in the same
root shell. This is an installation action, not a diagnostic check:

```bash
sudo /bin/sh -c '/usr/bin/install -o root -g wheel -m 600 /dev/null /var/db/com.squirrelops.allow-local-test && /usr/sbin/installer -pkg /Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/build/test-artifacts/SquirrelOpsHome-2.1.0-acceptance2-20260926-local-test.pkg -target /'
```

The approval is consumed when installation starts, even if the attempt fails.
The exact installation and resulting prompt count are not yet tested. A fresh
local-test credential namespace avoids reusing a previous ad-hoc build's
Keychain items; normal Developer ID releases use a stable namespace.

After Installer succeeds, open the installed app, not the synthetic test app:

```bash
open '/Applications/SquirrelOps Home.app'
```

Check the following before calling this candidate accepted:

1. Sensor connects, Settings loads, and existing devices/alerts/settings remain.
   Persisted decoys may need startup time; a running PID alone is not health.
2. Create a decoy and a mimic. Confirm their useful startup notes, eventual
   status, and persistence across scans and an app restart.
3. On Decoys, short pulls do nothing; a full pull shows **Release to refresh**,
   then **Updated just now**. Mid-list scrolling must not refresh. Command-R
   and the context-menu refresh should also work.
4. From a second LAN machine, test SSH and SMB against the actual displayed
   decoy address. Confirm connection and interaction evidence in Alerts.
   Local package checks do not establish virtual-IP/PF/ARP ingress or
   Bonjour/Time Machine discovery.

If installation fails, retain the error and the relevant `/var/log/install.log`
lines. Do not delete sensor data or uninstall as a troubleshooting shortcut.
If rollback is needed, identify the exact completed snapshot and previous
artifact before making any restore changes.

## Documentation and remaining release gates

The user guide and 2.1 notes describe the release cue, short-pull behavior,
transient confirmation, keyboard alternatives, and spoken announcement.
The development guide now queries the actual bundle path in its launch and
guest-test examples instead of assuming SwiftPM's old output layout.
The readiness and desktop-polish records reflect Matt's final acceptance.
`build/test-artifacts/acceptance2-documentation-sha256.txt` records the five
current development, user, security, and release-note documents; its SHA-256
is `3a5844db6ece4e929eaf47ae708b371244879d6f3056b11e505d43064afa0dce`.

This candidate is for local upgrade testing. Before public release, separately
complete exact-package installed acceptance, second-machine LAN and discovery
checks, and the reviewed Developer ID/notarization/release pipeline. A full
VoiceOver order/custom-action audit remains outside the completed foreground
checks. No commit, push, installation, release tag, or publication was made.

## Evidence

All paths are relative to the candidate worktree:

- `build/test-artifacts/acceptance2-build.log`
- `build/test-artifacts/acceptance2-final-test-build.log`
- `build/test-artifacts/acceptance2-final-SquirrelOpsHomeTests.log`
- `build/test-artifacts/acceptance2-final-SquirrelOpsHelperTests.log`
- `build/test-artifacts/acceptance2-final-SquirrelOpsDeceptionGuestTests.log`
- `build/test-artifacts/acceptance2-final-packaging-tests.log`
- `build/test-artifacts/acceptance2-package-verification.log`
- `build/test-artifacts/verify-acceptance2.sh`
- `build/test-artifacts/acceptance2-packaged-sensor.log` and `.xml`
- `build/test-artifacts/acceptance2-source-sha256.txt`
- `build/test-artifacts/acceptance2-source-verification.log`
- `build/test-artifacts/acceptance2-documentation-sha256.txt`
- `build/test-artifacts/pull-calibration-runtime.log`
- `build/test-artifacts/pull-calibration-source-sha256.txt`
