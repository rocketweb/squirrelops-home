# Home 2.1 relay and control fixes

Date: 2026-09-26. Status at completion of this batch: fixes verified and
local-test installer rebuilt, not installed or committed. Subsequent commit,
reviewer setup, and PR preparation are tracked in the
[GitHub release checklist](2026-09-26-github-release-preparation.md).
This report does not establish a final public release.

## Scope and source

Checkout: `/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current`.
Base commit: `66bda11a97ea8bf6192e812e9fae4584bfb16d85`.
This batch is uncommitted source on that base. It is not the earlier
`66bda11` installer. No installation, push, tag, notarization, or publication is
part of this batch.

The supplied Cursor review was checked against the current source before work
began. The detailed assessment remains in the local artifact
`build/test-artifacts/66bda11-cursor-review-assessment.md`.

| Finding | Change |
| --- | --- |
| M1, L1 | Both relay pumps retain descriptor owners and the admission lease until both finish. EOF half-closes the opposite write side; errors/cancellation shut down I/O before final close. |
| L7 | Oversized internal telemetry is discarded in bounded chunks through its newline, then draining resumes. A valid-looking suffix of a bad record is not accepted as a separate event. |
| L9 | Pairing checks the Security framework RNG result and stops before verification or credential storage on failure. |
| L16 | Remote/local pairing share trimmed, nonempty, bounded client-name validation, including controls at the beginning or end. |
| L19 | Pre-auth and authenticated WebSocket paths validate JSON object shape; fallback credential types and replay cursor types/ranges are checked before SQLite binding. |
| L24 | Behavioral alerts use an exact destination issue key. Older alerts retain exact-title deduplication without substring or wildcard matching. |
| L25 | AI classification manufacturer/model types and lengths, plus finite confidence in [0, 1], are validated before return. Existing invalid device-type fallback stays unchanged. |

## Deception-integrity review

The relay changes the attacker-visible transport behavior deliberately: a
write-side EOF no longer tears down the reverse response prematurely. SSH and
SMB remain opaque byte streams. This repairs protocol fidelity and does not
add authentication, lockouts, rate limiting, banners, headers, timeouts, or
quotas. The existing 16-connection limit, guest forwarding policy, persona,
credentials, service versions, guest bytes, and isolation settings are unchanged.
The slot remains occupied until both workers finish, including error cleanup.

Telemetry recovery changes internal supervision only. Its record schema and
valid connection evidence are unchanged. Control API and classifier validation
do not change decoy responses.

## Regression evidence

Before applying behavior changes, the new tests failed against the old
behavior with only test-injection seams added:

- `relay-control-guest-red.log`: both relay tests failed. The first pump closed
  both descriptors and released the slot while the second worker was delayed;
  a response after request EOF could not reach the client.
- `relay-control-nonce-red.log`: the failing RNG still led to `/pairing/verify`.
- `relay-control-python-red.log`: 37 failures, 70 passes. Failures cover
  malformed WebSocket frames, invalid/unnormalized names, exact-destination
  deduplication, invalid AI fields, and oversized telemetry recovery.
- `relay-control-alert-red.log`: the new destination key initially made a
  single-device alert look grouped. The app now limits affected-device-count
  presentation to grouped security findings, preserving the behavioral alert's
  source IP. Existing port-risk and ARP group presentation remains covered.

Logs are under `build/test-artifacts/`. Test clients and device data are
synthetic. The tests do not read production credentials or modify the installed
sensor. The write-failure socket fixture initially used a read-side shutdown
that did not produce EPIPE on this host; that test run was stopped and the
fixture changed to close the peer, with bounded test-only socket deadlines.

An initial live reconnect probe repeatedly disconnected SSH before
authentication. It hit OpenSSH's existing source penalty, recorded in
`relay-control-live-guest-preauth-probe.log`, rather than demonstrating a relay
slot leak. The acceptance test now uses authenticated SSH reconnects. Guest
policy was not changed to make the probe pass; native pre-auth penalties and
their effect when relay connections share a guest source address remain a
separate deception/availability review item.

## Verification

Host: ARM64 macOS 27.0 (26A428), CLT macOS 26.5 SDK. The SDK workaround is
documented in `docs/DEVELOPMENT.md`; no Xcode license or system setting changed.

| Check | Result | Artifact log |
| --- | --- | --- |
| Full sensor suite | 2,311 passed, one opt-in VM skip, 84.85 seconds | `relay-control-sensor-full.log` |
| Full sensor suite against extracted installer code | 2,311 passed, one opt-in VM skip, 88.04 seconds; first-party import paths asserted | `relay-control-packaged-sensor.log` |
| Focused control suites | 148 passed | `relay-control-python-focused.log` |
| App suite | 393 passed, 37 suites | `relay-control-SquirrelOpsHomeTests.log` |
| Helper suite | 121 passed, 8 suites; includes read-only LAN observation | `relay-control-SquirrelOpsHelperTests.log` |
| Guest-runtime suite | 17 passed, 3 suites | `relay-control-guest-green.log` |
| Relay repetition | Seven lifecycle tests passed in each of 50 runs, 350 executions | `relay-control-relay-repeat.log` |
| Disposable live guest, debug runtime | Passed in 25.51 seconds | `relay-control-live-guest.log` |
| Disposable live guest, extracted release runtime and sensor | Passed in 26.15 seconds | `relay-control-packaged-live-guest.log` |
| Extracted installer verification | Exact app/Python/script/lock parity; guest digest/architecture; app and 48 native Python signatures; metadata and no-relocation checks; embedded pip check and 19 isolated imports passed | `relay-control-package-verification.log` |
| Ruff and whitespace | Passed | `relay-control-ruff.log`; `git diff --check` |

The disposable guest test used the newly compiled debug runtime and read-only,
root-owned installed guest resources. It verified SSH authentication and persona
commands, SFTP and SMB file operations, host-canary and network isolation, 20
SMB reconnects alternating normal and write-side-half-close behavior, 20
authenticated SSH reconnects, both protocols' telemetry, and process exit code
zero while two protocol sockets remained open. This checks actual VZ transport
and clean whole-process shutdown, not a proof about all in-process VM teardown
or long-lived saturation cases.

The packaged sensor run used the test environment's pytest with `PYTHONPATH`
pointing to the extracted package's site-packages and assertions that both
first-party modules came from `relay-control-extracted`. Separately, the
embedded Python ran isolated dependency and import checks. The opt-in VM case
skipped by each full suite passed in both dedicated live runs above.

### Commands

From `sensor/`, with the existing environment:

```bash
env -u SQUIRRELOPS_DECEPTION_RUNTIME -u SQUIRRELOPS_GUEST_BUNDLE \
  .venv/bin/python -m pytest -q --tb=short -ra
.venv/bin/ruff check .
```

Swift bundles were compiled with the explicit SDK/scratch/plugin command in
`docs/DEVELOPMENT.md`, then run through CLT `swiftpm-testing-helper` using
absolute bundle paths, `--testing-library swift-testing`, the CLT framework
and library paths, and `SQUIRRELOPS_TEST_LIVE_LAN=1`. The repeated relay run
added `--filter SocketRelayTests` and did not enable a guest or LAN listener.

The live guest test used `SQUIRRELOPS_DECEPTION_RUNTIME` set to an ad-hoc-signed
copy of the new debug runtime under `/private/tmp`, and
`SQUIRRELOPS_GUEST_BUNDLE` set to the installed app's read-only guest resource
directory. Its listeners bound only to `127.0.0.1`.

### Rebuilt installer

The earlier `build/pkg` was preserved as
`build/pkg-preserved-20260926-pre-relay-control` before rebuilding. The exact
437 source/build/test inputs are hashed in
`build/test-artifacts/relay-control-source-sha256.txt`, including new files.
The intermediate package built before the alert-presentation integration fix
was also preserved in `build/pkg-preserved-20260926-relay-control-before-alert-integration`.
It is not the final test installer.
Installer: `build/test-artifacts/SquirrelOpsHome-2.1.0-relay-control-local-test.pkg`.
Size: 136,479,998 bytes. Version 2.1.0, ARM64.

```text
Package SHA-256:
611e3f3672f87191c59d42e0575f3b0c34d4002216fec6328deb12adc4dcedd3
Source-input manifest SHA-256:
3700eb29f2bb1e4ea1a82b783e0495853f85d5b4cf84f75b69b72281e085724c
```

This is an explicitly local-test package: ad-hoc-signed executables, unsigned
installer, not notarized. The builder verified all 39 locked Python runtime
distributions. Source-input hashes still match after the build. The package's
guest bytes exactly match the root-owned installed guest resources used for
the extracted-runtime live test. No installed process or file was changed.

The final build command was:

```bash
env -u APPLE_ID -u APPLE_TEAM_ID -u APPLE_APP_PASSWORD \
  -u SQUIRRELOPS_RELEASE_BUILD -u SIGNING_IDENTITY -u INSTALLER_IDENTITY \
  DEVELOPER_DIR=/Library/Developer/CommandLineTools \
  SQUIRRELOPS_SWIFT_SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
  SQUIRRELOPS_SWIFT_SCRATCH_PATH=.build/relay-control-release \
  SQUIRRELOPS_LOCAL_TEST_BUILD=1 SKIP_PKG_SIGNING=1 \
  bash scripts/build-pkg.sh
```

`build/test-artifacts/verify-relay-control.sh` contains the reproducible
extracted-package checks. It explicitly selects CLT: the first architecture
inspection attempt selected the default Xcode and stopped at its unaccepted
license. No license was accepted. Apple packaging tools also emitted the same
`write: Permission denied` warnings seen in the prior candidate build; the
builder exited zero and the extracted contents, metadata, and signatures
passed. This does not substitute for a real installation test.

### Optional manual installation, not executed

Preserve the current application/runtime and durable sensor data before local
upgrade testing. The installer has its own quiescent data backup workflow;
installed-upgrade and rollback acceptance are still separate from this rebuild.
The explicit local-test installer requires a one-attempt, root-owned opt-in:

```bash
sudo /usr/bin/install -o root -g wheel -m 600 /dev/null /var/db/com.squirrelops.allow-local-test
sudo /usr/sbin/installer -pkg "/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/build/test-artifacts/SquirrelOpsHome-2.1.0-relay-control-local-test.pkg" -target /
```

The opt-in is consumed when installation is accepted, even if a later step
fails. Do not use the earlier `66bda11` or intermediate package as though it
contained the final fixes. No commit or installation was performed in this
batch.

## Remaining gates

This batch does not resolve all review findings. Connection-pool saturation,
guest storage pressure, evidence-storage budgets, pre-auth control-session
limits, source-development database permissions, artifact path-race hardening,
and the other items in the assessment remain separate work. No generic decoy
timeout or SSH-forwarding restriction was added.

The prior live PF replacement/state-reuse/failure-injection checks and
second-machine virtual-IP SSH/SMB acceptance remain release gates. Intel
execution, fresh foreground accessibility acceptance, Developer ID signing,
notarization, and installed-upgrade acceptance are not established by this
local ARM64 rebuild.
