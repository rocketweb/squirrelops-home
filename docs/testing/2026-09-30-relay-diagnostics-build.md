# Relay diagnostics: local implementation and diagnostic installer

Scope: implement internal listener/guest-connection diagnostics, add real-listener
regressions, test locally and rebuild. The operator approved this scope after
the [retained-evidence review](2026-09-30-mini-readonly-diagnostic-result.md).
This does not authorize installation, startup, new probes or filter changes on
the Mini. No commit, push or release is included.

## Changes and diagnostic boundary

The host runtime now records listener activation/readability, accept/setup
errors, acceptance before the MainActor handoff, entry into that actor,
guest-connect start/result, relay start, first read in each direction, EOF,
I/O errors, timeout and closure. Per-process connection IDs and sequence numbers
correlate stages without recording peer identities or transferred content.

`RuntimeDiagnostics` uses an asynchronous queue bounded to 512 records plus
one truncation marker per VM. That limit affects diagnostics only. Existing
connection admission, SSH/SMB payloads, timeout policies and hit events are
unchanged. A blocked diagnostic sink does not wait on a listener/relay thread.
Records are best effort near process exit; their absence alone is not a filter
verdict. The diagnostic connection number resets for each runtime process.

The finalized producer writes structured records on stderr, separate from the
stdout readiness/hit-telemetry lock. The sensor supplies a fresh 128-bit host-only
marker through the runtime environment, never through the persona or guest.
The receiver requires that marker on stderr so guest console text cannot simply
impersonate a host checkpoint. It reconstructs bounded newline frames, rejects
invalid fields, limits logged records independently and redacts the marker from
its bounded raw stderr tail. The private rotating log receives fixed vocabulary
and numeric metadata only. Diagnostic records never become decoy hits.

No new dependency, public API, helper privilege, UI control, guest image,
protocol banner, credential policy or firewall rule is introduced.

## Verification

| Check | Current result |
| --- | --- |
| Diagnostic consumer before implementation | New checkpoint test failed because the frame was invalid telemetry |
| Swift negative control | Removing the acceptance checkpoint caused two new tests to fail; restoring it returned the suite to green |
| Restart budget reset before correction | New assertion failed at 513; per-start reset restored the expected zero |
| stderr framing before implementation | Both new stderr tests failed, then passed with framing/validation |
| Complete sensor suite, final product source | **2,436 passed, 2 skipped**, 3 dependency deprecation warnings, 90.91 seconds |
| Compiled guest suite | **30 passed**, including 7 new diagnostic/listener/relay tests |
| Real local TCP listener | Eight reconnects, exact synthetic SSH banner bytes, unique connection IDs, pre-MainActor acceptance |
| Backpressure and log budget | Blocked diagnostic sink did not block a real listener; exactly 512 records plus truncation marker |
| Byte parity / error cleanup | Instrumented duplex relay preserved request/response bytes; invalid descriptor emitted numeric errno and released its allowance |
| Cross-language/redaction checks | Fixed stage vocabulary, invalid types/fields, chunk boundaries, oversized stderr, marker redaction, guest-console spoof rejection, unchanged hit delivery |
| Full lint / whitespace | `ruff check sensor/src sensor/tests` and `git diff --check` passed |
| Packaged Python consumer | Isolated import from the extracted package, real stderr parsing, marker redaction and zero diagnostic hit callbacks passed |
| Package/source parity | Packaged `guest_runtime.py` exactly matches source; manifest, kernel and initramfs exactly match unchanged ARM64 guest inputs |
| Payload signing and architecture | Strict app/deep and Python checks passed; guest is ARM64 with virtualization entitlement; ad-hoc signing only |
| Prior shutdown fix retained | Packaged sensor plist retains `ExitTimeOut = 60` |
| Disposable local real-guest protocols | **1 passed**, 60.13 seconds; real SSH/SFTP/SMB, reconnects, capacity recovery, containment and clean shutdown; both service checkpoint streams validated |

The full-suite skips are the opt-in live guest and launchd tests. The separate
real-guest check is a disposable loopback test using a newly copied/ad-hoc-signed
debug runtime from the same source, not a root-installed release runtime. It
does not establish Mini LAN, content-filter, PF, upgrade or fault acceptance.
No launchd acceptance was repeated in that initial build pass.

The live guest test completed successfully with the exact expected runtime exit
code zero, with both protocol sockets open during its shutdown check. A later
anchored process-name check found no remaining instance of the uniquely named
local diagnostic runtime. The new assertions verified activation, acceptance,
guest-connect start and successful guest-connect records for both services,
the 513-record bound, and absence of the persona password and host marker from
checkpoint log messages.

An intermediate stdout-diagnostic build was superseded locally after review
identified shared-output-lock backpressure risk. Only the final stderr-channel
candidate below is proposed for further testing. It has not been installed.

## Final local artifact

- Home/App/Sensor 2.1.0, ARM64.
- `build/test-artifacts/SquirrelOpsHome-2.1.0-relay-diagnostics-20260930-local-test.pkg`
- Size: **136,565,301 bytes**.
- SHA-256: `3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea`.
- Guest executable SHA-256: `762e6825939f2eecc1c4c2d704060b7cea624f9ba85801681ca83b7c411fb3f3`.
- Sensor `guest_runtime.py` SHA-256: `f3dc0207945136bfac3ef599a2cf90fed72979421e4469685ae9b8e6a798fa73`.
- Baseline: `a50179417e8f726ceb03bb6914a42cb996d2ead6` plus preserved prior local
  release fixes and this diagnostic change. This is not a clean committed SHA.
- Installer unsigned, payloads ad-hoc signed, not notarized. Local test only.
- Previous `3a3cda47...` launchd-budget package remains retained separately.

Build command:

```sh
DEVELOPER_DIR=/Library/Developer/CommandLineTools \
SQUIRRELOPS_SWIFT_SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
SQUIRRELOPS_SWIFT_SCRATCH_PATH=.build/relay-diagnostics-release \
SQUIRRELOPS_LOCAL_TEST_BUILD=1 SKIP_PKG_SIGNING=1 bash scripts/build-pkg.sh
```

Logs under `build/test-artifacts/`:

- `relay-diagnostics-20260930-final-build.log`
- `relay-diagnostics-20260930-final-sensor.log` and matching XML
- `relay-diagnostics-20260930-final-swift.log`
- `relay-diagnostics-20260930-live-guest.log` and matching XML

Selected source inputs are recorded in
`relay-diagnostics-20260930-source-sha256.txt` (237 entries), SHA-256
`94ee6f98be7381014c593db79bbc4cc35bcd29b7dc601156920e211a7c10bc9a`.
This local source inventory is not a public build attestation.

## Deception review and remaining boundary

The changes are internal logging only. Existing protocol-handling code paths,
guest bytes, admission ceiling and configured deadlines are preserved.
Snapshot-style tests verify exact banner and bidirectional relay byte parity;
a blocked diagnostic sink test checks the intended nonblocking boundary.
These finite local checks are not a network timing-fingerprint certification.
Nothing makes the emulated system appear better maintained or strengthens its
deliberately plausible credentials.

The engineering verification skill informed failing-first checks, explicit
diagnostic boundaries, artifact parity verification and the distinction between
a built diagnostic candidate and an actual fix of the Mini's SSH/SMB stall.

The Mini was not contacted or changed during this implementation/build turn.
The next step requires a reviewed bounded installation/startup/probe/cleanup
scope for this exact package, preserving all seven rows and existing filters.
Fresh prompts are possible because the ad-hoc guest executable identity changes.
Do not reuse the old consumed acceptance commands or install this candidate
unattended to bypass that boundary. The original stall remains unresolved.

A subsequent [acceptance preparation pass](2026-09-30-relay-diagnostics-acceptance-preparation.md)
completed the app/helper suites, packaged shutdown tests and actual release
guest loopback acceptance, then staged a newly pinned attended Mini runner.
The diagnostic package bytes did not change. Mini installation remains pending.
