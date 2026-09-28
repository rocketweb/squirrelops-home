# Home 2.1 installer candidate acceptance

Date: 2026-09-26. Decision: **candidate 1 superseded; calibrated short/full pulls physically accepted; candidate 2 built and locally verified**.

Use the [candidate 2 installer and test record](2026-09-26-acceptance2-installer.md)
for the current artifact, checksum, fresh test results, and install instructions.
Its extracted sensor passed 2,259 tests with one opt-in live-guest skip. It has
not been installed or published. The sections below preserve the earlier
candidate 1 and gesture-diagnosis history; their pending states are historical.

Matt answered **“yes works”** when asked whether short pulls do nothing while a
normal full pull refreshes in the updated test window. This accepts the final
44-point calibration. The last three physical begin/end pairs produced one
request pair in total, advancing both counters from 4 to 5. The synthetic
fixture uses the production gesture source byte-for-byte. Do not reopen this
acceptance unless relevant code changes or a new failure occurs. Mid-list
negative behavior has foreground replay coverage, not separate physical
confirmation from Matt.

Latest correction: the 64-point visible threshold prevented Matt's full pulls
from refreshing. Captured physical pulls reached only 47–52 points. The
threshold is now 44 visible points, retaining measurement from native clip
bounds and rejecting accelerated input as a distance substitute. A regression
using the captured 52-point trace failed at 64, then passed after calibration.
The full app suite passes at 383 tests in 36 suites (15.413 seconds).

The exact production-source fixture was tested through normal macOS window
event routing. Two captured short-input replays made no requests (counts 1/1).
A full replay from the top made one request pair (2/2). An additional live
gesture then made one pair (3/3); its intent was not separately confirmed. A
down-scroll followed by a pull starting inside the list made no more requests
(still 3/3). Matt subsequently accepted the final gesture behavior as recorded
above. Earlier physical short-pull acceptance was against the 64-point version
and remains historical evidence only.

Evidence: `build/test-artifacts/pull-full-red.log`,
`pull-routing-diagnostic-runtime.log`, `pull-calibration-app-tests.log`,
`pull-calibration-runtime.log`, and `pull-calibration-source-sha256.txt`.
Temporary observer diagnostics were removed before the final replay; a byte
comparison confirms the fixture uses the production gesture source. Candidate 2
now includes both corrections. Candidate 1 does not and must not be presented
as the current installer. Neither candidate was installed during this pass.

The first attempt at process-targeted replay produced windowless events that
the app correctly ignored. The subsequent guarded session replay used normal
window routing. Those initial windowless events were a diagnostic limitation,
not an app event-routing defect. Physical telemetry established that the native
observer attaches and tracks correctly, but the threshold was too high.

## Previous acceptance and pre-build checks (before final calibration)

At that stage, Matt confirmed the corrected short-pull behavior. The exact
production-source fixture logged two physical begin/end pairs with no new
requests; counts remained 1/1. Full-pull and mid-list physical acceptance are
still pending. Candidate 1 below does not contain the fix and remains on hold.

Fresh pre-build checks after that acceptance: 382 app tests, 114 helper tests,
six guest-containment tests, and 22 packaging regressions passed. The gesture
source still matches the accepted fixture byte-for-byte. The user guide now
names the release cue and distinguishes a full pull from short pulls and
ordinary scrolling. Logs: `build/test-artifacts/acceptance2-app-tests.log`,
`acceptance2-helper-tests.log`, `acceptance2-guest-tests.log`, and
`acceptance2-packaging-tests.log`. No candidate 2 package has been built yet.

The continued acceptance pass confirmed the spoken refresh announcement and
built a new local-test installer through the corrected build scripts. Package
verification passes. The physical short-pull test did not: Matt reported that
one or both read counters increased before he saw the release-to-refresh cue.
No installer was installed, published, or notarized. No commit or push was made.

## Foreground acceptance

- VoiceOver: Matt explicitly confirmed hearing **Decoys updated** after the
  synthetic refresh. This closes the success-announcement check, not a full
  VoiceOver reading-order or custom-action audit.
- VoiceOver was restored to off. Keyboard navigation remains enabled.
- Short pull: Matt reported increased read counters. The original fixture log
  shows paired requests following physical scroll sequences, but logged only
  gesture beginnings/endings. It cannot establish peak distance or whether
  the release cue was rendered in time.
- Mid-list negative gesture: still pending; not inferred from automated tests.

### Short-pull diagnosis and correction

Matt supplied two physical short pulls. Their raw input totals were 548 and
456; each crossed the old 64-unit trigger and caused one request pair. Read
counts rose from 1/1 to 3/3. The SwiftUI background geometry preference stayed
at zero throughout, so it was not a reliable visible-position signal here.
Evidence: `build/test-artifacts/short-pull-diagnostic-runtime.log`.

Replaying the first input sequence through the native scroll view showed only
38 points of visible overscroll while the old code had already armed at 71
raw input units. The native clip bounds and SwiftUI's scroll-specific geometry
agreed. This replay is not a measurement of the original physical gesture's
visible displacement. It demonstrates the input-to-visible-distance mismatch.
Evidence: `build/test-artifacts/pull-geometry-diagnostic-runtime.log`.

The fix observes the native clip view's actual bounds, retaining the intended
64-point visible threshold. Raw wheel deltas no longer arm refresh. Starting
within the list, missing geometry, cancellation, momentum after release, and
in-flight refreshes cannot initiate a new refresh. A new gesture during an old
bounce must earn its own visible pull distance. Native notification and
elasticity settings are restored when the observer detaches. No dependency or
minimum-OS change was needed.

Verification after the fix:

| Check | Result |
| --- | --- |
| Captured-input regression before the fix | Both input cases failed by refreshing once |
| Focused presentation and refresh-feedback tests | 18 tests passed |
| Full macOS app suite | 382 tests in 36 suites passed, 15.546 seconds |
| Native test geometry | 38/63 points do not arm; 64 points arms and releases once |
| Cancellation, repeated release, momentum, mid-list start, residual bounce, concurrent refresh, observer cleanup | Passed |
| Short-pull replays in the foreground fixture | Both stayed unarmed; counts stayed 1/1 |
| Mid-list replay reaching overscroll | Stayed unarmed even after crossing the visible threshold |
| Physical short pulls on corrected code | Passed: Matt confirmed; two gestures, counts unchanged at 1/1 |
| Physical full-pull and mid-list checks on corrected code | Pending |

The offscreen tests use a clip-view subclass that permits test-supplied elastic
positions; standard AppKit otherwise clamps programmatic bounds changes when
there is no live gesture. Production uses the real native clip view. Replay
timings differ from physical input, so replay peaks varied and do not replace
physical acceptance. A planned positive replay was inconclusive: one sequence
stayed below threshold, and a later run had left Decoys before the positive
case. Neither was recorded as a positive UI pass.

Evidence under `build/test-artifacts/`: `pull-regression-red.log`,
`pull-regression-green.log`, `pull-fix-full-app-tests.log`,
`pull-replay-fixture-runtime.log`, and `pull-final-replay-runtime.log`.
The accepted physical short pulls are in `pull-physical-acceptance-runtime.log`.

Temporary replay hooks and geometry diagnostics were removed from the
acceptance window. Its gesture source now exactly matches production source.
The window is titled **SquirrelOps UI Acceptance (synthetic data)** and uses
only a non-networked fixture. The held installer below predates this fix and
must not be used to test it. No new package was built during this correction.

## Exact held package

Artifact: `build/test-artifacts/SquirrelOpsHome-2.1.0-acceptance1-20260926-local-test.pkg`

- Distribution/app/sensor version: 2.1.0; ARM64.
- SHA-256: `742f67fb9df8ee2f2f67fe395b5f45370bf4762c7dbe5a4b68a6c2b4ed0c3699`.
- Unsigned installer containing ad-hoc-signed app/runtime components.
- Not notarized, installed, or suitable for public distribution.
- One-time local-test authorization remains required for installation.
- The previous package/build directory was preserved intact at
  `build/pkg-preserved-20260926-acceptance` before running the builder.

Every entry in the 411-file manifest from the
[readiness-fix pass](2026-09-26-release-readiness-fixes.md) was rechecked after
the build. Signing changes staged app bytes; the earlier unsigned executable
hash is not this package's identity.

## Verification

| Check | Result |
| --- | --- |
| Corrected package builder with CLT/macOS 26.5 SDK | Completed on macOS 27 |
| Fresh `pkgutil --expand-full` extraction | Passed |
| Extracted app versus signed build bundle | Identical |
| Extracted sensor source versus working source | Identical, excluding Python caches |
| Preinstall/postinstall/uninstall scripts and dependency/build locks | Exact source/build parity |
| Deep/strict app signature and guest manifest | Passed |
| Guest runtime entitlements | Exactly match the reviewed entitlement file |
| Native Python signatures | 48 verified |
| App/helper/guest/Python architectures | ARM64 |
| Version metadata, non-relocation and local-test markers | Passed |
| Bundled Python isolated imports | Passed; sensor reports 2.1.0 |
| Bundled Python `pip check` | Passed |
| Full suite against extracted sensor code | 2,259 passed, one opt-in guest test skipped; 89.64 seconds |
| Source manifest recheck and whitespace | Passed |

The packaged-code suite used the development test runner with the extracted
site-packages first on `PYTHONPATH`, asserted the sensor's import origin, and
disabled bytecode writes. It did not install test dependencies into the signed
payload. Separate `-I -B` import and dependency checks used the extracted Python
interpreter itself. Previous live-guest acceptance is separate evidence, not
execution of this package's release runtime as an installed service.

The package tools emitted `write: Permission denied` warnings. Extraction,
byte comparisons, script checks, and signatures passed; a zero build exit
alone was not treated as proof. The verification script was corrected to allow
an empty `<relocate/>` with `relocatable="false"`, and to compare entitlements
against the complete reviewed plist, including its explicit false app-sandbox
value. Neither verification-script correction changed the package.

Evidence is under `build/test-artifacts/`: `acceptance-candidate-build.log`,
`acceptance1-verification.log`, `verify-acceptance1.sh`, app/sensor parity logs,
`acceptance1-packaged-sensor.log` and `.xml`, and
`acceptance1-source-recheck.log`.

## Next steps

1. Use candidate 2, not the superseded package documented here. Its final
   short/full gesture behavior is physically accepted and its package checks pass.
2. Preserve the recorded runtime positive/negative evidence. Reopen acceptance
   only for relevant code changes or a new reported failure.
3. Obtain approval for the exact installation, preserve rollback files and a
   verified database snapshot, then test upgrade/enrollment, Settings,
   decoy/mimic creation and persistence, and second-machine LAN alert behavior.

The installed app, sensor, helper, network aliases, and packet-filter rules
were not changed by this pass.
