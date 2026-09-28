# SquirrelOps Home 2.1 release-fix results

Date: September 4, 2026. Local verification completed on Matt's arm64 Mac Studio.

## Outcome

The reproducible code defects are fixed. The new local-test installer was subsequently installed on this Mac and passed local package, process, and sensor-health checks. Second-machine LAN acceptance remains pending.

The [plan](2026-09-04-release-fix-plan.md) was written before implementation. The [original functional report](2026-09-04-local-decoy-functional-report.md) and its failures are preserved. The engineering-constraints skill required failing regressions before fixes and separate evidence for source, packaged code, and live guest behavior.

| Finding | Change and verified result |
| --- | --- |
| OpenAI streaming returned plain JSON | Implements SSE chunks and terminal `[DONE]`, including optional usage records. Live HTTP and protocol tests pass. |
| Ollama streaming returned plain JSON | Implements NDJSON, including streaming by default and a final `done: true` record. Explicit `stream: false` stays JSON. |
| File Share SSH bait was not a real key | Generates independent RSA-2048 unencrypted PEM keys. Parser, signature round-trip, and actual HTTP download tests pass. These keys are not authorized on the Mac or any real service. |
| Legacy invalid SSH bait would survive an upgrade | Ordinary File Share credential loading replaces invalid bait for serving once, while retaining original database rows, trip state, and timestamps. Disposable-database migration and idempotency tests pass. |
| Studio could disappear with no operator explanation | Authenticated status exposes a bounded startup reason even before a host row exists. Decoys renders the notice even with an empty inventory. Refresh reloads status, not the guest. API, model compatibility, and SwiftUI render checks pass. |
| Studio startup/recovery gaps | Repeated startup does not launch another guest. Eligible unavailable hosts retry on later scans with a 60-second minimum start interval. Degraded hosts can be stopped, intentionally stopped hosts remain stopped, and shutdown prevents retry. Isolated lifecycle tests pass. |
| Installed app lacked newer alert-evidence fields | The existing candidate alert fix is included, without redesign. Packaged alert-handler regressions pass. The old installation has not been upgraded in this turn. |

Streaming retains the same synthetic narrative. Explicit non-streaming responses have byte-hash regression checks. Existing banners, authentication, errors, containment, and guest ownership validation remain in place. The intentional attacker-visible changes are recorded in the plan's deception review.

Protocol expectations were checked against the [OpenAI streaming reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/streaming-events) and [Ollama chat reference](https://docs.ollama.com/api/chat). These tests establish protocol behavior, not effectiveness against a malicious autonomous LLM.

## Test results

Counts below are separate overlapping runs, not an additive total.

| Run | Result | Evidence |
| --- | --- | --- |
| Streaming/key regression baseline | 8 failed, 108 passed | `release-fixes-red.xml` |
| Studio lifecycle/API baseline | 4 failed, 35 passed | `studio-lifecycle-red.xml` |
| Streaming/key focused rerun | 116 passed | `release-fixes-green.xml` |
| Studio lifecycle/API/entry-point rerun | 80 passed | `studio-lifecycle-green.xml` |
| Additional HTTP key, wiring, and focused checks | 45 passed | `release-fixes-added-checks.xml` |
| Final complete sensor suite | **2,202 passed, 1 skipped**, 85.74 seconds | `release-fixes-full-sensor-final.xml` |
| Final complete Swift suite | **468 tests across 39 suites passed**, 5.357 seconds | Observed `swift test` output |
| SwiftUI visual smoke | 2 passed; new notice image reviewed | `studio-diagnostic.png` |
| New release guest runtime with trusted root-owned guest bundle | **1 live acceptance test passed**, 23.39 seconds | `release-fixes-live-guest-root-bundle.xml` |
| Extracted installer sensor payload | **176 passed**, 3.33 seconds | `release-fixes-packaged-sensor-unsandboxed.xml` |
| Sensor Ruff and whitespace checks | Passed | `ruff check .`, `git diff --check` |

The full sensor suite's one skip is the opt-in live guest test, which was run separately. Three non-failing warnings concern Starlette/httpx and legacy websocket integration.

### What the live guest run proves

The new release runtime passed authenticated SSH commands, SFTP read/write/delete, SMB negotiation and file operations, bounded host-isolation checks, and connection telemetry for advertised ports 22 and 445. The disposable guest was stopped afterward.

The runtime used the installed root-owned guest bundle. `cmp` confirmed that its manifest, kernel, and initramfs match the candidate's guest bundle byte for byte. This verifies the current guest bytes without changing their ownership or weakening release validation.

An earlier attempt with a user-owned guest bundle was rejected with `Guest file is unsafe: DeceptionGuest`. This was the release ownership check working, not an SSH/SMB failure. The test fixture was updated to accept either root-owned installed inputs or developer-owned source inputs at its outer validation layer; the release runtime still independently requires root-owned guest files. The failed attempt is retained in `release-fixes-live-guest.xml`.

This is a disposable, loopback-relay test. It does not prove that the installed sensor creates Studio, advertises it over Bonjour, receives LAN packets through PF, or displays resulting native-app alerts.

### Packaged-code verification and environment failures

The installer was expanded without installing it. All seven changed sensor production files, plus the pre-existing alert-handler fix, matched the current candidate source byte for byte. The regression process imported modules from the expanded package, not `sensor/src`.

The first extracted-payload test attempt had 166 passes, two failures, and eight setup errors because the sandbox denied loopback listener creation with `Operation not permitted`. The approved rerun outside that sandbox passed all 176 tests without a product-code change. Both XML records are retained.

The extracted app passed `codesign --verify --deep --strict`. That proves local signature integrity, not Developer ID signing, notarization, or public distribution approval.

## Installer and identity

[Download the new arm64 local-test installer](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/build/test-artifacts/SquirrelOpsHome-2.1.0-release-fixes-20260904-local-test.pkg)

| Identity | Value |
| --- | --- |
| Checkout | `/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current` |
| Branch | `feature/deception-depth-2.1.0-current` |
| Base commit | `6b6ef8b5fe3d694695a9bc74982cbe80d05baeb5` plus this uncommitted working diff |
| Distribution, app, sensor version | `2.1.0` |
| Architecture | arm64 |
| Package SHA-256 | `d4331be9d2b407786d6f7a444f17fbf4ab742f08faa5f44a0d13c4eca4158555` |
| Packaged app executable SHA-256 | `ab83b0b0f66470034839a42d6f9a83f55832f969a481c999944678a0d45bc98f` |
| Local-test identity marker | `6174BD09-0E0A-4613-BB13-82BAFBA2D248` |
| Signing | Ad-hoc-signed app components; unsigned installer; not notarized |
| Installation state | **Installed successfully at 14:04 EDT on September 4, 2026** |

Built using:

```bash
SQUIRRELOPS_LOCAL_TEST_BUILD=1 SKIP_PKG_SIGNING=1 bash scripts/build-pkg.sh
```

The build verified the pinned standalone Python runtime and locked runtime dependencies. The uniquely named package above was preserved outside the builder's disposable `build/pkg` staging directory. The package contains all production fixes; subsequent edits added tests and documentation only.

### Installation performed

The package checksum was rechecked before installation. Installation used the explicit one-time local-test opt-in required by the unsigned test package:

```bash
sudo /usr/bin/install -o root -g wheel -m 600 /dev/null /var/db/com.squirrelops.allow-local-test
```

The privileged installer reported `The upgrade was successful`, and the opt-in was consumed. Gatekeeper was not disabled. This remains a deliberately unsigned local-test candidate, not the public release artifact.

Post-install verification found app and sensor receipts at 2.1.0. The installed app executable matched the packaged checksum above, all changed sensor modules matched candidate source byte for byte, and strict app signature-integrity verification passed. Fresh helper, sensor, and app processes were running. The sensor took several minutes to finish initialization; it then listened on TCP 8443 and returned `{"status":"ok"}` from `/system/health`.

## Required live follow-up

1. Confirm existing alert-history preservation in the native app. Installed file identity and basic sensor startup are now verified.
2. Open Decoys and refresh status. Record the Studio notice if startup fails. An intentionally stopped host needs an explicit start; a disabled configuration needs an operator decision. Do not assume retry overrides either state.
3. If Studio is still unavailable, inspect its private startup log with approved administrator access. No specific Studio startup cause has been established.
4. Once Studio is active, use its **currently displayed IP**, not an assumed `.203`, from the Linux laptop. Run the route, dynamically selected interface/ARP, TCP, SSH, SFTP, SMB, and AI checks in [the updated operator test instructions](../USER_GUIDE.md#safely-test-the-studio-build-mac).
5. Confirm remote source attribution, per-service counters, alert aggregation/evidence, and stop/start behavior in the native app. Multiple SMB commands within one TCP session need not create separate connection alerts.
6. Complete cross-device deception review and release signing/notarization gates before publication.

Do not treat host-local backend timeouts as proof of broken LAN ingress or weaken PF to make that test pass. No PF policy changes were made.

The Studio guest remains an isolated Linux system with macOS-shaped commands and files. It is not genuine macOS virtualization. Detailed OS fingerprinting can reveal that architecture; this known limit is now explicit in the release notes. Full macOS virtualization, exhaustive fingerprint concealment, malicious-agent effectiveness, long soaks, and Intel live acceptance were not implemented or claimed.

## Reproduction and retained evidence

Run from the candidate checkout using its existing development dependencies:

```bash
cd sensor
.venv/bin/python -m pytest tests/ -q --tb=short
.venv/bin/ruff check .
cd ../app
swift test
```

Loopback listener tests and Virtualization.framework acceptance require a host execution context that permits those operations. The live guest setup and environment variables are documented in [DEVELOPMENT.md](../DEVELOPMENT.md).

Extracted-package regression selection:

```bash
# Set PACKAGE_SITE to the expanded installer's sensor site-packages directory.
PYTHONPATH="$PACKAGE_SITE" .venv/bin/python -m pytest \
  -c /dev/null --rootdir=. --asyncio-mode=auto \
  tests/unit/test_deep_deception_protocols.py \
  tests/unit/test_credentials.py \
  tests/integration/test_ai_workbench_decoy.py \
  tests/integration/test_decoy_orchestrator.py \
  tests/integration/test_deep_decoy_orchestrator.py \
  tests/integration/test_routes_system.py \
  tests/integration/test_decoy_alert_handler.py -q --tb=short
```

All named XML files and the rendered diagnostic screenshot are retained in [evidence/2026-09-04-release-fixes](evidence/2026-09-04-release-fixes). The screenshot is a SwiftUI fixture render, not the installed app.

Before installation, final build-test inspection showed the original helper PID 31777, sensor PID 31785, and app PID 33865, with no test guest left running. The successful upgrade replaced them with helper PID 76171, sensor PID 76193, and app PID 76876. No live sensor configuration, private database, or PF rules were manually edited. No existing alerts were cleared. Implementation, tests, and documentation remain local and uncommitted. No push or publication occurred.
