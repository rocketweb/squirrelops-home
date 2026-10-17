# Home 2.1 signal shutdown fix and release follow-up

Date: 2026-09-29. Status: local fix verified and installer rebuilt.
**Public release remains blocked by failed live protocol acceptance.**

## Confirmed defect and fix

The pinned Uvicorn 0.51.0 server captures signals around `Server._serve()` and
replays them before `Server.serve()` returns. SquirrelOps previously cleaned up
its runtime only in the outer `run_sensor()` finally block. On SIGTERM, the
default signal handler can terminate the process before that block runs. On
SIGINT, asyncio's restored handler can cancel asynchronous cleanup.

An isolated subprocess regression reproduced both failures before the fix:
the server started in both cases, SIGTERM produced no guest/database cleanup
markers, and SIGINT interrupted the simulated guest stop at an await point.
The initial sandboxed attempt could not start its loopback listener and was
not treated as valid failure evidence. The reproduction and passing rerun used
disposable listeners outside that sandbox restriction.

`_RuntimeManagedServer._serve()` now cleans up inside Uvicorn's signal-capture
scope. The existing outer finally remains the fallback for earlier startup
failures, and cleanup remains idempotent. Tests cover ordinary completion,
startup failure, cancellation, cleanup failure, preservation of the original
startup exception, and real SIGTERM/SIGINT delivery. The private `_serve` hook
is intentional; the real-process tests protect the dependency contract.

This explains a mechanism that can leave a guest behind after the sensor exits.
It is consistent with the mini's orphaned guest observation, but does not prove
that every observed shutdown problem had this cause. SIGKILL, OS failure and
indefinitely stalled third-party cleanup remain outside this guarantee.

No decoy banners, synthetic files, credentials, protocol behavior, PF rules,
UID guards, or third-party filters were changed. The only product code change
is sensor process-lifetime management. An existing nullable diagnostic assertion
was also narrowed in its test, resolving a whole-suite type-check error without
changing runtime behavior.

## Verification

Commands below run from `sensor/` unless stated otherwise.

| Check | Result |
| --- | --- |
| `pytest tests/unit/test_runtime_shutdown.py tests/integration/test_entry_point.py -q` | 53 passed |
| `pytest tests/ -q` | 2,356 passed, one skipped |
| `ruff check src tests` | Passed |
| `pyright src/` (CI scope) | Zero errors, 29 warnings |
| `pyright` (source and tests) | Zero errors, 279 warnings after narrowing the pre-existing nullable test assertion |
| `swift test --filter SquirrelOpsHomeTests` from `app/` | 400 passed in 38 suites, including rendered layouts |
| `swift test --skip-build --filter SquirrelOpsHelperTests` | 121 passed in eight suites |
| `swift test --skip-build --filter SquirrelOpsDeceptionGuestTests` | 23 passed in four suites |
| Real SIGTERM/SIGINT tests against the extracted installer runtime | Both passed; Python isolated mode and module-path assertion exclude checkout imports |
| Extracted app `codesign --verify --deep --strict` | Passed for the ad-hoc signatures |

The existing type-check warnings and dependency deprecation warnings remain.
Native test fixtures do not establish installed-system or live-PF acceptance.
The signal probe uses simulated guest/database resources, not a running VM.

Raw local logs are in `build/test-artifacts/shutdown-fix-20260929-*`. The final
full sensor rerun also records JUnit XML there. These ignored local artifacts
are not public release assets.

## Exact local installer

File, relative to the current checkout:

```text
build/test-artifacts/SquirrelOpsHome-2.1.0-shutdown-fix-20260929-local-test.pkg
```

SHA-256:

```text
541fc783c41fd2f9a6baba1fe8edae93078a0a24089b8e6d4ede77ba051b7fb1
```

Built for ARM64 with Apple Swift 6.4 and the macOS 27.0 SDK. Distribution,
app and sensor versions remain 2.1.0. The build uses the pinned standalone
Python 3.12.12 runtime and verified all 39 locked runtime distributions.
The source baseline is `cb1f8e6bf0d53c8762909a4a0efebeea4e1b9b32`, plus this
signal-cleanup fix. That baseline's tree matches merged main
`c6db88efbd77826cdc5c7e7b93eb377131835e89`.

This is an **unsigned, unnotarized local-test package** with ad-hoc executable
signatures. It was built and extracted, not installed. The previous mini-test
package remains separately preserved with SHA-256
`3e8c0fc78befad3365fdbff5583d9f85c6b6fe01816b5863edbebeceaa4b8f5f`.
Do not substitute either local-test package for the signed release artifact.

## Live acceptance remains open

The earlier mini run on macOS 27.0 build 26A428 installed successfully but
failed protocol acceptance. From the authorized laptop, SSH and SMB completed
TCP handshakes, acknowledged client data, and sent no application response.
Both Python HTTP endpoints also timed out. The mini showed pending listener
queues across both the Swift guest and Python process, with zero recorded
connections or alerts. Guest-only and failed-TCP-handshake explanations do not
fit that evidence.

The mini has multiple activated network extensions, including Little Snitch
and Avast. A pending content-filter verdict is a hypothesis, not an identified
cause: Apple's published `soisconnected()` implementation delays making a
connection available to `accept()` while such a verdict is pending. That
source is not a build-matched trace of the mini's macOS kernel. See
[Apple's socket implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_socket2.c).

Read-only unified-log queries did not identify a matching filter decision.
Little Snitch traffic history requires root; the unprivileged command refused
to run. A bounded query for only the test window and laptop was requested from
the operator. No filter was disabled or reconfigured.

The previous attended cleanup completed at 14:38:18 UTC. Its root-produced
status reports guest stopped, aliases absent, original native listeners
present, own PF reference released and PF disabled. Independent unprivileged
checks verified service/process/address/native-listener state; they did not
repeat the root PF checks. Installation and private backups were retained.
Keep the mini app closed until the next reviewed acceptance session.

## Remaining release sequence

1. Identify and resolve the stalled live flows without removing containment.
2. Test the updated exact package on the mini, including normal signal-driven
   teardown, real SSH/SMB/HTTP payloads, source attribution and alerts.
3. Complete the separately scoped, approved
   [A5 live PF matrix](2026-09-26-pf-safety-development.md#live-acceptance-gate-not-executed).
4. Obtain independent review of this fix and green CI on its exact commit.
5. Merge through protected main, then use the reviewed signed-tag, dedicated
   dispatcher, independent environment approval, signing, notarization and
   immutable-publication workflow in [Release security](../RELEASE_SECURITY.md).

Passing local tests does not close the live acceptance gate. No signed release
tag, release workflow dispatch, website promotion or public 2.1 publication is
claimed here.
