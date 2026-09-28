# Home 2.1 availability review fixes

Date: 2026-09-26. Base: `c89cfa59bb031403d543ca8cc5c9aad81834f91e`, PR #49.
Scope approved by Matt: implement M2/N1 and qualified N2, fix App/Sensor CI,
test, rebuild a local installer, and commit/push for Chrissy's re-review.
No installation, PF mutation, merge, tag, release dispatch, or publication.

Update 2026-09-27: the [exact packaged-runtime live test](2026-09-27-packaged-runtime-acceptance.md)
passed after Matt approved temporary ownership of the disposable guest copy.
Ownership was restored; installer bytes are unchanged.

## Changes and deception review

- **M2:** a monotonic watchdog cancels a relay after 300 seconds without byte
  progress, or 30 seconds without progress after either direction reaches EOF.
  Progress resets the applicable deadline. Active sessions have no absolute
  duration limit. Shutdown interrupts reads/writes; descriptors and the
  admission allowance remain owned until both workers finish.
- Repetition caught a Darwin cancellation race: a blocking socket read could
  remain asleep despite shutdown. A standalone socket-pair diagnostic also
  reproduced it. Workers now use nonblocking I/O and 100 ms cancellation polls,
  and serialize EOF propagation with cancellation. No protocol bytes are parsed.
- Guest socket setup has a 10-second deadline. Since VZ connect cannot be
  cancelled, expiry invalidates the connector, resumes all pending waiters,
  refuses further requests, closes late results, and stops the unhealthy VM.
  This prevents a timeout/retry loop from accumulating unresolved callbacks.
- **N1:** sshd exempts only `127.0.0.1/32` from source penalties, because every
  relay uses that shared address. `MaxStartups 16` removes the earlier random
  refusal threshold without changing the existing 16-slot host ceiling.
- **N2:** each received attempt produces one outcome: `guest_connected`,
  `capacity_rejected`, `guest_connect_failed`, or `guest_connect_timeout`.
  Outcomes travel in the existing protocol-qualified `interaction_type`,
  through strict parsing, persistence, and the alert timeline. Rejected attempts
  still count as hits. Legacy `.connection` records stay ambiguous rather than
  being relabeled successful. Guest-connected does not mean authenticated.
- App CI: replace recursive `forEach` in the desktop-layout test with explicit
  traversal compatible with Xcode 16.2. Sensor CI: isolate lifecycle fixtures
  from real `en0`/LAN resolution; production fail-closed binding is unchanged.
- The first pushed App CI run compiled and ran all 538 tests, but its combined
  run timed out in one sub-second socket deadline test while other suites executed.
  CI now runs the three test targets separately, as in local acceptance. No
  test is removed. Run `36286665185` preserves the failing combined-run evidence.
- Sensor CI exposed one more directly constructed orchestrator outside the shared
  fixture. LAN isolation now covers the entire lifecycle module, including that
  instance; the offline/online test overrides the same resolver seam. The local
  forced-missing-LAN reproduction changed from one failure to all tests passing.

Transport timing and SSH refusal behavior change deliberately under the approved
deception review. No banner, credential, protocol parser, forwarding policy,
disk, network device, CPU/memory ceiling, or new rate limit was added. SSH and
SMB remain opaque byte streams. The byte-preservation and real-protocol tests
below cover normal transfers; the new timing is an explicit resource-lifecycle
policy, not a claim of indistinguishability from every real Mac configuration.

## Reproduced before fixing

- `availability-swift-red.log`: two deadline regressions failed against the old
  relay with inert test seams. Guest EOF and completely idle sessions retained
  admission until explicit cleanup.
- `availability-connector-red.log`: missing callbacks left pending work and
  failed to invalidate the connector before expiry behavior was enabled.
- `availability-python-red.log`: nine failures for new telemetry outcomes and
  the absent SSH exemption/admission configuration.
- `availability-preauth-red.log`: the real previous guest rejected a banner
  probe after activating a 15.631-second loopback-source penalty.
- `availability-ui-red.log`: all four new outcome labels were absent.
- `availability-guest-repeat.log` and `availability-socket-repeat-diagnostic.log`:
  repeated runs caught blocked cancellation and transfer cleanup. The bounded-I/O
  fix then passed 50 complete guest-suite repetitions. A separate test race in
  `availability-guest-repeat-final.log` inspected an already-closed descriptor
  number that another suite had reused; admission tests now observe peer EOF.
- Existing GitHub App CI logs show the Xcode 16.2 traversal compile error.
  Missing-LAN resolution was also reproduced locally: lifecycle tests deferred
  deployment instead of passing. These fixtures now bind loopback explicitly
  through test-only injection, without depending on the developer's network.

All artifact paths below are relative to ignored `build/test-artifacts/`.

## Verification

| Check | Result | Log |
| --- | --- | --- |
| Full source sensor | 2,321 passed, one opt-in VM skip, 84.99 seconds | `availability-sensor-full.log` |
| Extracted sensor code | 2,321 passed, one opt-in VM skip, 85.93 seconds; test-environment Python importing final package code | `availability-packaged-sensor-final.log` |
| App suite | 394 passed, 37 suites | `availability-app-tests-final.log` |
| Helper suite | 121 passed, 8 suites; read-only LAN observation | `availability-helper-tests-final.log` |
| Guest-runtime suite | 23 passed, 4 suites | `availability-guest-green.log` |
| Final guest-runtime repetition | 50 full runs passed: 1,150 test executions | `availability-guest-repeat-confirmed.log` |
| Disposable real guest | Passed, 59.80 seconds, final bounded-I/O runtime | `availability-live-guest-final.log` |
| Release/package contracts | 132 passed, 6.72 seconds | `availability-contracts.log` |
| Sensor type check | Pyright: zero errors, 29 warnings | `availability-pyright.log` |
| CI fixture follow-up | 15 auto-deploy tests passed with missing LAN; 47 lifecycle/resolver tests passed normally; 132 release/package contracts passed again | `availability-auto-deploy-no-lan-green.log`, `availability-lifecycle-followup.log`, `availability-contracts-ci-followup.log` |
| ARM64 and x86_64 guests | Both rebuilt from the pinned Alpine digest and unchanged package inventory | `availability-guest-arm64-build.log`, `availability-guest-x86_64-build.log` |
| Extracted package | Exact app/Python/script/lock parity, guest digests, metadata, entitlement and 48 native-Python signatures, pip check, 19 isolated imports passed | `availability-package-verification-final.log` |

The real VM test performs 24 unauthenticated banner grabs and five wrong-password
attempts followed by successful authentication. It fills the host pool with
one guest-closed SSH client that deliberately sends no FIN plus 15 silent SMB
peers, verifies one capacity-rejection event, waits through the real 30-second
half-close deadline, and then obtains a new SSH banner while the other peers
remain open. It also verifies SSH persona commands, SFTP/SMB read/write/delete,
20 authenticated reconnect cycles, half-closed SMB negotiation, host-canary
and no-NIC isolation, telemetry, and clean shutdown with two open relays.

The Swift tests additionally exercise blocked writers, active responses lasting
longer than the injected idle interval, cancellation, delayed workers, exact-once
release, late callback cleanup, and refusal of new work after connector expiry.
This is finite regression coverage, not a guarantee against all saturation or
scheduler behavior. A visitor that continuously makes progress can still occupy
one of the deliberately bounded 16 slots.

### Reproduction commands

Sensor: `cd sensor && .venv/bin/python -m pytest -q --tb=short -ra`.
Build tests with the CLT/macOS 26.5 SDK command in `docs/DEVELOPMENT.md`, using
scratch `.build/ui-refresh`. Run each compiled test executable with:

```bash
DYLD_FRAMEWORK_PATH=/Library/Developer/CommandLineTools/Library/Developer/Frameworks \
DYLD_LIBRARY_PATH=/Library/Developer/CommandLineTools/Library/Developer/usr/lib \
/Library/Developer/CommandLineTools/usr/libexec/swift/pm/swiftpm-testing-helper \
  --test-bundle-path /absolute/path/to/Tests.xctest/Contents/MacOS/Tests \
  --testing-library swift-testing
```

The live test uses the newly built ad-hoc-signed debug runtime and rebuilt
ARM64 guest with the documented `SQUIRRELOPS_DECEPTION_RUNTIME` and
`SQUIRRELOPS_GUEST_BUNDLE` variables. It binds only loopback. The package check
script is `build/test-artifacts/verify-availability.sh`. Source/build/test
inputs are hashed in `availability-source-sha256.txt` (439 entries). The original
installer-build manifest is retained as `availability-build-source-sha256.txt`;
the final manifest includes the CI/test-only follow-up. Product-source parity
with the extracted installer was checked again after that follow-up.

## Local installer

`build/test-artifacts/SquirrelOpsHome-2.1.0-availability-local-test.pkg`

Version 2.1.0, ARM64, 136,506,367 bytes. SHA-256:

```text
cc285b1c0061c1d424b602d43b1dc7e9a5573851a40e4a6a81f445eed32855e7
```

This package is unsigned, with ad-hoc-signed executables. It is not notarized
and was not installed. The previous package directory is preserved at
`build/pkg-preserved-20260926-before-availability`. Prior guest artifacts are
preserved under `guest/studio-mini/build/*-before-availability`.
The intermediate package from before the bounded-I/O follow-up is separately
preserved as `build/test-artifacts/SquirrelOpsHome-2.1.0-before-bounded-io-local-test.pkg`.
Its product sources are commit `3c2df5543aa1c343f13f5b2d699158d3bb709ca5`;
the subsequent CI-isolation follow-up changes only tests/workflow/documentation,
so the same verified installer bytes remain applicable.

The build used CLT/macOS 26.5, scratch `.build/availability-release`,
`SQUIRRELOPS_LOCAL_TEST_BUILD=1`, and `SKIP_PKG_SIGNING=1`. Apple identity,
notarization, and release-build environment variables were explicitly unset.
Both guests used the same Alpine digest pinned by the release workflow. No
dependency inventory was changed to make a build pass.

## Explicit limits and approval boundary

At the September 26 checkpoint, auto-review denied creating a temporary
root-owned guest copy without explicit approval. Matt approved that exact
operation on September 27. The unchanged extracted release-mode runtime then
passed the live test in 60.78 seconds using packaged sensor code and root-owned
copies of the three extracted guest artifacts.

Only `guest`, `guest/manifest.json`, `guest/vmlinuz`, and
`guest/studio-mini.initramfs` beneath
`/private/tmp/squirrelops-availability-release.1SiEhD` changed ownership.
All four were restored to UID 501, GID 0 afterward. Original files, installer
bytes, and installed services were untouched. The same release executable
subsequently rejected the restored user-owned copy before boot. See the
[follow-up report](2026-09-27-packaged-runtime-acceptance.md) for exact evidence.

A5 live PF acceptance, installed upgrade, second-machine virtual-IP ingress,
Intel execution, independent review, Developer ID signing/notarization, and
other outstanding review findings remain separate release gates. Source review
and local testing do not authorize bypassing them. Exact-candidate remote CI
must be checked after the authorized push; no success is assumed here.
