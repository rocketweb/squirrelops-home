# Home 2.1 follow-up verification

Date: October 2, 2026. Scope: macOS ARM64, local source and disposable runtimes.
This is not a live PF failure-matrix result or signed-installer acceptance.

## Source under test

Branch `release/2.1-docs-a5`, based on merged main
`d3ec67f656f0d5a23211cfa9ea86b61d47cb87ad`, with the documented network-map fix,
regression, release-documentation correction and screenshot fixture.

The production sensor and guest-runtime sources still match
`7a7b3d072f818215c8fd9b4573d287e63d068203` exactly. The existing Python environment
was reused only after this parity check. Pytest used this worktree's tests and
source path; the isolated launchd child imports the identical sensor source
through that environment's editable installation.

## Fresh results

| Check | Result |
| --- | --- |
| Full sensor suite | 2,455 passed, 3 explicit opt-in skips, 3 dependency warnings; 87.40 seconds |
| Full native suites | App 404 passed; helper 121 passed; guest runtime 30 passed |
| Acceptance-fixture suite | 357 passed, 12 historical/opt-in skips, 396 subtests passed; 4.94 seconds |
| Comprehensive disposable real guest | Passed: SSH, SFTP, SMB, synthetic file operations, capacity/reconnect and isolation checks |
| Fresh guest SMB identity and resolver | Passed; first handshake 0.005 seconds; expected Studio identity |
| Disposable user-domain launchd shutdown | Passed, including slow scan drain and normal cleanup ordering |
| All three opt-in cases together | 3 passed in 55.02 seconds |
| ARM64 guest-bundle verifier | Passed against the retained resolver package's image |
| Release-mode app/helper/guest compilation | Passed with the reviewed CLT macOS 26.5 SDK; 43.71 seconds |
| Ruff, dependency lock, screenshot shell syntax, whitespace | Passed |

The three skips in the broad sensor run were subsequently executed explicitly
and passed. Fixture skips refer to historical private captures, extracted older
packages and a separate root launchd experiment; they are not counted as live
acceptance. No historical failure-injection script was rerun.

Initial sandboxed attempts denied loopback socket creation. Those failures were
retained as environment evidence, not patched around or counted as passes. The
complete network-enabled reruns above passed without changes to product code.

Native test commands use the reviewed CLT macOS 26.5 SDK documented in
[Development](../DEVELOPMENT.md#macos-27-development-tool-caveat). Existing CLT
linker warnings remain. Source-level and local runtime checks do not establish
the final distribution's signature or notarization.

## Disposable guest identity and cleanup

The runtime was copied from this worktree's freshly built debug target and
ad-hoc signed only for testing. Its SHA-256 is
`8c29df994701d2129cc89ad6301147040e6e2937e19b7f94c894a5cc8351171d`.
The tests used loopback listeners and a memory-only guest with no network
adapter or host shares. Production release ownership checks were not weakened.

The retained image passed manifest, containment, architecture, network-identity
and digest verification:

- Kernel: `4c78ec153e7b8cf17011d44423ec2e11c9618933d4b931c60e63c240bf6db2f5`.
- Initramfs: `3e30d8a0f367504cda3c8b6b9937427bf34fc31bef6cb671355cb8ce7695d4a4`.

Both guest tests completed normal controller shutdown. After the run, anchored
process lookup returned no test runtime and the user launchd inventory had no
`com.squirrelops.test.shutdown.*` job. No installed sensor, helper or app was
started. No LAN alias, packet-filter rule or filter preference was changed.

## Remaining tests and prerequisites

Fresh read-only SSH inspection found the Mini on macOS 27.0.1 build 26A434,
with both product jobs still disabled. Administrative PF inspection stopped at
`sudo: a password is required`; no attempt was made to bypass it.

The [A5 matrix](2026-09-26-pf-safety-development.md#live-acceptance-gate-not-executed)
still requires a new, attended, isolated maintenance scope. A proposed scope
has been presented for approval: Mini only, provisional `.239` and `.240` VIPs
after conflict checks, disposable listeners, packet evidence and injected
listener/state-cleanup failures. Existing data and held jobs, Little Snitch,
the Studio and `.241` remain outside that scope. No live runner is authorized
merely by the contents of this report, and no old runner is reusable.

The official Home release workflow has no current 2.1 artifact. The latest
published release remains `home-v2.0.3`. Signed-installer acceptance therefore
must wait for the exact reviewed/merged source to pass the protected build and
notarization workflow, with publication held until testing completes.

## Evidence

Local logs are retained in `build/test-artifacts/precommit-20261002-*` and are
not committed. The [map and gallery report](2026-10-02-network-map-screenshots.md)
records the failing-first UI regression, native captures and browser checks.
The [release follow-up](2026-10-02-release-gates.md) tracks the remaining gates.

Local commits are authorized. Push, merge and publication are separate states;
none is implied by this test report.
