# Home 2.1 final-installer readiness

Date: 2026-09-26. Decision: **not yet ready to call an installer final**.

Current source status: [review-fix batch 2](2026-09-26-pf-safety-development.md)
postdates candidate 2 and the first review-fix batch. PF ownership-guard and
recovery changes are implemented; A5 remains blocked on live acceptance.
A10/A12 are also fixed in source. The remaining review items are not all closed.
No new installer or installed acceptance was performed for either fix batch.

Previous installer handoff: [candidate 2](2026-09-26-acceptance2-installer.md) is built and
locally verified for upgrade testing. Fresh results: 383 app tests, 114 helper
tests, six guest-runtime tests, and 2,259 extracted-sensor tests passed (one
opt-in live-guest skip). Exact-package installed acceptance and second-machine
LAN checks still precede final release approval. The review and superseded
blockers below remain historical evidence; the candidate 2 record describes
that older artifact and its install instructions, not the updated source.

Latest acceptance: a new local-test installer was built and its extracted sensor
passed 2,259 tests. Matt accepted the spoken refresh confirmation, but reported
that a short physical pull increased the read counters. The trace identified
raw accelerated input being mistaken for visible pull distance. The corrected
native measurement initially passed the short-pull check but prevented full
pulls because its visible-distance threshold remained too high. Calibration
from the captured physical traces now passes 383 app tests and foreground
positive/negative replays. Matt has now accepted the final short/full physical
pull behavior with **“yes works”**. Candidate 1 predates this correction and is
superseded; candidate 2 contains the accepted correction. See
[installer candidate acceptance](2026-09-26-installer-candidate-acceptance.md).
No new installer has been installed.

Update after approved fixes: the packaging output-path defect is resolved and
a release app bundle builds through the corrected script. Foreground keyboard
checks pass; a genuinely unnamed decoy lifecycle switch was fixed. The latest
round passes 2,259 sensor tests and 379 app tests. See
[readiness fixes and evidence](2026-09-26-release-readiness-fixes.md) for current
results and the remaining spoken/physical acceptance limits. Exact-package
upgrade and second-machine LAN acceptance are still required. At that point,
no new installer had been created or installed. The original review is dated
evidence, not the current status of those corrected defects.

The broad local test round passes, including a new disposable-guest SSH/SFTP/SMB
acceptance run. Documentation was corrected. Packaging-tool compatibility,
foreground accessibility, exact-package upgrade acceptance, and second-machine
LAN acceptance remain open. This review did not implement product-code fixes,
build or install a package, change the installed sensor, commit, push, or
publish anything.

## Exact scope

- Candidate: `.worktrees/deception-depth-2.1-current`, branch
  `feature/deception-depth-2.1.0-current`.
- Base commit: `6b6ef8b5fe3d694695a9bc74982cbe80d05baeb5`, plus the existing dirty
  release work. The base commit alone does not identify the tested source.
- Home, app, and sensor versions: 2.1.0.
- Host: macOS 27.0 (26A428), arm64. Swift builds used CLT with the installed
  macOS 26.5 SDK. Sensor tests used Python 3.12.12.
- `build/test-artifacts/final-readiness-source-sha256.txt` records 409 source,
  test, configuration, build, and release-policy files. Its SHA-256 is
  `937a18ba425f9b773f5b354c9bfd9abef243793127da538432693fc7a0530346`.
  This is local evidence, not a signed release attestation.
- Read-only GitHub checks returned protected `main` at
  `eb2d87af5e24d924204afb4f2c0bcbd7403ac559` and latest published release
  [`home-v2.0.3`](https://github.com/rocketweb/squirrelops-home/releases/tag/home-v2.0.3).
  There is no exact-candidate CI claim for the uncommitted working-tree bytes.
  Remote review controls and signing credentials were not fully re-audited.

## Fresh verification

| Check | Result |
| --- | --- |
| Full sensor unit/integration/functional suite | 2,246 passed, one opt-in guest test skipped, 87.13 seconds |
| Opt-in guest test, run separately | 1 passed, 23.13 seconds; covers the skipped case above |
| Complete app test bundle | 376 tests in 35 suites passed, 15.692 seconds |
| Complete helper test bundle | 114 tests in 7 suites passed, 4.997 seconds, including opt-in read-only physical LAN observation |
| Guest-runtime containment test bundle | 6 tests in 1 suite passed |
| Release-mode app/helper/guest compilation | Passed, 46.25 seconds, separate scratch directory |
| Package/release/backup/LAN contract selection after doc edits | 131 passed, 7.25 seconds; subset of the sensor suite, not additional coverage counts |
| Ruff | `ruff check .` passed |
| Lock consistency | `uv lock --check --offline` passed |
| Installed development environment vs frozen lock | `uv sync --frozen --dry-run --offline` audited 52 packages and would make no changes |
| ARM64 and x86_64 cached guest manifests | Both verified, including file set and artifact digests |
| Package/build script syntax and whitespace | `bash -n` checks and `git diff --check` passed |

The live guest used a newly compiled debug runtime copied to
`/private/tmp/squirrelops-readiness-guest.MtKFSI`, ad-hoc signed with the existing
virtualization entitlement. It was bound only to loopback and used synthetic
test credentials and disposable files. The test covered:

- real OpenSSH authentication and persona commands;
- SFTP read, upload, download, and removal of its test file;
- SMB2 negotiation and authenticated Samba directory/read/write/delete paths;
- an absent host-only canary and only the loopback network interface in the
  guest;
- connection telemetry for both SSH and SMB.

The test shut its guest down, and a read-only process check confirmed no
remaining runtime at that temporary path. This did not restart an installed
guest, publish a virtual LAN address, or change packet-filter rules. Debug
acceptance permits source-build artifact ownership; it does not replace
release-signed, root-owned package acceptance. Intel execution was not tested.

Warnings remain for Starlette's httpx test client, legacy WebSockets/Uvicorn,
CLT linker search paths/arclite, and the existing weak/strong capture diagnostic
in `App.swift`. They did not fail these runs. No dependency update or fresh
vulnerability-feed audit was performed.

## Remaining gates

### 1. Packaging output-path mismatch on this toolchain

With the tested SDK/toolchain,
`swift build --sdk /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk -c release --show-bin-path`
returns `app/.build/out/Products/Release`.

`app/build-app.sh` and `scripts/build-pkg.sh` instead expect
`app/.build/arm64-apple-macosx/release` for a native ARM64 build. They also do
not expose the explicit SDK selection used for the passing builds. Therefore
passing compilation is not proof that the current packaging entry point will
package these bytes on this Mac. An older output directory must not be used as
an accidental fallback.

Recommended fix: resolve Swift's output path with the same flags/toolchain
used for compilation, consistently pass the supported SDK choice, and add
regressions for the modern and legacy layouts. Keep release validation intact.
Before invoking the package builder, preserve needed prior artifacts: it
cleans `build/pkg`. Do not accept the Xcode license automatically.

### 2. Foreground keyboard and VoiceOver acceptance

The earlier foreground pass could Tab through search, lists, and the sidebar,
but still skipped buttons/menus after toggling all-control navigation. The
cause remains unclassified between application adoption of that setting and a
candidate focus defect. VoiceOver was audibly confirmed by Matt, but full
names/order/detail/refresh-action coverage and the new success announcement
were not accepted. This readiness run did not change accessibility settings.

Resolve and retest these issues before making an accessibility-readiness
claim. The successful refresh confirmation has separate foreground evidence in
[the desktop report](2026-09-26-desktop-polish.md); its implementation does not
close the older acceptance gaps.

### 3. Exact-package upgrade and second-machine LAN checks

There is no new final package containing all of the current source changes.
The September 25 package and earlier installed results are historical evidence,
not acceptance of the current UI and packaging inputs.

After the fixes, build one uniquely identified candidate and verify extraction,
source/payload parity, signatures, guest resources, and checksums. Obtain
installation approval for that exact artifact, preserve rollback copies and a
verified database snapshot, then test the upgrade, enrollment/password prompts,
Settings, decoy/mimic creation, and retention across scans/restart.

From an authorized second LAN machine, use the installation's displayed decoy
addresses to verify SSH/SFTP/SMB negotiation and file activity, true source
attribution, alert/counter updates, and host-service isolation. Do not assume
the historical `.203` still identifies the desired decoy. The loopback guest
test does not exercise Bonjour, virtual-IP publication, PF forwarding, or this
complete LAN-to-alert path.

### 4. Final distribution state is separate

If the intended artifact is a public signed release, the source must also pass
the normal review/CI/protected-tag path, Developer ID signing, notarization,
and exact-artifact verification. None of those states follows from a green
local test run. Linux publication remains independently blocked; the Home
workflow does not publish Linux artifacts.

## Documentation corrections made in this review

- `DEVELOPMENT.md`: replaced the obsolete root-sensor/no-helper Linux
  description; documented the working local SDK test route and packaging
  limitation; made Sensor publication conditional on Linux approval.
- `USER_GUIDE.md`: corrected the Linux installation hold to distinguish an
  implemented sidecar from independent review and publication acceptance.
- `RELEASE_SECURITY.md`: corrected Linux-only gating and removed the obsolete
  claim that the current remote-control pins were still zero/null sentinels.
  Checked-in positive pins still require fresh remote verification.
- `releases/2.1.0.md`: retained the explicit View Details action but removed its
  unverified keyboard-accessibility claim. The refresh confirmation, desktop
  changes, and macOS 27 recovery notes are present.

Older dated recovery reports describe the state at the time of those tests.
They must not be used to infer current installation or final-release status;
this report is the current readiness summary.

## Reproduction and evidence

From `sensor/`, the general suite was run with live-guest environment variables
unset:

```sh
env -u SQUIRRELOPS_DECEPTION_RUNTIME -u SQUIRRELOPS_GUEST_BUNDLE \
  .venv/bin/python -m pytest -q --tb=short -ra \
  --junitxml=../build/test-artifacts/final-readiness-sensor.xml
uv lock --check --offline
uv sync --frozen --dry-run --offline
.venv/bin/python -m ruff check .
```

From `app/`:

```sh
DEVELOPER_DIR=/Library/Developer/CommandLineTools swift build \
  --sdk /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
  --scratch-path .build/ui-refresh --build-tests \
  -Xswiftc -plugin-path \
  -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing
DEVELOPER_DIR=/Library/Developer/CommandLineTools swift build \
  --sdk /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
  --scratch-path .build/final-readiness-release -c release
```

Each Swift bundle was executed with `swiftpm-testing-helper`, its absolute
`.build/ui-refresh/out/Products/Debug/<suite>.xctest/Contents/MacOS/<suite>` path,
`--testing-library swift-testing`, and the CLT framework/library paths documented
in the desktop report. `SQUIRRELOPS_TEST_LIVE_LAN=1` enabled the helper's read-only
observation case. No privileged network mutation test was enabled.

Logs and XML files are under `build/test-artifacts/final-readiness-*`, including
the separate `live-guest`, `package-controls`, all three Swift suite logs,
debug/release compilation, lock, environment, Ruff, and source-hash evidence.
