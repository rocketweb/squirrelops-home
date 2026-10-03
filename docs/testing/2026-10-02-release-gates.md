# Home 2.1 release follow-up

Date: October 2, 2026. Scope: **macOS only, Apple Silicon**.
Linux publication remains blocked in `.github/release-policy.json`. No Linux
workflow, OCI image or installer is part of this release.

Latest: Matt authorized continuing through publication. The
[publication follow-up](2026-10-02-publication-followup.md) records fresh tests,
the exact source-review scope and the remaining acceptance/approval boundaries.
Authorization to proceed does not mark those boundaries complete.

## Verified source and CI

PR [#52](https://github.com/rocketweb/squirrelops-home/pull/52) was independently
approved by `chrissyrocket` and merged at 04:28:32 UTC. The merge commit is
`d3ec67f656f0d5a23211cfa9ea86b61d47cb87ad`; its tree matches the accepted PR
head `7a7b3d072f818215c8fd9b4573d287e63d068203`.

All three post-merge workflows completed successfully at that commit:

- [App CI](https://github.com/rocketweb/squirrelops-home/actions/runs/36964712647).
- [Sensor CI](https://github.com/rocketweb/squirrelops-home/actions/runs/36964712654).
- [Supply Chain CI](https://github.com/rocketweb/squirrelops-home/actions/runs/36964712640).

The [October 1 Mini result](2026-10-01-mini-resolver-live-result.md) remains the
normal-operation acceptance record. Its 17 checks, restart, folded-alert totals
and scoped cleanup are not being reopened. Those results do not cover the
separate [A5 failure matrix](2026-09-26-pf-safety-development.md#live-acceptance-gate-not-executed).

## Documentation correction

`RELEASE_SECURITY.md` still combined Home verification with Linux installer
and OCI verification commands. The Home workflow publishes neither. The new
documentation separates the two procedures, lists the six actual Home assets,
and checks Home attestations, checksums, the installer signature and Gatekeeper.
It leaves the Linux block and both release workflows unchanged.

The new regression failed first because the Home commands included
`install.sh`. After correction, all 47 tests in
`sensor/tests/unit/test_supply_chain_security.py` passed (4.93 seconds).
Ruff and `git diff --check` also passed. The follow-up is locally verified but
still requires push, independent review and merge. It is not published
documentation yet. The [fresh precommit pass](2026-10-02-precommit-verification.md)
also completed the full sensor/native suites and all three opt-in local
runtime tests; live PF failure cases and the signed artifact remain pending.

## Synthetic screenshots and map correction

The screenshot pass also found and corrected a display-only network-map defect.
Current device types and unknown future types now remain visible. The
[regression and capture report](2026-10-02-network-map-screenshots.md) records the
observed failing test, 555 passing native tests and seven recaptured synthetic
website images. The release notes include the correction. These source changes
also require review and merge; the prior PR's green CI does not cover them.

## Read-only test-host refresh

The Mini remains ARM64, macOS 27.0.1 build 26A434, boot epoch 1790777754.
The sensor and helper are disabled and absent from the system launchd domain.
No deception guest PID was returned and loopback has only 127.0.0.1. Its app
executable is root-owned mode 0755. The database is inaccessible to the SSH
user, so this pass does not claim a fresh database check.

Ethernet is `en0` at 192.168.1.115 and Wi-Fi is `en1` at 192.168.1.254; both
are active. The existing service UID/GID is 309. The laptop routes through
`wlp0s20f3` as 192.168.1.7 and has the existing protocol/capture tools. No
probe, installed service, rule, alias, route, configuration or database was
changed. Root PF inventory and address availability still need a fresh check
immediately before a newly approved test window.

The approved [Mini A5 experiment](2026-10-02-mini-a5-preparation.md) completed
all eight planned phases after two fixture issues were corrected. The
[eight-phase result](2026-10-02-mini-a5-eight-phase-result.md) records successful
listener handoff, real retained closing-state probes, packet-correlated denial
observations, recovery and scoped cleanup. No new Little Snitch prompt appeared.
Filter attribution remains qualified; established/half-open replacement,
simultaneous ambiguity, old-package upgrade and exact signed-installer acceptance
are not covered. The [earlier partial result](2026-10-02-mini-a5-partial-results.md)
preserves the previous bind failure and the 38-test fixture verification.

The [counter review](2026-10-02-mini-a5-counter-review.md) now records positive
PF blocking and zero wrong-UID LAN accepts from a checksum-verified read-only
export. Its unknown-line/comparability limitation remains explicit. The
[remaining test plan](2026-10-02-mini-a5-remaining-plan.md) now has Matt's
separate approval for the narrow temporary laptop RST-filter scope. The
[combined edge-run bundle](2026-10-02-mini-a5-edge-preparation.md) subsequently
completed its [five live phases](2026-10-02-mini-a5-edge-result.md) with verified
cleanup on both machines. Four simultaneous exact/wildcard listeners were
rejected by the production guard. Darwin refused cross-UID binding while
accepted sockets remained, and closing half-open listeners changed their
states before replacement. Those are qualified observations, not successful
retained-state replacement tests. The fixture suite again passed all 65 tests.

## Remaining boundary

Matt has superseded the [macOS VM proposal](2026-10-02-macos-upgrade-vm-preflight.md)
with explicit permission to wipe the Mini's SquirrelOps installation and data,
install official 2.0.3, and test an in-place upgrade. The
[native clean-baseline preparation](2026-10-02-mini-clean-upgrade-preparation.md)
records the exact removal scope, verified recovery copy, official signed old
installer and local fixture checks. No VM storage choice is needed. The Mini
reset subsequently reached a verified seven-path archive and partial removal,
then stopped at service-account teardown. Two reproduced compatibility defects
in display-name and missing-group-attribute handling are fixed locally with
regressions and a passing read-only check against the Mini. The attended resume
then completed the corrected cleanup but failed installing official 2.0.3.
Its exact private installer failure is not yet diagnosed; the Mini upgrade did
not run. Matt paused that path. The recovery archive is retained and the
wrapper reported both product jobs stopped/disabled.

Read-only SSH checks confirmed an existing, healthy 2.0.3 installation on
Matt's MacBook at 192.168.1.97, macOS 26.6.1 build 25G76, ARM64. Matt separately
approved backup and an in-place upgrade there, explicitly without uninstalling
or wiping it. The [MacBook preparation](2026-10-02-macbook-upgrade-preparation.md)
records the newly rebuilt local-test package, embedded script parity, fresh
package tests, and attended upgrade procedure. The subsequent
[MacBook result](2026-10-02-macbook-upgrade-result.md) records a successful live
2.0.3-to-2.1.0 upgrade and Matt's accepted UI check. All 60 devices, 59 trust
records, 22 existing decoys, nine alerts and 26 planted credentials passed the
defined preservation comparisons; configuration content was unchanged. Five
additional decoys and credentials appeared. The product anchor changed from
15 unconditional `rdr pass` rules to 20 translations with none unconditional.
The [completed saved-evidence review](2026-10-02-saved-release-evidence-result.md)
confirms .203 is present again, identifies the five new decoys as Studio on .214,
and confirms that both saved PF state inventories were empty. It also resolves
the Mini's unknown counter-format and child-event omissions. Upgrade with
existing state remains untested; this was not final signed-artifact or LAN
protocol acceptance. The Mini, other
apps, native services and unrelated filter policy stayed outside the operation.

1. Complete the remaining A5 cases on an approved isolated scope, using the
   eight-phase result rather than repeating completed controls without cause.
   Established/half-open replacement now has documented kernel constraints
   requiring review disposition; simultaneous listener ambiguity is covered.
   Filter-attribution qualifications remain explicit. The MacBook now covers
   actual old-package upgrade, saved-record preservation and old-rule replacement;
   it does not prove retained-state invalidation because both saved state lists
   were empty. All original aliases are present in the later read-only check;
   the cause of .203's temporary absence is not established. The former
   Mini database remains archived, never opened by the older runtime as a downgrade.
   The [retained-evidence review](2026-10-02-saved-release-evidence-preparation.md)
   is complete on both hosts. No further root export is needed for its
   counter-format or child-event questions, and no live probe or service change
   was made by that review.
2. Review and merge the documentation and map follow-up and any changes required
   by live acceptance. Keep the exact final source tied to CI and artifact identity.
3. Use the approved Home publication path to create signed component/Home tags
   and dispatch the protected workflow. Hold its separate publication approval
   until the exact Developer ID signed and notarized ARM64 installer has passed
   the required acceptance. The existing local ad-hoc installer is not public.
4. Verify the immutable release and its attested metadata before advancing the
   public download, update manifest or Homebrew candidate. The current public
   release is still Home 2.0.3. The requested synthetic 2.1 website screenshots
   can be prepared locally without advertising a nonexistent download.

This record updates the review/CI status in the
[October 1 readiness report](2026-10-01-publication-readiness.md). It does not
waive A5 or claim that the release has been published.
