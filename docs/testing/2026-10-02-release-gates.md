# Home 2.1 release follow-up

Date: October 2, 2026. Scope: **macOS only, Apple Silicon**.
Linux publication remains blocked in `.github/release-policy.json`. No Linux
workflow, OCI image or installer is part of this release.

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

## Remaining boundary

1. Complete A5 on an approved isolated scope. Listener replacement and retained
   PF states must be tested against real packet delivery, not inferred from
   unit tests or normal SSH/SMB success. The old-rule package migration case
   must preserve the current database rather than downgrade it.
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
