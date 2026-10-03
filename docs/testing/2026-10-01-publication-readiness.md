# Home 2.1 publication readiness

Update: the [October 2 follow-up](2026-10-02-release-gates.md) records PR #52's
merge and green post-merge CI. The GitHub snapshot below is historical; the
live A5 and final signed-artifact gates remain open.

Checked October 1, 2026, Eastern time (October 2 UTC). **Not ready to publish.**
The resolver-fix Mini acceptance is complete. Live PF failure-case acceptance,
review/CI for the final source, and release-signed artifact acceptance remain.
This record supersedes older status summaries, not their dated test evidence.

## Completed acceptance

The [resolver-fix Mini run](2026-10-01-mini-resolver-live-result.md) passed all
17 second-machine checks under the existing narrow Little Snitch test policy.
The exact package installed, preserved the seven saved decoys and passed a
normal sensor restart. SSH, SMB, SFTP, synthetic authentication, file roundtrips,
three AI endpoints and direct-backend containment passed. Anonymous SMB listing
took 0.525 seconds; the earlier 20-second stall did not recur.

All ten new connections reconcile with the sensor's per-service totals and the
operator-provided alert detail: one unread folded alert, 22 total connections.
The operator reported no new filter prompt. Final receipt and subsequent
read-only checks established stopped/disabled jobs, no guest or aliases,
preserved native listeners/data, and release of only the test's PF reference.
This does not establish default-filter or unattended behavior.

Local artifact retained, not for public distribution:

```text
SquirrelOpsHome-2.1.0-guest-resolver-20261001-local-test.pkg
SHA-256 47774088cd9eadc5aaddf38949e00a8b8f6eeb56c2192a5a72830d06d84a8aec
```

It is ARM64, unsigned at the installer level, with ad-hoc payload signatures
and no notarization. The checksum, guest verifier and all ten recorded resolver
source/test hashes were rechecked successfully during this pass. This does not
retroactively turn it into an official release built from a clean commit.

## Fresh local verification

| Check | Result |
| --- | --- |
| `cd sensor && uv run pytest tests/ -q` | 2,454 passed, 3 skipped, 3 dependency warnings; 91.08 seconds |
| Full native `swift test`, reviewed CLT/macOS 26.5 SDK | App 400 passed; helper 121 passed; guest runtime 30 passed |
| Five further helper-suite repetitions | 605 test executions passed |
| Acceptance fixtures with retained evidence and extracted resolver package | 366 passed, 3 optional skips |
| Acceptance fixtures copied without private captures or packages | 357 passed, 12 explicit optional skips |
| `sensor/.venv/bin/ruff check sensor scripts/verify-guest-bundle.py` | Passed |
| `uv lock --project sensor --check` | Passed; no dependency changes |
| Guest bundle verifier, changed shell syntax, `git diff --check` | Passed |

The three sensor skips are the two opt-in real-VM tests and the disposable
launchd test. Their earlier passing runs and limits are recorded in the
[resolver build report](2026-10-01-guest-resolver-fix.md) and
[shutdown-budget report](2026-09-30-launchd-shutdown-budget.md); they were not
rerun in this commit pass. No installed service, PF rule or remote test was
started here. Existing native toolchain warnings remain.

The first native run failed the helper's closed-peer fixture once. An isolated
rerun passed. Retaining a duplicate peer descriptor deterministically reproduced
the same failed expectation: `close` alone does not disconnect a socket with
another reference. The test now requires successful socket setup and explicitly
shuts down the peer before closing it, including with a duplicate retained.
The full native rerun and five helper repetitions passed. Descriptor inheritance
during concurrent subprocess tests is consistent with the original failure;
the particular subprocess was not captured. No production helper code changed.

A disposable copy without private captures initially produced nine fixture
errors. SMB input validation now uses synthetic data. Eight historical
capture-replay checks explicitly skip when their required private files are
absent; present files still undergo the same digest/content checks. The other
four clean-copy skips require extracted packages or the separately opted-in
root launchd experiment. Local replay still passes with the retained evidence.
No live-runner preflight was relaxed and no pinned runner was rewritten.

Logs are retained locally under `build/test-artifacts/commit-readiness-*`.
Raw captures, private logins, databases, backups, binaries and installers are
not committed. Fixture source and sanitized Markdown reports are included;
historical run commands are not authorization to reuse consumed sessions.

## Current GitHub state

Read directly from GitHub during this pass:

- [PR #52](https://github.com/rocketweb/squirrelops-home/pull/52) is open,
  `REVIEW_REQUIRED`, with no submitted reviews. Its remote head is
  `a50179417e8f726ceb03bb6914a42cb996d2ead6`. Four checks are green for that
  older head; they do not cover the new local commit.
- `main` is `c6db88efbd77826cdc5c7e7b93eb377131835e89`, the PR #51 merge.
- Latest published release is immutable
  [Home 2.0.3](https://github.com/rocketweb/squirrelops-home/releases/tag/home-v2.0.3).
  No `home-v2.1*` tag exists.
- Main still requires independent latest-push approval and the strict
  `Verify release and package controls` check, with no bypass actors.
  Release-tag protection is active. The protected `release` environment still
  names `chrissyrocket`, prevents self-review and restricts deployment branches.
  Observed policy IDs and revision timestamps match the checked-in pins.

This pass reads GitHub and prepares a local commit only. It does not push,
merge, create tags, dispatch release workflows, publish or promote a download.

## Remaining gates, in order

1. **Live PF failure cases.** The canonical
   [A5 matrix](2026-09-26-pf-safety-development.md#live-acceptance-gate-not-executed)
   remains release-blocking. Normal LAN traffic, direct-backend denial and
   scoped teardown now have passing evidence. The remaining cases include
   second-ingress denial, different-UID/missing/ambiguous listeners,
   established-state/retransmission/port-reuse behavior with quarantine and
   state-cleanup failures, multiple-endpoint recovery, and migration from the
   old unconditional-rule version. These require a new exact isolated-host
   maintenance scope, backups and approval. Do not restart held jobs or reuse
   a historical runner to approximate this gate.
2. **Final source review and CI.** Once pushing is authorized, update PR #52
   with this commit, run applicable App/Sensor/Supply Chain and dependency
   checks, and obtain Chrissy's independent review of the new head. Merge is
   a separate approval and must preserve the tested source. The earlier
   OpenSSH shared-loopback penalty defect was fixed and tested in the
   [availability pass](2026-09-26-availability-review-fixes.md); it is not a
   newly reopened gate here.
3. **Official artifact and publication.** After acceptance and merge, separately
   authorize the exact tags and release dispatch. The protected Home workflow
   must build ARM64 from that source, sign/notarize, verify the package and
   attest assets. Keep its separate publish environment approval held until
   the final signed artifact's required acceptance is recorded. The local
   ad-hoc installer cannot substitute for this artifact. After publication,
   verify the immutable release and authorize website/Homebrew promotion
   separately. Intel Macs are unsupported; Linux publication remains blocked.

The engineering-constraints skill informed the failing-first fixture checks,
fresh regression runs and explicit separation of local acceptance from release
readiness. None of these results is a waiver of A5 or publication approval.
