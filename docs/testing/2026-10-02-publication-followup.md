# Home 2.1 publication follow-up

Date: October 2, 2026. Matt authorized continuing through publication. This
record prepares the final source review; it does not waive independent approval,
outstanding security acceptance or exact signed-artifact acceptance.

## Review scope

Base: protected main `d3ec67f656f0d5a23211cfa9ea86b61d47cb87ad`.
Branch: `release/2.1-docs-a5`, including existing local commit `00239f5`.

The production changes since that base are limited to:

- The dashboard network-map category correction, with current, legacy and
  unknown-type regression coverage and synthetic screenshots.
- Three installer lifecycle scripts accepting the two verified service-account
  display names and the exact macOS missing-group-attribute response. The UID,
  GID, membership, home, shell and record-existence checks remain enforced.
- Release documentation corrections and the corresponding supply-chain test.

The rest is acceptance-fixture source and dated sanitized Markdown evidence.
No captures, private databases, account records, reference tokens, installers,
compiled probe binaries or backup payloads belong in the commit. Historical
attended commands are evidence, not permission to run them again.

## Fresh verification before submission

The current checkout, not the older merged head, was tested:

| Check | Result |
| --- | --- |
| Full sensor suite, explicit current `sensor/src` on `PYTHONPATH` | 2,464 passed, 3 explicit opt-in skips, 3 dependency warnings; 86.93 seconds |
| Full app suite | 404 passed; 14.734 seconds |
| Full helper suite | 121 passed; 10.003 seconds |
| Full guest-runtime suite | 30 passed; 0.950 seconds |
| All acceptance fixtures via pytest | 491 passed, 12 historical/opt-in skips, 403 subtests passed; 5.64 seconds |
| New upgrade/export fixtures, separately | 69 passed; 0.28 seconds, included in the full fixture result |
| Disposable PF fixture suite, separately | 65 passed; 0.717 seconds, included in the full fixture result |
| Ruff on sensor, guest verifier and all new Python fixtures | Passed |
| Offline dependency-lock verification | 57 packages resolved; unchanged lock |
| Changed package shell syntax and whitespace | Passed |

The opt-in sensor cases are not counted as live tests in this pass. Their
earlier disposable-guest and launchd results remain in the
[precommit report](2026-10-02-precommit-verification.md). Historical fixture
skips do not count as acceptance. Simulated cleanup failures in the fixture
suite produce expected warning messages; no live cleanup ran here.

Native commands used the reviewed CLT macOS 26.5 SDK, scratch path
`app/.build/ui-refresh`, and sequential app/helper/guest suite filters. Logs:

- `build/test-artifacts/publish-app-tests-20261002.log`.
- `build/test-artifacts/publish-helper-tests-20261002.log`.
- `build/test-artifacts/publish-guest-tests-20261002.log`.

The MacBook-accepted local installer still hashes to
`669e4b2b5762f819b4b07c4f5cddc5b6797bae4cd7519282280ee049d3533c17`.
All three changed package scripts compare byte-for-byte with its extracted
payload. That is local artifact/source parity, not release signing or notarization.

## Live acceptance summary for independent review

The [saved-evidence result](2026-10-02-saved-release-evidence-result.md) is the
current index. It supersedes only the stale unknown-line and pending-export
qualifications in earlier records, not their observed failures or scope.

Confirmed:

- Mini normal operation: real SSH/SMB/SFTP, file operations, AI decoys, folded
  alerts, restart and scoped cleanup, within the previously documented filter policy.
- Mini PF tests: wrong/missing owners, simultaneous exact/wildcard ambiguity,
  closing-state reuse, injected cleanup failures, recovery, packet evidence,
  positive PF block counters and no recorded UID-501 LAN accepts.
- MacBook: actual 2.0.3-to-2.1 local-test upgrade, original saved records and
  configuration preserved, restored health, accepted UI and guarded-rule replacement.
- All 144 previously omitted PF lines match the same owner/priority metadata
  digest; all sixteen omitted edge child events have reviewed bounded schemas.

Still not established:

- Wrong-UID replacement while an established socket remains: Darwin refused
  the replacement bind in the tested configuration.
- Wrong-UID replacement while state remains half-open: closing the original
  listener changed the state before replacement.
- Upgrade from old unconditional rules while connection state exists: the
  actual MacBook upgrade had empty before/after PF state listings.
- PF-exclusive attribution for every observed timeout or second-ingress result.
- Acceptance of the exact final Developer ID signed and notarized installer.

These limits need explicit independent review and, where required, additional
approved acceptance. Code approval alone is not an implicit security-test waiver.
No reset or downgrade of the working MacBook is authorized by this record.

## Remote controls and publication sequence

Current read-only GitHub checks found main at the base SHA above, no existing
follow-up PR for this branch, no Home 2.1 tag, and Home 2.0.3 still published.
Main requires one independent latest-push approval, resolved threads and the
strict GitHub Actions `Verify release and package controls` check; it has no
bypass actors. The protected release environment still names the separately
pinned `chrissyrocket` reviewer, prevents self-review and limits deployment
to protected branches. Observed control timestamps match the checked-in policy.

Next steps under the publication request:

1. Commit and push only the reviewed release follow-up; request Chrissy's
   independent review and inspect CI for that exact head.
2. Resolve the outstanding acceptance scope without marking untested conditions
   passed. Merge only through normal protected-main checks and approval, then
   inspect post-merge CI.
3. After applicable acceptance, create the exact signed component/Home tags and
   dispatch the protected Home workflow. Linux publication remains blocked.
4. Hold the independent publish-job approval until the exact signed/notarized
   Actions artifact has passed required acceptance. Local ad-hoc results cannot
   substitute for that package.
5. Verify the immutable release, attestations, all six assets and exact checksums.
   Then prepare the separate reviewed manifest/website promotion, including the
   already prepared synthetic gallery, and verify the public pages and downloads.

The workflow and website release-data source remain unchanged by this follow-up.
