# Home 2.1 GitHub release preparation

Date: 2026-09-26. Status: reviewer transition approved and applied; candidate
being submitted for independent review. No merge, tag, release dispatch, or
publication is authorized by this preparation.

Publication remains blocked on live acceptance, exact-candidate CI, independent
review, and separately authorized release actions. This checklist is not
approval to bypass any gate.

## Baseline before the approved changes

Verified with read-only GitHub API calls and `git ls-remote`:

| Item | Current state |
| --- | --- |
| Repository | `rocketweb/squirrelops-home`, public |
| Protected main | `eb2d87af5e24d924204afb4f2c0bcbd7403ac559` |
| Candidate branch | `feature/deception-depth-2.1.0-current`, local only |
| Candidate HEAD | `66bda11a97ea8bf6192e812e9fae4584bfb16d85`, two commits ahead of main, plus uncommitted relay/control fixes |
| Home / app / sensor versions | `2.1.0` / `2.1.0` / `2.1.0` |
| Candidate PR | None open |
| 2.1 tags | No remote `app-v2.1.0`, `sensor-v2.1.0`, or `home-v2.1.0` |
| Latest published release | `home-v2.0.3`, immutable |
| Release immutability | Enabled |
| Main ruleset | `19759625`, active, no bypass actors, independent latest-push approval and strict Actions-pinned supply-chain check required |
| Tag ruleset | `19759637`, active; only `mattmacrocket` (ID `247222255`) may bypass to create protected signed tags |
| Release environment | ID `18780758237`, sole reviewer `gregor-RW` (ID `29927193`), self-review prohibited, admin bypass disabled, protected branches only |
| Intended reviewer | `chrissyrocket`, User ID `333806721`, effective repository permission `read`, not currently an environment reviewer |

Both live ruleset timestamps and the environment timestamp match the checked-in
policy when requested in UTC. This is a partial read-only preflight, not the
full release checker: that checker also requires a real signed tag, a fresh
workflow run, and its actual approval history. None exists for 2.1 yet.

The repository requires exactly one independently pinned release reviewer.
Adding Chrissy alongside Gregor would not satisfy that policy. Replacing him
requires both a deliberate settings change and a reviewed policy-pin update.

## Approved scope

Matt approved the following scope after reviewing the baseline:

1. Give `chrissyrocket` repository **Write**, not Maintain/Admin, if she will
   provide the required PR approval as well as release-environment approval.
2. Replace `gregor-RW` with `chrissyrocket` as the sole required reviewer for
   this repository's `release` environment. Preserve its ID, secrets, protected
   branch restriction, self-review prohibition, and disabled admin bypass.
3. Read back the server-generated `updated_at`, then propose a reviewed
   update to `.github/release-policy.json` with reviewer ID `333806721` and that
   exact timestamp. Keep the policy change in its own commit in the candidate
   PR. Do not invent a timestamp or weaken validation.
4. Commit the candidate's explicit source/test/documentation allowlist, push
   its feature branch, and open the 2.1 review PR. Keep raw captures in
   `docs/testing/evidence/`, build outputs, installers, and local control
   snapshots out of commits. Request Chrissy's review after access is verified.

GitHub distinguishes these permissions: environment reviewers need only read
access, but required PR approvals come from reviewers with write access.
Sources: [ruleset review requirements](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-a-pull-request-before-merging)
and [environment reviewers](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments#required-reviewers).

Affected control scope: one repository-access grant, one environment reviewer,
and one policy file. No main/tag ruleset changes, bypass additions, secret
changes, merge, signed tag creation, release dispatch, publication, website
update, or Linux publication is included in that preparation scope.

### Verified reviewer transition

- `chrissyrocket` (ID `333806721`) now has effective repository **Write**.
  The grant is active; no invitation is pending.
- The existing `release` environment (ID `18780758237`) now has Chrissy as
  its sole required reviewer. Self-review is prohibited, admin bypass is
  disabled, and the protected-branches-only deployment policy is unchanged.
- GitHub returned the unchanged environment `updated_at` value
  `2026-07-26T19:39:02Z` after the reviewer update. The proposed policy keeps
  that observed value and changes only the reviewer ID. The release checker
  compares the actual reviewer list and protections, not only the timestamp.
- Before/after main and tag ruleset responses match byte-for-byte. No signing
  secret was read or changed. Release immutability remains enabled.
- The main branch still contains the old reviewer pin. Release checks fail
  closed until the proposed policy passes independent review and is merged.

### Backup and inverse operation

Read-only snapshots are retained in `build/test-artifacts/`:

- `github-release-preparation-environment-before.json`
- `github-release-preparation-main-ruleset.json`
- `github-release-preparation-tag-ruleset.json`
- `github-release-preparation-chrissy-direct-access.json`

Before any approved change, refresh these snapshots and verify whether access
is explicit or inherited. Reverting an access grant restores the prior direct
membership state, not an assumed role. Reverting the reviewer restores Gregor
and all protection settings; read the resulting server timestamp rather than
assuming it changes. Any reverted policy needs independent review. Keep
publication blocked until the live environment and reviewed policy agree.
Do not invent a timestamp or bypass the check.

Fresh pre-change snapshots use the `github-release-approved-` prefix under
`build/test-artifacts/`. The environment rollback payload is
`github-release-approved-environment-rollback.json`. The access inverse is to
remove the new direct grant to `chrissyrocket`, restoring its prior absence;
do not create an artificial Read grant. Rollback is prepared, not executed.

## Local preparation evidence

- All 437 source/build/test input hashes still match the tested candidate.
- The local-test installer SHA-256 matches
  `611e3f3672f87191c59d42e0575f3b0c34d4002216fec6328deb12adc4dcedd3`.
- `uv lock --check --offline --project sensor` passed.
- The six release/package/backup/LAN contract files used by the required
  supply-chain job passed locally: **132 tests**, 6.99 seconds.
- `git diff --check` passed. No exact-candidate GitHub CI result exists yet.

Logs use the `github-release-preparation-` prefix under `build/test-artifacts/`.
The previous complete runs remain recorded in the
[relay/control report](2026-09-26-relay-control-fixes.md): 2,311 source and
packaged sensor tests, 531 Swift tests, and disposable real-protocol acceptance.
Those full suites were not rerun during this preparation pass; their input
hashes were reverified instead.

Before the approved policy edit, all 437 input hashes and the installer hash
were reverified again. The reviewer ID is the only subsequent change to those
manifested inputs; the historical installer and its manifest are not rewritten
to claim they were built from the new release policy.

After the reviewer-policy edit, the six release/package contract files passed
again: **132 tests**, 6.81 seconds. Ruff, the offline lock check, and whitespace
checks passed. Exact live environment/policy comparisons passed, and the
environment response excluding only reviewer metadata is unchanged from the
saved baseline. The full sensor rerun initially hit sandbox-denied socket
binds; that infrastructure-limited run is retained separately from the rerun
with permission for local test sockets.

That full sensor rerun passed **2,311 tests**, with one opt-in live-VM skip and
three warnings, in 85.05 seconds. Command, run from `sensor/`:

```bash
env -u SQUIRRELOPS_DECEPTION_RUNTIME -u SQUIRRELOPS_GUEST_BUNDLE \
  .venv/bin/python -m pytest -q --tb=short -ra
```

Result log: `build/test-artifacts/github-release-approved-sensor-unsandboxed.log`.
The packaged sensor, Swift bundles, and live guest were not rerun in this
reviewer-transition pass; their prior evidence and unchanged application
source hashes remain recorded above. Remote CI is not inferred from these
local results.

## Gates before tags or release dispatch

Current status is consolidated in the
[October 1 publication-readiness record](2026-10-01-publication-readiness.md).
The numbered list below is the historical gate definition, not a claim that
the subsequently completed Mini upgrade/protocol run is still pending.

Platform scope corrected September 30, 2026: Home 2.1 supports Apple Silicon
only. Intel execution is not a release gate. See
[macOS release support](../RELEASE_SECURITY.md#macos-release-support).

1. Complete the [A5 live PF acceptance](2026-09-26-pf-safety-development.md#live-acceptance-gate-not-executed), including different-UID listener replacement,
   established state, failed quarantine/state cleanup, and scoped restoration.
   This remains explicitly release-blocking. Choose an isolated Mac or obtain
   approval for the exact local maintenance scope before changing live PF.
2. Verify the current package's installed upgrade and SSH/SMB ingress from a
   second machine through the actual virtual IPs, including source attribution
   and alerts. Loopback guest tests do not establish these results.
3. Review remaining security/deception findings, including OpenSSH's existing
   pre-authentication penalties when relayed sessions share a guest address.
   No blanket waiver or automatic decoy hardening is implied.
4. Obtain current PR CI and independent approval for the exact final source and
   policy; merge only after separately authorized. Dependency review must run
   against the real PR diff, not be inferred from local tests.
5. Confirm ARM64 release-signed containment acceptance; build guests for
   both architectures from the pinned image and package inventory through the
   release workflow for build coverage. The supported macOS package must
   contain the ARM64 guest. Do not upload the ad-hoc local-test installer as a
   public release artifact.

## Eventual release sequence

After those gates and explicit publication authorization:

1. Verify the exact merged `main` SHA and all version/source mappings.
2. As the pinned signer, create and verify signed annotated `app-v2.1.0`,
   `sensor-v2.1.0`, and `home-v2.1.0` tags at that SHA, then push atomically.
3. Dispatch `Release Home Distribution` from protected `main` with the Home
   tag and full SHA. Chrissy approves each requested protected-environment job
   only after checking the final tags and source. Do not approve on her behalf.
4. Let the workflow build, sign, notarize, attest, create its own draft, verify
   asset digests, and publish the immutable release. Do not pre-create a GitHub
   draft or reuse the local-test artifact. Do not rerun a failed release run.
5. Verify published immutable metadata, package signatures/notarization, and
   attestations. Website and Homebrew promotion remain separately authorized
   reviewed changes. Linux remains blocked; its component tag is identity only.

The current workflow publishes automatically after its protected build and
verification stages. Dispatch is therefore publication authority, not merely
a request to compile an installer.
