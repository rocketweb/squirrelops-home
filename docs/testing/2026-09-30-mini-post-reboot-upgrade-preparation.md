# Post-reboot mini acceptance: original staging superseded

The original attended run below stopped in preflight on an incorrectly applied
1 MiB evidence-file limit. It did not reach configuration, PF enablement or
installation. Do not rerun the original command. The corrected v2 staging,
regressions and replacement command are recorded in
[the payload-check fix report](2026-09-30-mini-post-reboot-payload-check-fix.md).
The remainder of this document preserves the original preparation evidence.

The replacement runner, pinned bootstrap and laptop wrapper are locally tested
and now staged after Matt's explicit approval of this mini-only test. Remote
plan-only verification passed. The mini remains held stopped. This is not an
installation, restart, LAN acceptance or release result. Only the new private
staging directories and their inputs were created remotely; no product service
overrides, configuration, database rows, aliases, PF policy or Little Snitch
rules changed. The attended root command below remains pending.

## Fresh read-only host evidence

SSH inspection of `matt@100.108.203.27` confirmed:

- Host `Matts-Mini-2.localdomain`, macOS build `26A434`, boot `1790777754`.
- Both `com.squirrelops.sensor` and `com.squirrelops.helper` explicitly disabled;
  neither system job loaded.
- No SquirrelOps or Virtualization processes, or UID 309 processes, in the
  inspected process inventory.
- Native LAN addresses `.115` on `en0` and `.254` on `en1`; no `.240` or `.241`
  local aliases. Tailscale address remains `100.108.203.27`.
- Exact receipt IDs `com.squirrelops.home.app` and `com.squirrelops.home.sensor`
  both remain 2.1.0, install time `1790731448`.
- Installed Python SHA-256 remains
  `d2555cd22a33506826f9eb069bb13fb0cc41303c7da41da5b761967d616f4147`.
- Installed launch plist still lacks the new shutdown allowance. The candidate
  has not yet been installed.

The earlier attended PF, ledger and SQLite output is historical evidence.
Those root-only checks must be repeated by the new runner before any mutation;
read-only SSH cannot replace them.

## Replacement behavior

The exact scope remains in
[the post-reboot upgrade scope](2026-09-30-mini-post-reboot-upgrade-scope.md).
Its checksum-pinned text is preserved, including its original proposed status.
Matt subsequently approved the itemized mini-only install, two-field config
change, temporary sensor/helper and test-owned PF enablement, restart and
laptop probes, and restoration of the stopped/disabled hold. That approval does
not cover Studio, `.241`, Little Snitch, a commit or publication.

`mini_post_reboot_acceptance.py` implements a new preflight directly on the
shared upgrade utilities. It never invokes the historical recovery or cleanup
receipt preflight. Historical checksum-pinned runners remain unchanged.

- Revalidate this boot, package receipts, old payload hashes, both disabled
  jobs, absent runtime/aliases, exact stale `.240` ledger, native listeners and
  concrete PF baseline.
- Make fresh durable installation, configuration, receipt and consistent SQLite
  backups. Live database reads run as UID/GID 309 with no supplementary groups,
  not as root. There are no SQL status repairs or credential resets.
- After attended confirmation, apply only the two reviewed pool fields; use
  an exclusive attempt record and preserve the exact configuration inverse.
- Acquire this run's PF reference before enabling only the two product jobs
  at the installer boundary. Never bootstrap the old sensor in between.
  The installer, not the runner, retires the stale ledger.
- Verify the new payload, both persisted and loaded 60-second shutdown
  allowance, all six saved decoy identities/intent, classic listener, and five
  guarded guest publications. Persisted `active` rows alone are not readiness.
- Exercise normal sensor stop/restart before bounded `.240` laptop probes.
- On successful teardown, restore both disabled overrides before releasing
  this run's PF reference. A surviving guest or failed cleanup retains
  protection and requires review. Keep installation, narrowed config and data.
- Mirror sanitized status/snapshots into the private durable backup. Temporary
  public results are only a convenient read surface, not future authority.

The laptop wrapper additionally requires the new scope, current boot, exact
package, verified single-IP configuration and fresh readiness. It rejects old
single-IP runner status and `.241` as a target.

## Local verification

The engineering-constraints skill led to adding tests before implementation,
testing failure paths, and separating local evidence from live acceptance.

- New fixture suite initially failed because the new module did not exist.
  Readiness regressions also failed before the new publication guard existed.
- `sensor/.venv/bin/python -B -m unittest discover -s docs/testing/fixtures -p test_mini_post_reboot.py -q`:
  25 passed. Includes exact job targets, consent/backup/PF prerequisites,
  survivor and installer failures, replay refusal, durable results, real
  disposable WAL-database backup, UID-drop arguments and all bootstrap pins.
- Same 25 tests passed with the candidate's extracted Python using `-I -B`.
- Full local fixture suite, `unittest discover -s docs/testing/fixtures -p 'test_mini*.py' -q`:
  238 run, 237 passed, 1 skipped, 3.991 seconds. Remote/product mutations are
  mocked. The skipped test is the historical opt-in root launchd probe; it is
  not part of the replacement workflow or new acceptance evidence.
- Four existing loopback listener tests were initially denied by the sandbox.
  The final loopback-enabled run passed. Dependency deprecation warnings remain.
- Ruff on the three new Python files, bootstrap `bash -n`, checksum checks,
  plan-only mode and `git diff --check` passed.

These checks do not establish native privileged installation, real guest
shutdown, LAN/PF behavior, or a safe unattended upgrade from a running old
five-second daemon. Those remain separate release gates.

## Pins and next boundary

The unchanged candidate is
`build/test-artifacts/SquirrelOpsHome-2.1.0-launchd-budget-20260930-local-test.pkg`,
SHA-256 `3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c`.
It is an unsigned local-test installer with ad-hoc payload signatures, not a
signed/notarized public artifact.

| Input | SHA-256 |
| --- | --- |
| `mini_post_reboot_acceptance.py` | `b02554ecf5025ac3201589daa212816f9ec3b1de098d28a5591d7867b9c2c91c` |
| `start-mini-post-reboot-acceptance.sh` | `a36c8f117d4bf0cb5e1c00af75e30886680f3970f5005a00e76de8f4ebbaa853` |
| Proposed scope | `288eb8eb45a50caaac9538f02ac1cc23ca697573e967771a06314cfb2725f24e` |
| `mini_post_reboot_client.py` | `17fe8d27b16e2edb0bfb520f050cef3846d5236ac606630f1aa31cddd33c94a1` |
| Shared `mini_upgrade_client.py` | `15b3bb270b77d3801870d2a81b64dee266a8f823ce234f6b2be2ff360b02b7f6` |

## Approved staging completed

- Mini: `/Users/matt/squirrelops-mini-post-reboot.tzFZw7KI` on
  `matt@100.108.203.27`.
- Laptop: `/root/squirrelops-mini-upgrade-client.VNbggFA7` on
  `root@192.168.1.7`.
- Both new directories are mode 0700. All ten mini inputs and both laptop
  scripts are regular single-link mode-0600 files, owned by their staging user.
  All remote SHA-256 values match the reviewed local files and package.
- Mini shell syntax and plan-only execution with its installed Python passed.
  The reported scope is `mini-post-reboot-240`, boot `1790777754`, the pinned
  candidate, no database repair, and restoration of both disabled jobs.
- Laptop plan-only execution passed without probe traffic. The laptop is still
  Linux host `laptop`; its route to `.240` uses `wlp0s20f3`, source `.7`. Existing
  Python, pexpect, SSH, SFTP and smbclient dependencies are available.
- Fresh mini checks still show the same boot/OS/receipts/Python digest, both
  jobs disabled and unloaded, no relevant processes, and no `.240`/`.241`
  aliases. Root-only PF, ledger and database checks remain the attended gate.
- The 25 new local tests, Ruff, shell syntax and `git diff --check` were rerun
  and passed before the handoff. No test credentials were transferred yet.

Run in the mini's Terminal, keeping its SquirrelOps app closed:

```bash
sudo /bin/bash /Users/matt/squirrelops-mini-post-reboot.tzFZw7KI/start-mini-post-reboot-acceptance.sh
```

After fresh backups and the scope preview, confirm with
`UPGRADE HELD MINI AND TEST 240`. At `READY FOR TESTS`, leave Terminal open
without pressing Return and tell Codex. New Little Snitch prompts remain
unanswered. A `STOPPED` result requires review, not a retry or an old command.

For the agent's laptop continuation, require fresh root-owned server readiness,
the exact new scope/boot/package and `.240`-only endpoints. Transfer only the
synthetic guest login and the matching endpoint/readiness JSON privately, with
mode 0600; never display the password. Run only the new
`mini_post_reboot_client.py --run /root/squirrelops-mini-upgrade-client.VNbggFA7`
once. The wrapper must reject stale or historical readiness. Collect results
and verify durable cleanup before any further app launch or release action.

No commit, push, installer rebuild, installation, release or website deployment
was performed. The Intel-support documentation edits remain local and separate.
