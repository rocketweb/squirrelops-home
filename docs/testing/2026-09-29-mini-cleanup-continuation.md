# Exact mini acceptance cleanup continuation

Date: 2026-09-29. Status: attended cleanup completed at 14:38:18 UTC;
subsequent read-only SSH checks verified service, process, address and native
listener state. Installation and private data retained.

This completes the stop/withdraw/reference-release portion of the already
approved [mini test scope](2026-09-28-mini-install-test-scope.md). It does not
install, start the sensor, retry protocol acceptance or resolve the failed
decoy responses. The [live acceptance report](2026-09-29-mini-live-acceptance.md)
remains failed for protocol acceptance, but its cleanup is now complete.

## Bound session and observed state

Matt supplied the latest attended session's exact private baseline:
`/Library/SquirrelOps/acceptance-backups/mini-20260928.bukymecp`.
The root-produced status, now reporting successful cleanup, is at
`/private/var/tmp/squirrelops-mini-results.fxk5kskd/status.json`.

Before the continuation, read-only SSH confirmed that the sensor launchd job
was absent, but UID 309 still owned guest PID 27646 and its VM PID 27647, both
parented to PID 1. `distnoted` PID 27648 was also owned by that UID. The `.240/32`
loopback alias remained. No live cleanup occurred during preparation.

The original harness immediately checked launchd after `bootout`. A local test
reproduced that premature failure, then passed with a bounded 30-second poll.
The original script and its pinned backup are unchanged. The separate cleanup
continuation uses the corrected wait when stopping the remaining helper.

## Mutation preview and preservation

| Exact target | Authorized continuation |
| --- | --- |
| Root-private staging directory | Extract the identical checksum-pinned package solely to use its isolated Python; no Installer invocation |
| New private child of this baseline | Preserve initial status, script, scope, command logs and an integrity-checked pre-cleanup SQLite backup |
| Guest PID 27646 and VM PID 27647 | Revalidate UID, executable path and process start identity; SIGTERM only these identities, at most 45 seconds each; no SIGKILL |
| `distnoted` PID 27648 | Inspect identity only; never signal it |
| Owned VIP `192.168.1.240` | After runtime/listener absence, apply block-only quarantine, remove its alias and proxy ARP, then verify both approved VIPs absent |
| Product forwarding anchor and helper | Clear product forwards only after alias withdrawal, then boot out only `com.squirrelops.helper` with a bounded wait |
| This run's PF reference | Match the private saved token to original successful acquisition and current references; release only that token after network absence, empty-policy inventory and original native listener/interface parity |
| App, installed runtime, account, config, database, logs, earlier backups | Retain; no uninstall, recursive deletion, permission reset or restart |

The existing protection is retained on uncertain runtime shutdown or failed
withdrawal. There is no automatic restart inverse: returning a disposable test
guest to service would begin a new test session and needs review. Preserved
configuration, database backup, package and original baseline support a later
controlled restart. Native SSH/SMB/Screen Sharing, AI, VPNs, Tailscale and
unrelated VMs are not stopped or reconfigured. No global PF disable, flush,
ruleset reload or new PF enable reference is permitted.

Preflight rejects changed evidence hashes, replaced executables, changed
configuration/receipts, a restarted sensor or app, new service-UID processes,
changed alias ownership/PF rules, missing private reference, or failed native
listener/interface parity. It also checks the original private command log for
exactly one successful acquisition, a successful pinned-package installation,
and no earlier PF-release attempt. A root-private exclusive marker prevents
concurrent or repeated mutation attempts. Never delete that marker to retry.

## Verification

- Watched the delayed-launchd regression fail with the old immediate check;
  then passed it after adding the bounded poll.
- `sensor/.venv/bin/python -B docs/testing/fixtures/test_mini_cleanup.py`:
  **18 tests passed**, including safe operation order, failure injection before
  release, process replacement, refused `distnoted` termination, no force-kill,
  original reference binding and redaction on command timeout.
- Original acceptance guard suite: **28 tests passed**.
- Ruff passed on the new Python files. Shell syntax and packaged-Python checks
  passed locally. All 18 cleanup tests also passed with the exact candidate's
  extracted isolated Python interpreter.
- These are local fixture checks, not evidence of completed live cleanup.

## Staging verification

The new files were copied into `/Users/matt/squirrelops-mini-test.yktIwbVu`
only after verifying they did not already exist. Original setup files and the
candidate package were not overwritten. Remote checks matched these digests:

| File | SHA-256 |
| --- | --- |
| `finish-mini-cleanup.sh` | `a207ecf6c1a7a1d6a4a418f88e17d52e444a62bcff1198f4b0fa0ebd531adadf` |
| `mini_cleanup.py` | `ee842b733f72c0cba2343d1abc29a614b1f9790d9fa5ac33a375729397c328ad` |
| Unchanged `mini_acceptance.py` | `47b6c6df59083230ac63f97f1b32c55fa804f71839d433bfbc9fb952bf7bd40a` |
| Unchanged `candidate.pkg` | `3e8c0fc78befad3365fdbff5583d9f85c6b6fe01816b5863edbebeceaa4b8f5f` |

Remote `/bin/bash -n` passed. Running `mini_cleanup.py` without `--run` using
the mini's installed isolated Python returned `plan_only`, the exact baseline
and result directory, `install: false`, `delete_data: false` and
`global_pf_reset: false`. This plan path makes no host-operation calls, as
checked by its local regression test. The root-only preflight and teardown
subsequently completed using the attended command below.

## Attended command

Executed once on the mini after staged checksum verification. **Do not rerun:**

```sh
sudo /bin/bash /Users/matt/squirrelops-mini-test.yktIwbVu/finish-mini-cleanup.sh
```

## Live completion and independent verification

Matt supplied `CLEANUP COMPLETE` from the attended command. Its new private
backup is
`/Library/SquirrelOps/acceptance-backups/mini-20260928.bukymecp/cleanup-20260929.zzlg2yx9`.
The validated script makes an integrity-checked pre-cleanup SQLite backup in
that root-private directory before teardown; private contents and the PF
reference were not retrieved or exposed.

The root-produced status timestamp is `2026-09-29T14:38:18Z`. A sanitized copy
is preserved as
[cleanup-status.json](evidence/2026-09-29-mini/cleanup-status.json); the original
failure remains preserved separately in `status.json`. The completion reports:

- `phase: stopped`, `test_guest_stopped: true`, `aliases_absent: true`.
- `own_pf_reference_released: true`, `pf_enabled: false`.
- `original_listener_endpoints_present: true`.
- `installation_retained: true`, `test_data_retained: true`.

Independent read-only SSH checks after completion confirmed:

- `launchctl print` cannot find either the sensor or helper system job.
- Recorded guest PID 27646 and VM PID 27647 no longer exist. The only remaining
  service-UID process is the intentionally untouched `distnoted` PID 27648.
- Neither `.240` nor `.241` is assigned on any interface, and neither has a
  published proxy-ARP entry. A normal incomplete `.241` neighbor-cache entry
  was observed; it is not a published entry and was not flushed.
- No test-VIP TCP listeners remain. Native wildcard SSH 22, SMB 445 and Screen
  Sharing 5900 still listen, as do `.115:11434` and loopback `127.0.0.1:49199`.
- Ethernet `.115` and Wi-Fi `.254` remain unchanged.
- Both app and sensor package receipts remain version `2.1.0`, original
  install-time `1790689617`.

PF reference release, empty-policy inventory, full original UID/endpoint set
comparison and SQLite integrity are evidenced by the guarded root run and its
sanitized completion status. They were not independently re-executed with
root from the agent's unprivileged SSH session. No further administrator prompt
was requested merely to duplicate those completed checks.

Do not reopen the app or rerun either setup/recovery command yet. Successful
cleanup does not fix the unanswered decoy protocols. The next step is a
reviewed diagnosis of the shared listener/flow failure, not release promotion.

No product code, installer bytes, Git commit, push or release is changed.
