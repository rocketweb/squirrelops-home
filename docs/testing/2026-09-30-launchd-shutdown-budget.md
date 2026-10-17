# launchd shutdown budget: confirmed cause and local fix

Status: locally fixed, tested, and rebuilt. Mini cleanup completed; the new
upgrade and real-VM restart acceptance remain pending. Nothing in this record
authorizes public release.

## Evidence and mechanism

The mini's ownership-fix package installed and passed first-start checks.
During the normal restart check, Python disappeared while the detached guest
and VM remained. The protected sensor log reached `Stopping scan loop...`
three seconds after shutdown began. A read-only unified-log query established
the terminating actor and reason:

```text
2026-09-29 21:24:45.239 Service did not exit 5 seconds after SIGTERM. Sending SIGKILL.
2026-09-29 21:24:46.252 exited due to SIGKILL | sent by launchd[1]
```

The installed sensor plist had no `ExitTimeOut`. launchd's system-defined
default on this machine was five seconds. mDNS goodbye took about three
seconds, followed by a scan drain that can take ten seconds. launchd killed
the sensor before its ordered cleanup reached the guest. This is independent
of whether Little Snitch permits mDNS traffic. No filter settings were changed.

## Changes

- Set `ExitTimeOut` to a finite 60 seconds in the sensor launchd template.
- Allow up to 70 one-second sensor removal checks in both package preinstall
  scripts and the uninstaller. Helper removal keeps its ten-second bound.
- Preserve stop ordering and all fail-closed checks. A surviving guest still
  blocks alias withdrawal and protection release in the acceptance runner.
- Add shell-function tests and an opt-in disposable launchd regression using
  the real managed server signal boundary and real scan timeout.
- Update development documentation and draft 2.1 release notes.

This change gives normal cleanup time to finish. It does not promise that
every stuck shutdown completes in 60 seconds, nor repair an already-orphaned
guest. The mini needs the exact-session attended cleanup before a new install.

## Verification

| Check | Result |
| --- | --- |
| New regression before product edits | 11 failed, 6 passed; disposable launchd job stopped before guest/database markers |
| Focused package, shutdown, and entry-point tests with launchd opt-in | 110 passed |
| Complete sensor suite: `.venv/bin/python -m pytest tests/ -q` | 2,417 passed, 2 skipped, 3 dependency deprecation warnings |
| Extracted installer Python: `test_launchd_shutdown.py` and `test_runtime_shutdown.py`, launchd opt-in | 28 passed |
| `ruff check sensor/src sensor/tests` | Passed |
| Package shell syntax and `git diff --check` | Passed |
| Extracted sensor plist, both preinstall scripts, installed uninstaller vs source | Exact byte matches; plist timeout is 60 |
| `codesign --verify --strict` on packaged Python; `--deep --strict` on app | Passed ad-hoc signature checks, not Developer ID release verification |
| Local mini acceptance/cleanup harness tests | 146 passed, including 17 new restart-cleanup guards |

Four existing local harness socket tests initially failed under the restricted
sandbox with `PermissionError`. The complete suite passed with loopback socket
permission; no remote operations are invoked by those tests.

The opt-in launchd test runs one uniquely named console-user job, no installed
daemon. Its guest, mDNS, and database are fakes. Real mini guest shutdown,
sensor restart, installer upgrade, LAN protocols, and the separate PF A5 fault
matrix are not established by these local results.

## Candidate artifact

Build command:

```bash
SQUIRRELOPS_LOCAL_TEST_BUILD=1 SKIP_PKG_SIGNING=1 bash scripts/build-pkg.sh
```

- ARM64, Home/App/Sensor 2.1.0.
- File: `build/test-artifacts/SquirrelOpsHome-2.1.0-launchd-budget-20260930-local-test.pkg`.
- SHA-256: `3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c`.
- Built from `a50179417e8f726ceb03bb6914a42cb996d2ead6` plus the local shutdown-budget edits.
- Unsigned installer, ad-hoc payload signing, no notarization. Local test only.
- Build log: `build/test-artifacts/launchd-budget-20260930-build.log`.
- Sensor results: `build/test-artifacts/launchd-budget-20260930-sensor.log` and matching XML.

## Mini continuation boundary

The failed run's private backup is
`/Library/SquirrelOps/acceptance-backups/mini-upgrade-20260929.z8rfqzvz`.
Its original sanitized evidence remains unchanged in
`/private/var/tmp/squirrelops-mini-upgrade-results.w3qacnps`.

Prepared scripts are in `/Users/matt/squirrelops-mini-restart-cleanup.OaJV86GE`
on `100.108.203.27`. `finish-mini-restart-cleanup.sh` verifies all script and
package hashes, extracts a private runtime from the already-tested ownership
package, and does not invoke Installer. The old package is used only to run
cleanup, not as the next candidate.

Before mutation, cleanup verifies root-owned original evidence, the successful
installation, receipt, current executable hashes, exact guest/VM PIDs with
UID/path/start time, unchanged startup PF rules, owned alias, and the original
unreleased PF reference. It reconstructs the pre-enable PF inventory from
recorded read results without executing logged commands. Repeated equal native
listener snapshots are allowed; inconsistent ones stop the operation.

It makes a new private SQLite backup, prints the exact scope, and requires
`STOP TEST GUEST`. SIGTERM is permitted only for the two recorded guest
processes. If either survives, there is no force-kill or protection release.
After their verified exit, the existing tested teardown withdraws only the
owned `.240` alias, clears only product PF rules, stops the product helper,
verifies native endpoints and empty PF policy against the original baseline,
then releases only the saved PF reference once.

Installation, configuration, account, data, and previous backups are retained.
No database status edits or automatic restart are included. Restart is not a
safe inverse while the old installed service still has the five-second default;
a new guarded upgrade requires separate continuation after verified cleanup.

At initial preparation, no cleanup, install, commit, push, tag, release, or
website publication had been performed. Independent review and live release
gates remain open.

## Attended cleanup completed

Matt ran the prepared command and confirmed `STOP TEST GUEST`. The root-produced
receipt at `/private/var/tmp/squirrelops-mini-restart-cleanup-results.v93amy48/status.json`
records completion at `2026-09-30T09:15:28Z`: guest stopped, aliases absent,
native endpoints present, the test's reference released, and PF disabled.
Installation and test data were retained. Receipt SHA-256:
`707399a27e4e66f62dedc90b9c8b7f6a9cb369dc8c45ba22ea9ffa7caa886042`.

A subsequent read-only SSH check confirmed both launchd jobs absent, the
recorded guest/VM/helper PIDs absent, and only the expected `distnoted` remaining
under UID 309. The sensor receipt remains `1790731448`; no new package has been
installed. See `2026-09-30-mini-launchd-upgrade-preparation.md` for the staged
next run, which does not repeat database recovery.
