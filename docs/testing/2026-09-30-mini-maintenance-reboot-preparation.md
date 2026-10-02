# Mini maintenance reboot preparation

Status: prepared and staged, not executed as root. No service override,
shutdown, reboot, installation or network-filter change was made by the agent.

## Live baseline

Read-only SSH checks still show mini `100.108.203.27`, build `26A434`, boot
`1790766531`, sensor PID 887 (runs 1, exit timeout 5), helper PID 888 (runs 1),
and no disabled override for either product service. This is pre-reboot evidence,
not a durable promise of the host's later state. The attended preparation
revalidates the baseline and makes fresh durable backups before writes.

## Scope and design

See [approved scope](2026-09-30-mini-maintenance-reboot-scope.md).
The engineering-constraints review prompted separation of the reusable
read-only backup preflight from the failed shutdown/probe path. The new entry
point calls only that backup audit and its two future-load disable operations.
It never calls the failed native proof, sends a signal, boots a job out or
reboots the host. The old runner is retired and must not be rerun.

The receipt is deliberately `pending-reboot.json`, with
`stopped_state_verified: false`. Post-boot acceptance and a safe upgrade from
the running old package remain unverified.

## Verification performed

- New preparation tests were added before the implementation; the initial run
  failed because that new entry point did not yet exist.
- `sensor/.venv/bin/python -B -m unittest discover -s docs/testing/fixtures -p test_mini_maintenance_hold.py`:
  13 passed, including two-job-only writes, failed backups/disable verification,
  changed runtime/config/PF state, pending-not-stopped receipts, and input pins.
- The same 13 tests passed with the extracted shutdown-budget installer's
  isolated Python 3.12 (`-I -B`).
- Full `test_mini*.py` fixture suite: 213 run, 212 passed, 1 skipped. The initial
  sandbox run blocked four loopback-listener tests; the approved loopback-enabled
  rerun passed. The skipped root/system-domain legacy probe is the previously
  failed, retired mechanism, not evidence for this method.
- Ruff, bootstrap `bash -n`, and `git diff --check` passed. Bootstrap shell syntax
  and every staged file digest were also verified on the mini without execution.

## Staged command for Matt

Run in the mini's Terminal, not the Studio:

```bash
sudo /bin/bash /Users/matt/squirrelops-mini-maintenance.ipoZVz05/prepare-mini-maintenance-reboot.sh
```

Only if it prints `READY FOR ATTENDED RESTART`, save other mini work and choose
Apple menu > Restart. Uncheck reopening windows to avoid restoring the app.
After logging back in, keep SquirrelOps closed and report that the mini is back
for the post-boot audit. If it stops, do not reboot or rerun; report the output.

Staged wrapper SHA-256:
`3700143d63f334e8354e48a865595ec77d8e9b77dfb8d2dba8a2d71ff1697028`

New entry-point SHA-256:
`a90f94885c5eec19ebbdafa8e75444ddaab54b485b71b3fb937815f8c9904314`

Scope SHA-256:
`6bb043a98dd66573e3955d889499c13b9245ff7b03b28c25be01be326560c5aa`

All prior staging directories, backups and source changes remain intact.
No commit, push, rebuild, installation or release was performed.
