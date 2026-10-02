# Approved mini maintenance reboot preparation

Matt approved the controlled-recovery proposal and asked whether to shut down
the mini now. Do not shut down first. Prepare and verify the future-load hold,
then let Matt perform an attended Apple-menu Restart after saving other work.

## Exact change and blast radius

On `100.108.203.27` only, these two effective launchd overrides change:

| Job | Before | After |
| --- | --- | --- |
| `system/com.squirrelops.sensor` | enabled | disabled |
| `system/com.squirrelops.helper` | enabled | disabled |

The preparation performs no stop, signal, bootout, debug replacement, reboot,
installation, database update, configuration edit, PF mutation or Little Snitch
rule change. Already-running KeepAlive jobs can continue running while disabled.
The two overrides are intended to prevent their loading on the next boot; this
must be verified after the actual reboot. A pending receipt is not stopped-state
acceptance. Nothing on the Studio or laptop is changed.

The attended restart interrupts all mini workloads and SSH. The old five-second
shutdown budget could still truncate cleanup. Do not claim the reboot proves a
safe installer upgrade or repairs leftover ownership records.

## Backup and checks

Use the pinned installed Python in isolated mode. Before either override write,
verify the same mini boot, OS, service account, package receipts, executable
digests, `.240`-only current runtime and alias ownership, and existing PF
containment. Preserve config, both launch plists, a consistent service-UID SQLite
snapshot, alias ledger, and private runtime/PF evidence in a fresh root-private
directory under `/Library/SquirrelOps/acceptance-backups`. Never print tokens or
configuration secrets. Backups and evidence are exclusive, not overwrites of an
earlier attempt.

Recheck boot, config, launch plists, runtime cohort, job PIDs, aliases, PF rules
and references before and after disabling. Verify both disabled overrides and
write `pending-reboot.json` only after all checks pass. No root/native launchd
experiment is part of this method. The failed one-shot replacement is not used.

## Failure and inverse

On a failure, retain evidence and any partial disabled hold; do not automatically
enable, stop or restart anything. Do not reboot on a failure or blindly rerun.
The inverse is `launchctl enable` for exactly the same two jobs, but only at the
reviewed upgrade boundary after stopped-state and `.240`-only configuration
checks. Do not reload the old pool while the Studio owns `.241`. Backups are
evidence, not permission for a database downgrade or global network reset.

After `READY FOR ATTENDED RESTART`, Matt saves other work and restarts the mini.
Keep the SquirrelOps app closed and existing Little Snitch prompts unanswered.
After logging back in, inspect the new boot, both disabled overrides, absence of
product jobs/processes/aliases, retained data/ownership state and actual PF state.
Stop for review if any condition is unexpected. No installation or LAN probes
follow automatically, and no previous PF reference tokens may be reused.
