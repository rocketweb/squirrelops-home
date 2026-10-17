# Mini reboot invalidated the stopped acceptance baseline

Status: diagnosis only. Do not rerun the staged single-IP acceptance command or
restore its missing receipt as a substitute for fresh stopped-state evidence.

## Failure and verified current state

The attended `start-mini-single-ip-acceptance.sh` invocation stopped in
`LaunchdUpgrade.preflight()` while checking the historical cleanup directory:

`/private/var/tmp/squirrelops-mini-restart-cleanup-results.v93amy48`

This check precedes the installation/data backup, attended confirmation,
configuration replacement, test PF reference acquisition and Installer call.
The bootstrap can still have created a private staging directory and extracted
its pinned package. No new configuration or installer success is established.

Read-only SSH observations at 2026-09-30 11:30 UTC confirmed:

- `sysctl kern.boottime`: 2026-09-30 07:08:51 local, epoch 1790766531.
- The historical cleanup results directory is absent. The reason it was removed
  is not independently established.
- Sensor launchd job is running as UID 309, PID 887, started 07:10:36 local.
  It still reports `exit timeout = 5`, `keepalive`, and `runatload`.
- Helper launchd job is running as root, PID 888, started 07:10:36 local.
- Deception guest PID 1870 is UID 309, parent 887, started 07:11:08 local.
- Mini `lo0` currently has `192.168.1.240/32`; en0 remains `192.168.1.115`.
- Sensor package receipt is still version 2.1.0, install-time 1790731448.
- The sensor PID matches the unanswered Little Snitch mDNS prompt supplied by
  Matt. This is not a new candidate started by the failed test command.
- A noninteractive, read-only `sudo -n pfctl -s info` required a password.
  Current PF enablement, references and containment rules remain unverified.

## Cause and required change in procedure

Closing the GUI and booting out jobs did not make the stopped baseline persist
across a reboot. The installed launch daemons started again after boot. The test
runner additionally depends on one historical temporary receipt. Replacing or
skipping that receipt would not solve the active-service baseline drift.

Do not use the old PID-pinned restart-cleanup script: its historical orphaned
guest identities do not describe these newly booted processes. Do not blindly
boot out the old five-second sensor job, force-kill guests, reset PF, or modify
Little Snitch rules. No laptop probes are authorized by this failed readiness.

A revised recovery needs fresh privileged read-only inventory, verified backups,
an explicitly approved mini-only controlled shutdown, and a reversible plan to
hold the stopped state across reboot while acceptance is pending. Durable
cleanup evidence must be retained outside temporary storage, with boot identity
and fresh service/runtime/alias/PF validation before continuation. Restore prior
launchd enablement only at the approved boundary. Preserve Studio, native mini
services, product data and all existing backups.

No services, aliases, filter rules, installed files or Git publication state
were changed during this diagnosis. Recovery and the revised acceptance run
remain pending operator approval and attended administration.
