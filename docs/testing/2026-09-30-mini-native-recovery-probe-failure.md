# Native recovery proof failed: do not retry shutdown

The attended v2 runner reached the mandatory disposable system-domain launchd
proof, then reported `Probe respawn was not inert`. Evidence is retained at:

`/Library/SquirrelOps/acceptance-backups/mini-reboot-20260930.nJZbW9EI`

The user-supplied transcript reports that preflight config, launch plist,
launchd-state and consistent SQLite backups completed. The failure occurs before
the `STOP MINI AND HOLD` confirmation and before product mutation is enabled.
No installer or LAN test ran. Do not treat this as successful recovery.

## Fresh read-only verification

- Boot remains epoch 1790766531, 2026-09-30 07:08:51 local.
- Sensor PID 887, helper PID 888, each still at launchd runs 1.
- Guest PID 1870 and VM PID 1871 still run as UID 309.
- Sensor still reports the old five-second launchd exit allowance.
- The exact disposable job
  `com.squirrelops.test.recovery.d349e1004cca4474a44928b260a498a6`
  is absent from the system domain. Its effective-enabled override record
  remains. No product disabled override was observed.
- The private evidence directory is inaccessible to the SSH user, and
  noninteractive sudo requires a password. Its contents have not been read by
  the agent.

## User-supplied private evidence

Matt subsequently supplied the narrowly extracted probe records. This is
user-supplied evidence, not a fresh agent read of the private directory:

```text
Probe events: READY 19884
TERM
DONE
```

The exact disposable job's command was:

```text
/bin/launchctl debug system/com.squirrelops.test.recovery.d349e1004cca4474a44928b260a498a6 --program /bin/sleep -- /bin/sleep 2147483647
```

It returned exit 0, empty stdout, and `Service configured for next launch.` on
stderr. The subsequent `/bin/ps -p 20357 -o comm=` returned exit 0 and:

```text
/Library/SquirrelOps/sensor/python/bin/python3.12
```

The original worker received TERM and reached DONE. However, the replacement
observed by the guard was Python, not `/bin/sleep`. A successful `launchctl debug`
return therefore did not establish the required inert replacement. The precise
reason remains unproven. Do not weaken the identity check, assume eventual
success, or use this mechanism to stop the real sensor.

## Decision and remaining boundary

After the repeated recovery failures, the engineering-constraints skill requires
reassessment of the recovery design before another fix/attempt. Retire the
current next-launch replacement approach. No new shutdown runner was built or
staged, and the existing v2 runner must not be retried.

A possible alternative is a separately approved, attended maintenance reboot
with both product jobs persistently disabled and their disabled state verified
first. This is a proposal, not an approved or tested recovery procedure. It
interrupts other mini workloads and SSH, and the old shutdown budget could still
truncate normal cleanup. It therefore requires fresh preflight and durable
backups, followed by a post-boot audit of processes, aliases, product ownership
records and PF state before any installation or restart. No automatic rollback
may restart the old pool while the Studio owns `.241`. Studio changes, filter
resets and Little Snitch rule changes remain out of scope.

The proposed reboot is host recovery, not proof that the installer can safely
upgrade a running old version. The new 60-second plist only takes effect after
loading that plist; release readiness still requires a verified old-version
upgrade path and native restart acceptance.

Keep the app closed, leave Little Snitch prompts unanswered, and preserve all
backups. No new host mutation, reboot, installation, LAN probe or publication
was performed on the basis of this evidence.
