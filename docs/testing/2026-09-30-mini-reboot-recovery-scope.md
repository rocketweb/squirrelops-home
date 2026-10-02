# Mini reboot recovery: stop and hold, not install

Matt approved preparing a guarded mini-only recovery after the boot at
2026-09-30 07:08:51 local restarted the installed sensor. Current observed OS
build is `26A434`, boot seconds `1790766531`, Tailscale `100.108.203.27`, native
LAN address `192.168.1.115`. The old installed sensor receipt is `1790731448`.

## Exact targets and changes

Only these two mini launchd jobs are disabled across reboot and then unloaded:

- `system/com.squirrelops.sensor`
- `system/com.squirrelops.helper`

Before any product mutation, verify host, boot, OS, executable hashes, account,
receipt, config, `.240` ownership, runtime cohort, PF protection, native listeners
and data. Preserve config, both installed launch plists, private command logs and
a consistent SQLite snapshot under a fresh root-private directory beneath
`/Library/SquirrelOps/acceptance-backups`. SQLite is read as UID/GID 309; root
never opens the live database. A service-owned intermediate snapshot remains
private and is recorded, not recursively removed.

Run one disposable root/system-domain launchd experiment with no network access
or product imports. It must demonstrate an eight-second graceful exit followed
by an inert `/bin/sleep` invocation, then verify its own job was unloaded. If the
probe fails, do not signal or disable product jobs. The proof requires root and
has not yet been observed on the mini. Its default opt-in local test is skipped
without root authority.

Then display the two-job scope and request `STOP MINI AND HOLD`. Revalidate the
runtime and network inventory after confirmation. Disable the two product jobs.
Because a loaded KeepAlive job can still respawn despite being disabled, arm
only the sensor's next invocation with `launchctl debug --program /bin/sleep`.
This is an inert process, not a replacement executable written to disk. Failure
to arm it stops before any signal. Recheck PID/start time, send one SIGTERM to
the actual sensor, and allow up to 90 seconds for normal runtime cleanup.

Do not boot out the old five-second sensor while it or its guest remains alive.
Require guest exit, alias withdrawal and empty product PF rules before unloading
the inert sensor job and the original helper. Recheck exact identities before
bootout. No manual alias removal, helper mutation RPC, force-kill, PF flush,
PF enable/disable, or PF reference release is part of this recovery. The running
sensor's normal cleanup removes its own aliases and rules. Unrelated policy,
native listeners, PF enablement/references and decoy identity/intent must match
the pre-stop evidence.

Success creates an exclusive, fsynced `held-stopped.json` in the durable private
backup directory. It records the boot identity, disabled jobs and checked
conditions. A receipt alone never replaces fresh checks; a subsequent reboot
requires revalidation even though the disabled-state hold persists.

## Inverse and failure

Config and installed launch plists are backed up but not edited. No installer,
database SQL mutations, credential changes, Studio operations, native-service
changes or Little Snitch decisions are included. Backups are not automatic data
downgrades. No previous PF tokens are reused.

If a check fails after changes begin, preserve evidence and the disabled-state
hold; never automatically restart or remove surviving protection. A pending
one-shot replacement or inert process may need separately reviewed completion.

The inverse of the hold is to restore effective enablement of those same two
jobs at an explicitly reviewed upgrade boundary, with `launchctl enable`.
Unloading the exact sensor job clears its one-shot debug replacement. Do not
bootstrap the old configuration while it can allocate the Studio's `.241`.
The next acceptance runner must explicitly restore enablement immediately before
its authorized installation and restore the hold on teardown. It must use fresh
durable evidence and the current OS/PF baseline, not the old temporary receipt
or the previous assumption that PF is disabled.

Keep the mini GUI closed. Leave new Little Snitch prompts unanswered. No LAN
probes or release/publication claims follow from recovery alone.
