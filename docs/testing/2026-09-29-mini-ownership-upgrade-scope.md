# Mini ownership-fix recovery and upgrade acceptance

This is an attended local test, not a public release or approval to change Little
Snitch rules. Keep SquirrelOps closed on the mini throughout the test. The
Studio app can remain closed while these tests run.

## Exact targets and bounded changes

- Mini: `matt@100.108.203.27`, macOS 27.0 build `26A428`, ARM64.
- Installed sensor receipt timestamp must remain `1790711659`. Old installed
  app, helper, guest, Python, configuration and startup module must match the
  preceding shutdown-fix package.
- Candidate: `SquirrelOpsHome-2.1.0-ownership-fix-20260929-local-test.pkg`.
- SHA-256: `2d5f4d287ca3ce971fd201f539d27a9272431f160a5a5debddc8d1b0b4dc7c82`.
- This candidate is unsigned and not notarized. The attended runner uses the
  existing one-use local-test installer opt-in. It does not disable Gatekeeper.
- Database: `/Library/SquirrelOps/sensor/data/squirrelops.db`.
- Accept the observed regular, single-link database owned by UID/GID 309 with
  mode `644`, or a mode-`600` database, only inside its UID/GID-309 mode-`700`
  data directory. Both must have no extended ACL. Group/other write access,
  symlinks, hard links, wrong identities, and special file types still stop
  preflight. This corrects the runner's prior unsupported mode-`600` assumption;
  it does not change any installed permissions or the installer payload.
- Restore only `status` from `stopped` to `active` for deep-service rows 1 to 5,
  with respective ports 445, 22, 11434, 1234 and 8765 on `192.168.1.240`.
- Verify that those exact rows were active in the retained consistent database
  at `/Library/SquirrelOps/acceptance-backups/mini-upgrade-20260929.knon9pvr/pre-upgrade.sqlite`.
  Every other field must match that historical state except `updated_at`, which
  is retained as-is. Different counters, credentials, configuration, identities
  or retirement state stop the recovery.
- Preserve row 6 (the classic dev-server listener), other families, all
  credentials, counters and history. Hash every table before and after the
  transaction, excluding only those five status fields.

Before live changes, verify both product services are stopped, no guest runtime
or owned aliases remain, native listener endpoints still exist, and PF is
disabled with no states and only the already-reviewed empty anchor policy.
Check both approved VIPs for conflicts, then create and verify a root-private
full installation/configuration/data backup and a consistent SQLite backup.
The runner prints the five-row dry-run and requires the exact attended phrase
`RESTORE FIVE AND UPGRADE`. Return declines without recovery or installation.

## Upgrade, restart and LAN checks

After confirmation, claim this package's single-use attempt marker, restore the
five fields transactionally, and retain an exclusive mode-0600 inverse journal.
Acquire only this session's PF reference, then install the pinned package.
Validate installed payloads, health and guarded publication of all five services.
Stop the sensor normally, require guest exit and alias withdrawal, verify that
shutdown preserved all five rows, then restart and repeat readiness checks.

Only after `READY FOR TESTS`, the laptop `192.168.1.7` on `wlp0s20f3` may run the
bounded client. It tests SSH banner/login and synthetic file operations over
SSH/SFTP/SMB, plus the three advertised AI HTTP services. Synthetic guest
credentials move only through private files. It also checks that direct
connections to the advertised backend ports are refused. Network scope is
the test VIPs `.240` and `.241`, not the mini's native SSH/SMB services.

The runner observes for at most 20 minutes after readiness; Return stops early.
Scoped packet metadata and sanitized service/connection/alert snapshots support
correlation. Stop on unexpected prompts: leave new Little Snitch or macOS
connection prompts unanswered and report their process/path/destination.
No third-party filter changes, broad PF flush, unrelated service stop, real
credential use, or uncontrolled scanning are permitted.

## Cleanup and inverse

Stop sensor and guest, verify exit before withdrawing only ledger-owned VIPs,
clear only product PF rules, stop the helper, verify native listener parity,
then release only this session's PF reference. Never force-kill a surviving
guest or drop its protection. Uncertain installer completion or unsafe cleanup
stops for review with protection retained.

Keep the upgraded installation, data and root-private backups. `cleanup.json`
preserves successful teardown evidence even if `status.json` later records an
acceptance failure. Do not reopen the app pending review.

There is no automatic downgrade or data rollback. If recovery completes but
installation subsequently fails, the five restored intent fields may remain
active while services remain stopped. A reviewed inverse uses this attempt's
`five-row-recovery.json` and `pre-upgrade.sqlite`, with services stopped and
fresh conflict checks. Restoring old binaries or all database contents requires
separate exact approval; never overwrite new evidence indiscriminately.

## Release boundary

These are upgrade/restart and normal-protocol checks. They do not complete the
separate A5 live PF fault/isolation matrix. That gate and independent review of
the updated PR remain required before release publication. No commit, push,
merge, tag, publication, or website update is performed by this runner.
