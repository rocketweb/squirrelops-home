# Ownership-fix mini upgrade: first start passed, restart failed

Status: failed live restart acceptance. Do not promote this package or rerun the
consumed installation runner. Keep SquirrelOps closed and retain PF protection.

## Exact attempt

- Candidate SHA-256: `2d5f4d287ca3ce971fd201f539d27a9272431f160a5a5debddc8d1b0b4dc7c82`.
- Attended runner: `/Users/matt/squirrelops-mini-ownership-v2.290wspVB/start-mini-ownership-acceptance.sh`.
- Root staging: `/private/var/root/squirrelops-mini-ownership.s4L9F0BA`.
- Private backup: `/Library/SquirrelOps/acceptance-backups/mini-upgrade-20260929.z8rfqzvz`.
- Sanitized results: `/private/var/tmp/squirrelops-mini-upgrade-results.w3qacnps`.
- Updated installed sensor receipt timestamp: `1790731448`.

Matt confirmed the printed five-row preview with `RESTORE FIVE AND UPGRADE`.
The runner passed installed payload verification and first-start readiness,
then failed its normal sensor-stop check. Root-produced status at
`2026-09-30T01:26:48Z` records:

```text
RuntimeError: Runtime survived restart stop; retain protection
Cleanup incomplete: Guest/runtime remains; no force-kill or PF release
```

## Read-only observations

`first-start.json` reports rows 1 to 5 active at `192.168.1.240` on ports 445,
22, 11434, 1234 and 8765. Row 6, the existing classic dev server on
`192.168.1.115:60556`, is still active. All recorded counters remain zero;
connection and alert inventories are empty. The guest's five advertised
ports have tag/UID-guarded PF mappings in that startup snapshot.

After the failure, the sensor launchd job is absent and the Python sensor is
gone. These identities were still present when checked:

| PID | UID | Parent | Executable |
| --- | --- | --- | --- |
| 65298 | 0 | 1 | `/Library/PrivilegedHelperTools/com.squirrelops.helper` |
| 65499 | 309 | 1 | `/usr/sbin/distnoted` |
| 65802 | 309 | 1 | `/Applications/SquirrelOps Home.app/Contents/Library/Helpers/com.squirrelops.deception-guest` |
| 65804 | 309 | 1 | `/System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine` |

PIDs are historical observations, not permission to signal them later without
fresh identity/start-time checks. The helper launchd job remains running.
The session's stop path refused to withdraw aliases or release its PF reference
while the guest survived. Current root-only PF contents have not been separately
retrieved; startup rules are not a substitute for current-rule verification.

Public launchd logs show the sensor becoming inactive and being removed at
`2026-09-29 21:24:46.252` local time. They do not establish its exit signal or
the cleanup step at which it stopped. A surviving guest alone does not prove
Little Snitch terminated the Python process.

## Next diagnostic boundary

The protected sensor log is required to locate the last completed shutdown
step. Current unit signal tests exercise real SIGTERM/SIGINT delivery with a
fake fast guest stop; they do not prove the complete launchd/real-guest cleanup
path succeeds. Do not loosen the harness wait or force-kill the guest without
determining the mechanism and reviewing containment/cleanup.

No client probes were run. No signals, firewall changes, restarts, data edits,
package rebuilds, commits, pushes, or releases were performed during this
read-only investigation. The retained backup and recovery journal remain the
rollback evidence for any subsequently approved continuation.

## September 30 follow-up: launchd timeout confirmed

The operator's sensor log stops at `Stopping scan loop...` at 21:24:43.419.
A subsequent read-only unified-log query found launchd's explicit cause:

```text
2026-09-29 21:24:45.239 Service did not exit 5 seconds after SIGTERM. Sending SIGKILL.
2026-09-29 21:24:46.252 exited due to SIGKILL | sent by launchd[1]
```

The installed sensor plist lacked `ExitTimeOut`. mDNS goodbye consumed about
three seconds before the scan loop's bounded ten-second drain. launchd killed
the process before guest cleanup. This establishes the stop mechanism without
attributing it to Little Snitch. A disposable launchd job reproduced the old
failure and passes with the new finite 60-second allowance. See
`2026-09-30-launchd-shutdown-budget.md` for current verification and limits.
