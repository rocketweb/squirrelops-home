# Mini post-reboot acceptance: installation/restart pass, SSH/SMB blocked

Observed on 2026-09-30. The corrected runner installed the pinned candidate
and completed its normal sensor restart check. The laptop's ordinary protocol
gate failed on SSH and SMB, so authentication, file writes and backend denial
tests did not run. After operator Return, cleanup stopped at 16:26:07 UTC on
the runner's exact six-row intent check. Services stopped and the disabled hold
was restored, but the PF-reference release was not reached in that attempt.
The separately approved cleanup continuation completed at 17:12:32 UTC,
released only the original test reference and recorded PF disabled. This
completes cleanup, not overall protocol acceptance or release readiness.

## Exact run

- Mini: `100.108.203.27`, macOS build pinned to `26A434`, boot `1790777754`.
- Attended staging: `/Users/matt/squirrelops-mini-post-reboot-v2.UU8waUaT`.
- Private execution: `/private/var/root/squirrelops-mini-post-reboot.lQlvs3JI`.
- Root-produced sanitized results:
  `/private/var/tmp/squirrelops-mini-post-reboot-results.3p_hssk9`.
- Laptop: `192.168.1.7`, client directory
  `/root/squirrelops-mini-upgrade-client.VNbggFA7`.
- Candidate: `SquirrelOpsHome-2.1.0-launchd-budget-20260930-local-test.pkg`,
  SHA-256 `3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c`.
- Scope: `mini-post-reboot-240`, only `192.168.1.240` was probed.

Before traffic, the root-owned readiness record, parent/input metadata, exact
package/scope/boot, configuration confirmation, remaining time and endpoints
were checked. Both laptop script hashes matched the staged approved versions.
The wrapper passed its own fresh-readiness, one-use, source-address and route
checks. The synthetic guest login was transferred through a mode-0700 local
directory into mode-0600 root-owned laptop inputs without displaying it.
It is not included in repository evidence and was not used for authentication.

## Observed results

| Check | Result | Evidence |
| --- | --- | --- |
| Package installation | Pass | Both 2.1.0 receipts have install time `1790784842`; all seven installed payload checksum/metadata checks passed independently over SSH |
| Shutdown allowance | Pass | Loaded sensor job reports `exit timeout = 60` |
| Normal sensor restart | Pass under runner checks | `first-start.json`, `after-restart.json` and fresh readiness exist; the pinned path requires guest exit, alias/policy cleanup and preserved intent before restart |
| Five advertised services | Configuration/runtime readiness pass only | Five guarded mappings for 22, 445, 11434, 1234 and 8765 on `.240` |
| SSH banner | **Fail** | TCP connected, but banner receive timed out after five seconds |
| SMB share discovery | **Fail** | `smbclient` did not complete within the client's bounded wait; no share listing was recorded |
| OpenAI-compatible `/v1/models`, port 1234 | Pass | HTTP 200, 210 bytes, valid nonempty model list |
| Ollama `/api/tags`, port 11434 | Pass | HTTP 200, 651 bytes, valid nonempty model list |
| MCP `tools/list`, port 8765 | Pass | HTTP 200, 894 bytes, valid nonempty tool list |
| Sensor evidence | Partial pass | One connection each for ports 1234, 11434 and 8765 from `.7`; one high-severity `decoy.trip` alert persisted |
| SSH/SMB sensor evidence | **Absent** | Both corresponding counters remained zero; no matching connection rows |
| Direct backend/native-port denial | Not run | Protocol prerequisite failed before this phase |
| Wrong-password and successful authentication | Not run | Protocol prerequisite failed |
| SFTP/SMB synthetic file roundtrips | Not run | No file operations attempted |
| Initial teardown | **Stopped for review** | Runtime stopped, aliases withdrawn and both jobs disabled; extra-row intent check stopped execution before PF-reference release |
| Approved cleanup continuation | Pass | At 17:12:32 UTC, the root receipt confirms the original test reference released, PF disabled and all seven decoys preserved; fresh SSH checks confirm no runtime/aliases and both jobs disabled/unloaded |

The exact client invocation was:

```text
python3 -I -B /root/squirrelops-mini-upgrade-client.VNbggFA7/mini_post_reboot_client.py --run /root/squirrelops-mini-upgrade-client.VNbggFA7
```

It ran once and exited 1. The checks completed between 16:19:00 and 16:19:20
UTC. [Client results](evidence/2026-09-30-mini-post-reboot/client-results.jsonl)
record the failed protocol gate and explicitly state that authentication and
file operations were not attempted. No new probes or client retries followed.

## Server evidence and unexpected new row

Retained snapshots:

- [Pre-upgrade](evidence/2026-09-30-mini-post-reboot/pre-upgrade.json)
- [First startup](evidence/2026-09-30-mini-post-reboot/first-start.json)
- [After normal restart](evidence/2026-09-30-mini-post-reboot/after-restart.json)
- [Before probes](evidence/2026-09-30-mini-post-reboot/before.json)
- [Endpoint mapping](evidence/2026-09-30-mini-post-reboot/endpoints.json)
- [Post-probe observation](evidence/2026-09-30-mini-post-reboot/latest.json)
- [Final observation before teardown](evidence/2026-09-30-mini-post-reboot/after.json)
- [Cleanup failure status](evidence/2026-09-30-mini-post-reboot/final-status.json)
- [Subsequent successful cleanup receipt](evidence/2026-09-30-mini-post-reboot/cleanup-complete.json)

The existing six rows kept their IDs, types, bind addresses, ports and active
intent through startup/restart and the collected post-probe snapshot. During
observation an additional `home_assistant` row appeared: ID 7 on native address
`192.168.1.115:51232`, active, with zero connections. No agent command created
this row. Subsequent [private-log review](2026-09-30-mini-readonly-diagnostic-result.md)
confirmed classic auto-deployment at 12:16:43 local time, before the probes.
The classic `.115:60556` listener's original row remains present.

The runner's final `restore_hold()` calls `verify_intent()`, whose exact
six-row equality check rejects any additional row. This was confirmed as the
actual cleanup failure, not a surviving-guest timeout. Do not delete row 7,
overwrite the database or relax a live runner to manufacture a pass. A
pre-upgrade `owned_aliases` value is ledger evidence, not proof of an active
interface alias.

## Cleanup failure diagnosis

The root-produced final status at 16:26:07 UTC reports:

```text
Cleanup incomplete: Persisted decoy identity or intent changed; no database repair authorized
```

Fresh read-only SSH checks after this status found:

- Both `com.squirrelops.sensor` and `com.squirrelops.helper` absent from the
  system launchd domain, each with the explicit missing-service error.
- Both product jobs explicitly disabled.
- No SquirrelOps sensor/helper/guest or Virtualization process, and no `.240`
  or `.241` interface alias. A service-account `distnoted` process remains;
  that is not the product runtime.
- Boot unchanged at `1790777754`.

A local read-only reproduction loaded the actual runner's `validate_intent()`
and the recorded pre-upgrade/final JSON. All six original five-field rows
matched exactly. The only addition was `[7, "home_assistant", "192.168.1.115",
51232, "active"]`. The original six rows pass the validator; the recorded
seven-row snapshot raises the exact observed error. No live database was
opened or changed for this reproduction. The origin of row 7 was unverified
at that point; subsequent private-log review confirmed application auto-deployment.

The error occurs in `restore_hold()` after both disable operations and before
the inherited PF-reference release. The runner's preceding cleanup path also
checked guest exit, no service-owned listeners, owned-alias withdrawal, empty
product policy parity and preservation of original listener endpoints.
Those root checks are inferred from the pinned execution path and stop location;
only the unprivileged stopped-state checks listed above were independently
repeated during the failure diagnosis. The remaining reference and current PF
policy were subsequently checked by the approved cleanup-only continuation,
which released the reference and produced the successful receipt above. There
was no PF reset, database edit or installer retry.

## Little Snitch and diagnostic limits

The operator supplied screenshots of Python connection prompts to `.6`
(marked terminated) and `.111` (not marked terminated). Their age and process
identity were not established from those screenshots. Neither target matches
the bounded laptop probes. The operator was asked to leave the prompts
unanswered and report the `.111` information-tab path/PID. No rule decision or
filter change was made by the agent.

All three AI services responded, while SSH/SMB did not. This narrows the
observed failure but does not prove whether the guest relay, native routing,
PF state or a content filter is responsible. Do not attribute the failure to
Little Snitch merely because prompts were visible. The running guest process
was PID 15923, its Virtualization process PID 15924, and the sensor PID 15614
in the inspected inventory.

An unprivileged Little Snitch query for the one-minute probe window exited 14
without usable traffic evidence. Sensor logs were not readable as `matt`.
Unprivileged `netstat` produced no matching `.240` rows, despite fresh readiness
and a visible `.240` interface alias; that empty output cannot establish absent
listeners or completed cleanup. Privileged packet/log evidence remains in the
runner's private backup and requires a scoped attended read.

## Next boundary

Keep the app closed. The approved
[cleanup-only continuation is complete](2026-09-30-mini-reference-cleanup-preparation.md).
It preserved all seven rows and released only this run's own PF reference
after checking its private provenance. No reinstall, restart, database repair
or Little Snitch change occurred. Do not rerun that consumed command.

The next unresolved issue is the failed SSH/SMB protocol gate. Existing private
packet/log evidence should be reviewed before proposing another live test or
any filter decision. A new privileged diagnostic export or runtime startup is
not implied by this cleanup result. No new probes were run after cleanup.

The operator subsequently approved proceeding with retained-evidence review.
A [narrow read-only exporter](2026-09-30-mini-readonly-diagnostic-preparation.md)
completed its attended export at 17:28:23 UTC. The
[reviewed result](2026-09-30-mini-readonly-diagnostic-result.md) confirms received
SMB request data, present guest listeners, no parsed SSH/SMB response payload,
and successful Python-backed services. It does not identify a specific filter
or guest-relay cause. No restart, new probes or filter changes occurred.

The engineering verification skill was used to distinguish observed passes,
failed prerequisites, skipped tests and unknown causes. No code changes,
rebuild, commit, push, Little Snitch rule change or publication occurred during
these probes. A successful recovered-host restart does not satisfy the separate
old-running-daemon upgrade, A5 fault/isolation, signing or release gates.
