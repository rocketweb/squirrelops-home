# Resolver-fix Mini run: scoped acceptance passed

The approved one-shot laptop run finished successfully on **October 1, 2026,
9:20:18 p.m. Eastern**. All **17 client checks passed**, process exit 0.
The anonymous SMB share list completed in **0.525 seconds**, compared with
20.841 seconds in the earlier SMB-only diagnostic. The previously observed
stall did not recur in this run.

**Cleanup verified:** the runner completed at **9:38:33 p.m. Eastern** and a
fresh read-only check at **9:58:47 p.m.** confirmed stopped/disabled product
jobs, no guest/product processes and no test aliases. The root-produced final
receipt confirms preserved native listeners, release of only this run's PF
reference, and PF disabled. The new installation and all seven decoys remain.

**Alert detail verified:** the operator's read-only SQLite result confirms
alert 3 remains unread, contains all 22 recorded connections and was last
updated at `2026-10-02T01:20:18.223308Z`, matching the final client operation.
This closes the folded-alert check for this run.

**Filter observation confirmed:** the operator answered **no** when asked
whether any new Little Snitch prompt appeared during the successful run.
This is operator-reported evidence, not an independent rule audit.

The approved resolver-fix Mini run is complete and passed under the existing
test policy. Unattended/default-filter behavior is not inferred. Do not rerun
the consumed client, reopen the held app or change rules without the next
approved scope. These results do not authorize public release.

## Exact artifact and installation

- Candidate: `SquirrelOpsHome-2.1.0-guest-resolver-20261001-local-test.pkg`.
- SHA-256: `47774088cd9eadc5aaddf38949e00a8b8f6eeb56c2192a5a72830d06d84a8aec`.
- Both installed component receipts: 2.1.0, install time `1790903800`.
- Installed app executable:
  `132ccbe57823481da159e15b2bf0a0140994bb911c3d659a0c815515855d7efe`.
- Installed guest manifest:
  `cdbb8bcb53f4d3fc8c04703c7c5fce6b9903a38b263b8290a0fb7ba608b8e13f`.
- `codesign --verify --deep --strict` passed on the installed app. This is
  the ad-hoc local test build, not Developer ID/notarized release acceptance.

The checksum-verified attended runner reached `ready_for_tests` only after
installation, payload verification and its normal sensor stop/start check.
The first-start and after-restart snapshots preserve all seven saved decoys,
their counters and the two classic host listeners. No additional host listener
was reported. Configuration remained unchanged and `.240` only.

## Laptop results

Client window: `2026-10-02T01:19:57Z` through `01:20:18Z` (9:19:57 to
9:20:18 p.m. Eastern on October 1). The single-use client result guard is
consumed. Source was laptop `.7`, through `wlp0s20f3`.

| Check | Result |
| --- | --- |
| SSH banner | `SSH-2.0-OpenSSH_10.3` |
| Anonymous SMB listing | All four shares; exit 0; 0.525 seconds |
| AI endpoints | Ports 1234, 11434 and 8765 returned expected JSON, HTTP 200 |
| Private backend containment | Five backend connections timed out as expected |
| Native-service exposure | `.240:5900` timed out; native Mini VNC was not probed |
| Wrong SSH password | One attempt rejected, exit 255 |
| Synthetic SSH persona | `buildbot`, expected simulated Darwin identity and project content; exit 0 |
| Wrong SMB password | One attempt rejected with `NT_STATUS_LOGON_FAILURE` |
| SFTP file operations | README read, unique upload/download parity and deletion verified |
| SMB file operations | README read, unique upload/download parity and deletion verified |

SMB's final file-operation command deliberately lists the deleted unique file.
Its exit 1 with `NT_STATUS_NO_SUCH_FILE` is the expected deletion proof, not an
authentication or transfer failure. Both test uploads were verified removed.

## Telemetry and alert boundary

Connection evidence recorded the exact ten protocol connections from `.7`:

| Service | Before | After | New |
| --- | ---: | ---: | ---: |
| SMB 445 | 2 | 5 | 3 |
| SSH 22 | 1 | 5 | 4 |
| Ollama 11434 | 3 | 4 | 1 |
| OpenAI-style 1234 | 3 | 4 | 1 |
| MCP 8765 | 3 | 4 | 1 |

Classic listeners remained at zero. Seven SSH/SMB relay sessions were accepted,
connected to the guest and closed; fixed-vocabulary diagnostics show no failed
connect, read, write or timeout stage. Idle listener queues were zero.

Credential-trip counters stayed zero. This is expected for the opaque SSH/SMB
relays; they do not inspect encrypted authentication. The explicit agent API
credential-trip route was not part of this approved client run and is not
claimed tested here.

One existing source alert remains in the basic snapshot (ID 3). The harness
exports only its identity, severity, source and creation time, not mutable
detail. The operator subsequently supplied the requested read-only SQLite
result, preserved as `alert-detail-operator.json` with that provenance:

- Alert ID: **3**, unread: **1**.
- Connections: **22**, exactly the sum of the post-run connection records.
- Last seen: **2026-10-02T01:20:18.223308Z**, within the final client second.
- Service totals: **SSH 5, SMB 5, 1234: 4, 11434: 4, 8765: 4**.

All service totals match the independent saved snapshot. The 12 pre-run
connections plus this run's ten connections account for all 22. The unchanged
alert ID is the documented folding behavior, not a missing alert. This is
operator-provided database evidence reconciled with captured client/sensor
evidence, not a claim that the agent independently queried the live database.

An attempted scoped `sudo -n` read-only query failed with `a password is
required`; it did not read or alter the database. After cleanup, the operator
ran the compact read-only query below and supplied its output. It need not
be repeated:

```sh
sudo -u _squirrelops /usr/bin/sqlite3 -batch -init /dev/null -readonly -header -column \
  /Library/SquirrelOps/sensor/data/squirrelops.db \
  "SELECT id, read_at IS NULL AS unread,
   json_extract(detail,'$.connection_count') AS connections,
   json_extract(detail,'$.last_seen') AS last_seen,
   json_extract(detail,'$.service_counts') AS services
   FROM home_alerts
   WHERE id=3 AND source_ip='192.168.1.7' AND alert_type='decoy.trip';"
```

Do not acknowledge or clear the alert to manufacture a new one. Do not send
another probe as a substitute for reading the saved evidence.

## Evidence and completed cleanup

Sanitized local evidence:
[`evidence/2026-10-01-mini-resolver/`](evidence/2026-10-01-mini-resolver/).
It includes client results, before/after restart snapshots, post-client
counters, endpoint mappings and bounded relay checkpoints. No synthetic login
was copied into the repository. Private transfer files remain in a 0700
temporary directory with login files at 0600.

- Mini results: `/private/var/tmp/squirrelops-mini-resolver-results.bdhye4l6`.
- Consumed laptop run: `/root/squirrelops-mini-resolver-client.yquQ1Mfr`.
- Private local transfer: `/private/tmp/squirrelops-resolver-live.ypaOMjMg`.
- Server claim: `/Library/SquirrelOps/acceptance-backups/relay-1790777754-47774088cd9e-attempt.json`.

The final `after.json`, `after-diagnostics.json` and `cleanup-status.json`
are now saved. Final pre-cleanup counters match the immediate post-client
snapshot exactly; there were no additional test connections or new decoys.
`after.json` was taken immediately before teardown, so its alias and `active`
intent fields must not be interpreted as current runtime state. The later
cleanup receipt and live process/launchd/interface checks establish shutdown.

Cleanup receipt SHA-256:
`07b1dc96d92c8ad759f26bf66f3aa31fb838d57f313ebdafb18f64cc1b74e22f`.
The final receipt has `phase=stopped`, `.240`-only scope, preserved installation
and data, `aliases_absent=true`, `guest_stopped=true`,
`original_listener_endpoints_present=true`, `own_pf_reference_released=true`
and `pf_enabled=false`. No PF command was repeated to establish these facts;
the root-produced receipt provides the privileged cleanup evidence.

The compact operator query was first validated against a synthetic in-memory
SQLite row. That syntax check was not counted as live alert evidence; the
subsequent operator-provided result closes the live detail check.

No Little Snitch rule was edited, no global PF reset was performed, and no
Studio or `.241` tests were made. No commit, push or publication occurred.
The engineering-constraints skill required reconciling the supplied alert
detail with the exact saved connection counts before closing that gate.
The operator's no-new-prompt confirmation closes the final observation for
this scoped run. Separate public release gates remain outside this result.
