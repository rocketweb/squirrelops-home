# Mini shutdown-fix upgrade: installed, guest readiness failed

Date: 2026-09-29. **The pinned package installed, but ordinary protocol acceptance
did not start. A reproducible persisted deep-decoy startup defect blocks release.**
No product fix or additional installation is claimed in this record.

## Exact session

- Approved scope: [upgrade and ordinary protocol acceptance](2026-09-29-mini-upgrade-protocol-scope.md).
- Package SHA-256: `541fc783c41fd2f9a6baba1fe8edae93078a0a24089b8e6d4ede77ba051b7fb1`.
- Mini staging: `/Users/matt/squirrelops-mini-upgrade.Um4HlMcy`.
- Private execution: `/private/var/root/squirrelops-mini-upgrade.aQ8SysJU`.
- Private backup: `/Library/SquirrelOps/acceptance-backups/mini-upgrade-20260929.knon9pvr`.
- Sanitized results: `/private/var/tmp/squirrelops-mini-upgrade-results.63yk75te`.
- Laptop client staging remains unused: `/root/squirrelops-mini-upgrade-client.tnStT9B9`.

The operator ran the reviewed attended command. A Scapy/cryptography finite-field
Diffie-Hellman deprecation warning appeared during preflight; it did not abort
the run. At 19:53:48 UTC the root-produced status changed to `installing`, which
is reached only after the pinned runner's backup and preflight checks succeed.

Both installed receipts now have version 2.1.0 and install-time `1790711659`.
Independent unprivileged SHA-256 checks after cleanup matched the new payload:

| Installed component | SHA-256 |
| --- | --- |
| App executable | `6b4785162f19a01abb8efc3539ad1bd36101cc93442523b7a8912758336cf03f` |
| Privileged helper | `e903f082d194b153782c6435c6dda1c6ae12d8566e51e6b83cc3bd922cebc67a` |
| Guest runtime | `41b74f04f6a25a4f5fc50aba4120356ea4231eb8c03c83e122e44dc902296819` |
| Sensor shutdown module `__main__.py` | `c0819d199b6f609c2a012070b8451c68fcf8771821cda5a8a459c4601dde0181` |

At 19:55:42 UTC the mini's localhost health endpoint returned
`{"status":"ok","uptime_seconds":89.5}`. The guarded `before.json` snapshot
is produced only after installer exit zero, payload/config verification and
stable sensor health. None of these establish guest readiness.

## Observed failure

The root-produced [pre-upgrade snapshot](evidence/2026-09-29-mini/upgrade-pre-upgrade.json)
has five active deep-decoy rows, IDs 1 through 5, with ports 445, 22, 11434, 1234
and 8765 at `.240`. The durable virtual-IP row was present, but no alias or PF
rules were active in the stopped baseline.

The [post-install startup snapshot](evidence/2026-09-29-mini/upgrade-before.json)
shows all five rows stopped, the virtual-IP table empty, no owned aliases, no
product PF rules and zero connections/alerts. No guest process appeared.

At 19:57:32 UTC the runner recorded
`RuntimeError: Guest did not become ready within three minutes` and completed
its cleanup path without adding a cleanup error to the final reason. The
[retained final status](evidence/2026-09-29-mini/upgrade-final-status.json)
is `needs_review`, not a passing acceptance result.

No laptop probes, authentication, synthetic file operations or credential
transfer occurred. The prior TCP/filter experiments neither caused this
selection defect nor establish protocol success for this run.

## Reproduced mechanism

The classic `DecoyOrchestrator.resume_active()` selects every active/degraded
row except `mimic`, so it also selects `deep` rows. It applies the classic
three-listener profile limit to those five deep service records, marking two
stopped. Its factory maps unrecognized types, including `deep`, to the HTTP
`FileShareDecoy` fallback. The first three selected records are therefore handed
to the classic listener path on the physical host address, not the guest path.

The mini already has native listeners on those three ports: 445, 22 and 11434.
The classic resume exception handler marks failed rows stopped. Later in startup,
`DeepDecoyOrchestrator.start()` sees the stopped primary row and correctly honors
it as stopped, so it never activates the guest. Startup orders the classic
resume before the deep manager. The SQL ownership error explains why a clean
first provisioning could work while a restart/upgrade loses the deep host.

The diagnostic [reproduction script](fixtures/reproduce_deep_restart_selection.py)
ran against the exact extracted package runtime using an in-memory database,
five synthetic active deep rows and mocked occupied-port failures. No listeners,
real credentials, installed data or PF rules were touched. The real factory
constructed three `file_share` objects, for physical-host ports 445, 22 and
11434. All five deep rows became stopped, reproducing the observed state change.
Its preservation assertion failed as intended with:

```text
AssertionError: Classic resume changed deep-host restart intent
```

This confirms the packaged-code defect and reproduces the mini's transition.
The three bind errors were simulated in the local reproduction; private mini
startup logs were not read, so they are not presented as captured live stack
traces. Related classic capacity/reconfigure/degraded-recovery queries also
exclude only `mimic`; they need review as part of the eventual fix.

## Stopped-state verification and limits

At 19:57:53 UTC independent SSH checks found both product launchd services absent
with their exact missing-service errors and no matching product or guest/VM
processes. A later `ifconfig` check found neither approved VIP. `netstat` found
no 8443 listener and retained native SSH, SMB, Screen Sharing, Ollama and the
loopback inference listener. No third-party filter was changed.

The final `needs_review` write replaces the runner's successful `stopped`
status, so its public file does not retain the detailed PF-release fields.
The original failure reason contains no cleanup exception. This is consistent
with successful guarded teardown, but PF/reference state was not independently
re-read as root. The operator was asked to confirm the final Terminal cleanup
message. Keep the mini app closed and do not rerun the consumed upgrade script.

The private pre-upgrade backup retains the original active records. Do not
bulk-enable stopped decoys or rewrite the live database to bypass the gate.
Any eventual restoration must identify these exact five rows and preserve
genuinely operator-stopped services and all forensic history.

## Recommended next scope, not yet executed

1. Restrict classic lifecycle and capacity operations to the types they own;
   reject unsupported factory dispatch. Do not hide deep rows from `/decoys`.
2. Add mixed classic/mimic/deep startup, profile-change and recovery regressions,
   plus a real packaged restart/upgrade check. Preserve deliberate stopped intent.
3. Perform the required deception review: banners, guest protocols, synthetic
   data, weak-looking presentations and telemetry must remain unchanged.
4. Rebuild a new local-test installer after those checks. Prepare a separate,
   exact-artifact mini continuation and reviewed recovery of the affected rows.

No workaround, source patch, rebuild, commit, push or release was performed
during this diagnostic session. The engineering-constraints skill guided the
local reproduction before proposing a fix.
