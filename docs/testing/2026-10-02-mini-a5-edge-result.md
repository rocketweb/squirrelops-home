# Mini A5 TCP-edge results

Date: October 2, 2026. Result: **all five planned phases completed and both
machines cleaned up. Simultaneous listener ambiguity was rejected. Two
retained-state replacement cases remain qualified by observed kernel behavior.**

This was the single approved [TCP-edge experiment](2026-10-02-mini-a5-edge-preparation.md).
No product source, installed package, data, service configuration or Little
Snitch rule was changed. It is not full A5 sign-off or release approval.

## Evidence identity

- Mini nonce: `cbba59af3e2b`.
- Private Mini evidence: `/Library/SquirrelOps/acceptance-backups/mini-a5-edges-20261002.ouytf6ce`.
- Sanitized Mini evidence: `/private/var/tmp/squirrelops-mini-a5-edges.wenpfk2w`.
- Private laptop evidence: `/root/squirrelops-edge-client.u71oojsw`.
- Laptop filter nonce: `c99b94e003f5`.
- Local evidence: `build/test-artifacts/a5-edges-20261002-ouytf6ce/`.

The pinned coordinator exited 0 after the five client responses and Mini
cleanup receipt. Client probes and state observations span 13:53:34 to
13:53:50 UTC. All 39 copied Mini JSON files match their remote SHA-256 hashes.
The local `evidence-sha256.txt` also covers the client responses, saved phase
statuses, laptop cleanup receipt and counter derivation. Its SHA-256 is
`5177d48cd71866ce79611e0d1ea368693bafbbcefc0e78e0800b8ed206e06846`.

The user was asked whether a new Little Snitch prompt appeared. No answer
was available when this report was written; do not infer that no prompt appeared.

## Results

| Case | Direct observation | Disposition |
| --- | --- | --- |
| Healthy established control | Both public endpoints returned `A5 uid=309`; both PF states were `ESTABLISHED:ESTABLISHED`. | Control passed. |
| Close listening sockets, retain accepted sockets | Both original UID-309 connections returned `A5-PONG uid=309`. Both attempted UID-501 binds failed with Darwin errno 48; selected listener inventory was empty. | Cross-user reuse was prevented in this tested configuration. This was not a successful wrong-UID replacement with an established socket. |
| Inject quarantine-load and first-IP state-kill failure | Helper returned `ok=false` and alias authorization `[false,false]`. The .239 established state survived; .240 was absent in the pre-probe state snapshot. Fresh public connects timed out while original trusted sockets remained usable. | Failure was not misreported as safe cleanup. It did not disconnect every trusted accepted socket, and no replacement UID-501 listener existed in this phase. |
| Exact plus wildcard ambiguity | Four simultaneous UID-309 listeners existed: exact and wildcard on each backend. The unchanged production guard returned `ok=false`; none were published. | Simultaneous ambiguity rejection verified on both ports. |
| Half-open control and retransmission | Two SYNs per tuple produced six SYN-ACK observations in total, including server retransmissions. Both PF states were `SYN_SENT:ESTABLISHED`; no handshake was completed. | Actual half-open control verified. |
| Stop half-open listeners, bind UID 501, inject cleanup failure | Both UID-501 listeners bound. Stopping the originals emitted one RST/ACK per tuple. Before replacement probes, .239 was `TIME_WAIT:TIME_WAIT`, not half-open; .240 had no state. The guard rejected the new owners and cleanup remained unauthorized. | Same-sequence retransmission against replacement listeners was tested, but retained half-open replacement was not. |
| Wrong-owner retransmission | Two SYNs per tuple reached en0. No new response appeared; guarded-pass counters did not increase and each VIP block counter increased by two packets. | No SYN-ACK or recorded UID-501 LAN accept. PF participation in blocking is observed, subject to the export limits below. |
| Successful quarantine and final retransmission | Helper returned `ok=true`, alias authorization `[true,true]`; final scoped PF state inventories were empty. Two further SYNs per tuple reached en0 with no response. | Recovery and final denial verified. |

The held-socket responses came from the original trusted processes, not from a
different UID. Both held connections completed FIN/EOF, leaving closing states
in the after-snapshot. The established test therefore cannot demonstrate
delivery to a wrong-owner replacement that the kernel refused to create.

The half-open test retained the exact source ports and SYN sequence numbers
across all three phases. Its two pre-phase RST/ACK observations were recorded
separately, not hidden among the later no-response results. Neither replacement
nor quarantine produced a new SYN-ACK. The Mini capture contains all twelve
raw SYNs, six per tuple, and no laptop RST for those tuples during the control.

## Qualified counter and event review

Subsequent review: the [completed retained-evidence review](2026-10-02-saved-release-evidence-result.md)
identifies all 56 omitted counter lines by exact checksum and all sixteen
omitted child events by bounded schemas. The unknown-format/event qualifications
below describe the original export and are now resolved. The kernel constraints
and rule-level/filter-attribution limits remain.

Comparisons require the same rule index, complete rule-text hash and
nondecreasing cumulative counters within each phase. These are packet-counter
differences, not connection counts:

| Phase | Block .239 / .240 | Guarded pass .239 / .240 |
| --- | ---: | ---: |
| Healthy established | 2 / 2 | 6 / 6 |
| Established socket, failed rebind | 2 / 2 | 8 / 8 |
| Half-open healthy control | 0 / 0 | 5 / 5 |
| Wrong-owner same-sequence SYN | 2 / 2 | 0 / 0 |
| Final quarantine | 2 / 2 | Not present |

The two wrong-owner and two quarantined block packets per VIP also correspond
to 80 bytes per phase. The packet metadata records the matching two SYNs
arriving on en0 and no outgoing reply during each of those phases; that
sanitized packet export does not itself include packet lengths.
Counter attribution remains qualified: counters are rule-level, other filters
are installed, and the parser withheld 56 additional raw lines across the ten
snapshots. Their content has not been reviewed. No parser was weakened or
withheld line reclassified to force acceptance.

Reproduce the recognized-counter comparison from the local evidence directory:

```sh
jq -n -f review-counters.jq mini/*-counters.json
shasum -a 256 -c evidence-sha256.txt
```

The saved derivation keeps `automatic_gate_pass=false` and every withheld-line
count. Fourteen child summaries contain stopped markers, two UID-309 LAN
accepts and two UID-309 echoes; none records a UID-501 LAN accept. The reused
event parser withheld sixteen lines. It does not recognize the edge fixture's
ready, bind-failure or listener-closed event types; the sanitized summary alone
does not establish the contents of every withheld line. Separate bind and
listener snapshots support the observations above. Do not claim a complete
raw-event review or use this as proof of no possible omitted event.

## Cleanup and preservation

The Mini receipt reports `phase=cleaned`, `cleanup_complete=true`. The runner
only issues that receipt after stopping its disposable listeners, recovering
quarantine, withdrawing its aliases, checking held services, retained-file
parity, native-listener parity and unrelated PF policy, emptying its own
anchor, releasing its own reference once and observing PF disabled.

A subsequent unprivileged read-only check independently confirmed sensor and
helper disabled/unloaded, only the normal loopback addresses on lo0, and no
matching sensor, deception guest or standalone PF probe process. The receipt
remains the privileged evidence for PF/data parity; the follow-up SSH check
does not claim a separate privileged database inspection.

The laptop watchdog reports `phase=cleaned`, `cleanup_complete=true`, one add
attempt and one delete attempt. It verified the resulting filter definition
against its saved baseline, ignoring only documented runtime fields. Baseline
SHA-256: `23879c314fa0e5f92eabf27ba45a16e3d30298fe8e31146e347e8c2ea72d36e4`.
A subsequent `nft list tables` read confirmed the unique test table was absent.
The normal completion path ran; this live run did not test forced parent loss
or kernel timeout expiry. Those remain offline fixture coverage, not live
fault-injection claims.

## Verification and release impact

After the live run, the full fixture suite was rerun: **65 tests passed in
0.774 seconds**. Its intentionally simulated cleanup failures print warnings;
they are not live cleanup failures. Command:

```sh
SQUIRRELOPS_DIAGNOSTIC_CHILD_PYTHON=/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/sensor/.venv/bin/python \
  /usr/bin/python3 -m unittest discover \
  -s docs/testing/fixtures/pf-acceptance -p 'test_*.py' -q
```

No additional product defect was demonstrated by this run. The simultaneous
ambiguity case is now covered. Review must disposition the observed
established-bind constraint and half-open-to-closing transition without
relabelling them as retained wrong-owner replacement passes. Do not repeat
the same experiment expecting those kernel behaviors to change.

The old unconditional-rule package upgrade with existing state and exact
signed/notarized final-installer acceptance remain. They require a separate
approved disposable installation or maintenance scope, not a downgrade of
the Mini's current database. Follow-up source review/merge/CI, release and
website publication also remain separate. No commit, push, merge, installer,
tag, release or deployment was performed in this run. Keep the Mini app closed.
