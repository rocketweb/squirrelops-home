# Mini A5: eight-phase run completed

Date: October 2, 2026. Status: **all eight planned phases executed; scoped
cleanup verified; full A5 release gate remains open**.

The revised fixture completed without the previous bind failure. These are
observations from the approved disposable Mini experiment, not acceptance of
an installed release package or an isolated PF-only environment.

## Exact run

- Mini: ARM64 macOS 27.0.1 build 26A434, Ethernet en0 and Wi-Fi en1.
- Temporary targets: 192.168.1.239:22 and 192.168.1.240:445, with private
  backends 61322 and 61445. Laptop source: 192.168.1.7 on wlp0s20f3.
- Run nonce: `c21040d915eb`.
- Durable evidence:
  `/Library/SquirrelOps/acceptance-backups/mini-a5-20261002.DcmC5nO5`.
- Sanitized Mini evidence:
  `/private/var/tmp/squirrelops-mini-a5-results.tj3gpkxe`.
- Local client results, snapshots, helper receipts and packet correlation:
  `build/test-artifacts/a5-20261002-third-run/`.
- Pinned bundle manifest:
  `c2e405364c5fd80e1949dc13cac0da0c37b13fd260fec399f8dc3d4c4d06a12d`.
- Client SHA-256:
  `00393e309433797434bf3eaae92dc70bd240d2ffd46f380ed4b3bc40c40d2417`.

The source and bundle identity remain those recorded in the
[fixture-correction report](2026-10-02-mini-a5-partial-results.md). The standalone
binary uses unchanged production helper sources. No product code was edited
for this run. Each client phase ran once; its result was saved before its
nonce-bound acknowledgement. The coordinator exited successfully.

Client phases ran from 06:32:46 through 06:33:58 UTC, or 02:32:46 through
02:33:58 America/Indianapolis. The capture timestamps use local time.
Matt confirmed: **no new Little Snitch prompt appeared**.

## Results

| Phase | Observation |
| --- | --- |
| Healthy | Both public ports returned `A5 uid=309`. Both private-port probes timed out. Two sessions stayed open. Four second-ingress SYNs were sent. |
| Retained states | Injected anchor-load failure plus first-IP state-kill failure reported failure and denied alias authorization for both IPs. The second-IP kill still ran successfully. The first IP retained an established PF state. Healthy existing and fresh flows continued under the old live rules. |
| Quarantined | Successful block-only recovery cleared the PF states and cleanup debt. Held-session operations and new public/private connections timed out. |
| Healthy again | Both new public connections returned the UID-309 banner. Held sessions returned payload again after republication. Both new sessions completed client-initiated FIN/EOF before replacement. |
| Wrong UID with retained closing state | UID-501 exact listeners started successfully and the ownership guard rejected them. Failed quarantine and failed first-IP state cleanup preserved closing states on .239. Fresh public/private probes and both same-tuple reconnects timed out with no reply packets captured. |
| Missing listeners | Ownership guard rejected missing listeners. Quarantine loading was deliberately failed; public/private probes timed out. |
| Wrong-UID wildcard | Ownership guard rejected UID-501 wildcard listeners. Quarantine loading was deliberately failed; public/private probes timed out. This was not simultaneous exact-plus-wildcard binding. |
| Recovered | Successful block-only recovery cleared pending cleanup, restored cached protection for both IPs, and left no PF states. Public/private probes timed out, as expected for block-only quarantine. |

The loopback UID handoff preflight also passed: reaching the healthy phase is
conditional on real UID-309 and UID-501 children using the same ephemeral
loopback backend port successfully before PF or alias writes.

### Packet and state correlation

The en0 export contains 151 packets; en1 contains four. All four en1 packets
are the expected SYNs to the public test ports. No matching reply was captured
on either interface for those source tuples.

The 34 fresh/reconnect connection probes comprise six successful UID-309
payloads and 28 timeouts. All 28 timeout tuples have arriving SYNs and no
matching outgoing reply in the phase-bounded captures. All 16 direct backend
probes are in that timeout set. There are also six held-session operations
(four payload responses, two quarantine timeouts) and two completed client
close handshakes.

At 06:33:17 UTC, immediately before the wrong-UID client phase, .239 had:

- Source port 35575: `TIME_WAIT:TIME_WAIT`.
- Source port 45687: `FIN_WAIT_2:FIN_WAIT_2`.

The reconnect actually reused source port 45687 to .239:22, and two SYNs
arrived at the Mini with no reply captured. The .240 reconnect likewise reused
46435 and delivered two SYNs. These attempts were not rejected locally by the
laptop before transmission. After the phase, only the older .239 TIME_WAIT
record remained. Missing, wildcard and final recovery snapshots were empty.

This proves the closing-state scenario was exercised. It does not prove
established-state or deliberately retained half-open-state replacement.
Little Snitch and other installed filters remained enabled and unchanged.
No new prompt does not prove that no pre-existing filter contributed to a
denial. The subsequent [counter and listener review](2026-10-02-mini-a5-counter-review.md)
now confirms positive PF block-counter changes and zero wrong-UID LAN accepts.
Additional unrecognized output lines and per-rule rather than per-tuple counters
keep attribution qualified; the observations are not labeled PF-exclusive proof.

## Cleanup

The final receipt reports `phase=cleaned`, `cleanup_complete=true` and
`ready=false`. The runner reached that state only after stopping its children,
quarantining, withdrawing its two aliases, checking retained-file and unrelated
policy/native-listener parity, emptying its own anchor, releasing its one PF
reference, and checking the original disabled PF baseline.

A separate read-only SSH check found the sensor/helper still disabled, no
product helper, guest, app or disposable Swift probe process, and only the
original .115 and .254 IPv4 addresses on en0/en1. Root-only PF checks here are
attested by the completed pinned runner, not a separate root SSH query.

Installed services, configuration, database, Little Snitch rules, Studio and
.241 were not changed. The Mini remains stopped pending the next reviewed test.

Evidence hashes:

| Artifact | SHA-256 |
| --- | --- |
| Final status | `8560766edb41c2a8a1936dd2ab0537fafd3531421fce32c1e68c1355cef03566` |
| en0 metadata | `64636cdf68ec5d15e079b1526b89ca13a36fdc71caa7cc75fdcaf03fb5ea297c` |
| en1 metadata | `a17ec129bf50064596ea0190ba4f2e46348c6721d245ab39427bc1c112ca46fc` |
| Phase-bounded packet correlation | `3a45d57d02711f10f14a533e4729f718e520a2bb42b62a99302a6d9cd9e650d1` |

## Remaining release boundary

The [canonical A5 matrix](2026-09-26-pf-safety-development.md#live-acceptance-gate-not-executed)
still requires established-state replacement, deliberately retained half-open
state/retransmission, simultaneous ambiguous listeners, and actual migration
from the old unconditional-rule package with existing states. Filter attribution
also remains qualified as described above. The signed/notarized final installer
has its own acceptance gate. The old-package migration is not authorized by
this disposable run and must not downgrade or overwrite the current database.

The source/docs and website follow-ups still need their separately authorized
review, merge and publication steps. This turn did not commit, push, merge,
install, tag, release or deploy anything.
