# Approved remaining TCP-edge experiment

Approved October 2, 2026. This is one additional disposable Mini run, not a
repeat of the completed eight-phase fixture, an installed package upgrade or
release approval. Production helper sources remain unchanged.

## Mini scope and phases

Reuse the original runner's root preflight, retained-file backup/parity,
native listener checks, .239/.240 conflict checks, unique PF anchor/reference,
scoped packet capture and fail-closed cleanup. Sensor/helper remain disabled.
No installed package, data, Little Snitch, Studio or .241 changes.

1. `edge_healthy`: two actual UID-309 TCP sessions through .239:22/.240:445.
   Require both established PF states before continuing.
2. Close only the listening sockets, retaining accepted connections. Attempt
   exact UID-501 binds to the same private ports, recording success or Darwin
   errno 48. Invoke the production listener guard, inject quarantine-load and
   first-IP state-kill failures, and probe held sessions plus fresh connections
   in `established_replacement`. A denied bind is a kernel constraint, not a
   successfully replaced established connection. Finish the TCP close before
   stopping disposable processes and recovering quarantine.
3. Under quarantine, attempt two exact plus two wildcard UID-309 listeners with
   port reuse. Record the complete selected listener inventory. If all coexist,
   require the production guard to reject them. Do not publish these ambiguous
   listeners. A kernel bind refusal leaves simultaneous ambiguity unproven.
4. Start fresh exact UID-309 listeners and publish. `half_open_start` sends
   exactly two SYNs per approved tuple and requires SYN-ACK responses without
   completing the handshake. Require real half-open PF states on both VIPs.
5. Stop the disposable sensor listeners, start UID-501 exact replacements,
   reject their ownership and inject load/first-IP cleanup failure. Record
   whether .239's half-open state actually survives. `half_open_wrong_uid`
   retransmits the same tuple/sequence. Do not call half-open replacement
   proven if the kernel closed that state during listener shutdown. Any
   SYN-ACK is recorded as unexpected, not silently counted as denial.
6. Successful quarantine must restore safety/debt state. Run the final bounded
   retransmission phase `half_open_quarantine`, require no remaining scoped
   PF states, then perform the original narrow Mini cleanup and parity checks.

Before initial readiness: attended preflight. Initial readiness window: eight
minutes. Later phase windows: 90 seconds; whole Mini session: 20 minutes.
Return stops early. Leave new Little Snitch prompts unanswered and report them.

## Approved laptop filter change and inverse

Only these IPv4 reset packets may be suppressed:

- 192.168.1.7:42839 to 192.168.1.239:22
- 192.168.1.7:42840 to 192.168.1.240:445

The client reserves both source ports and verifies its wlp0s20f3/.7 routes.
The independent watchdog saves the current nftables ruleset privately, prints
no existing rules, and checks syntax before mutation. It atomically adds one
unique `ip squirrelops_a5_<nonce>` table containing an OUTPUT hook, one timed
set and exactly two drop rules. Each rule requires the literal approved source
and destination address/port, the RST flag, and membership in that timed set.
It does not grant access, change existing policy or flush any rule or state.

Timed-set entries expire in the kernel after **80 seconds**, inside the approved
90-second limit even if the parent disappears. A detached watchdog starts
cleanup by 65 seconds or immediately on parent EOF; the client refuses probes
after 55 seconds. Temporary table objects should also be removed normally.

Inverse: delete only that unique test table, after checking its original handle
and structural identity. The checker permits expiration of the timed elements
and changing runtime counters, not a change to rules or chain configuration.
The resulting complete filter definition must match the saved baseline, ignoring
only runtime counters, expiration countdowns and nonsemantic handles.

Add/delete attempts are durably marked first and never blindly repeated.
Uncertain ownership is retained for review instead of deleting another actor's
rules. Kernel expiration still bounds the original rule matches; an unverified
table cleanup is a failure, not an accepted baseline. No broad ruleset restore
is available. The independent watchdog is never force-killed by the client.

## Build, stage and execute

`bash docs/testing/fixtures/pf-acceptance/build-edges.sh` builds the unchanged
helper into the standalone probe, copies the new fixture modules and generates
checksum-pinned Mini and laptop wrappers. Only `start-mini-a5-edges.sh` starts
this experiment; do not use the older eight-phase wrapper.

Stage the complete bundle in a fresh Mini directory; stage only `client.py`,
`edge_client.py`, `edge_guard.py` and `run-laptop-a5-edges.sh` in a fresh root-owned
laptop directory. Verify both sets of hashes and no-argument plan output.
The Mini user runs its wrapper with sudo in an attended Terminal. On
`READY: edge_healthy`, start the laptop wrapper with `--run` over persistent
SSH. Send exactly the five `edge_client.py` phase names in order, save each
result, and acknowledge only that exact current nonce/phase on the Mini.
The filter starts only at `half_open_start`, not while waiting for the user.

On a failed control or unexpected SYN-ACK, retain the result, end the client
so the watchdog cleans up, and let the Mini's attended stop/deadline restore
its own scope. Do not repeat probes or broaden allowances. Record the exact
artifacts, packet/state results, bind constraints and both cleanup receipts.
