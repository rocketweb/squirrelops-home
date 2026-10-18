# Guest relay listener backlog (issue 66)

Date: 2026-10-18. Machine: Apple Silicon Mac Studio, macOS 27, Virtualization.framework.
Runtime: debug `SquirrelOpsDeceptionGuest` from the `feature/guest-auth-events` build
(PR 65), ad-hoc signed with the Virtualization entitlement. The runtime was identical
across both measurements; only the guest bundle changed.

## Question

Issue 66 recorded two `guest_connect_failed` checkpoints out of fifteen concurrent SMB
connects during one live run, with the slots they freed admitting a connection the test
expected to be capacity-rejected. The error code was not captured at the time. The first
hypothesis was the guest-side listen backlog: `socat VSOCK-LISTEN` defaults to 5, and
Linux vsock resets a connect that arrives while a listener's accept queue is full.

## Method

A reproduction script started the real guest through `GuestRuntimeController`, opened
15 SMB connections concurrently with `asyncio.gather`, waited two seconds, counted the
`guest_connected` and `guest_connect_failed` relay checkpoints and their `errno` field,
closed the peers, waited three seconds, and repeated. The runtime bounds structured
checkpoints at 512 per VM, so the script restarted the VM every four bursts to keep the
codes observable. Telemetry (`on_connection`) was counted alongside as an unbounded
cross-check.

## Results

Unmodified guest (`main` at PR 65, listeners `reuseaddr,fork,max-children=16`):

| Bursts | Connects | Connected | Failed | Codes |
|---|---|---|---|---|
| 12 | 180 | 147 | 33 (18%) | 54 x 33 |

Every burst had between 1 and 5 failures. Every failure carried code 54, `ECONNRESET`,
the reset vsock sends for a full accept queue. No burst produced a capacity rejection.

Rebuilt guest with `backlog=16` on both relay listeners, same runtime, same script:

| Bursts | Connects | Connected | Failed | Codes |
|---|---|---|---|---|
| 12 | 180 | 180 | 0 | none |

## Live acceptance

`tests/integration/test_deep_deception_live_guest.py` now opens its 15 SMB peers
concurrently and asserts that no `*.guest_connect_failed` telemetry appears during the
capacity scenario. Against the unmodified bundle that assertion failed on the first run
(one `smb.guest_connect_failed`). Against the rebuilt bundle the full test passed in
39.6 s, including SSH and SMB login attribution, the capacity rejection of the 17th
connection, the 30 s half-close resume, and host containment.

## What changed

`guest/studio-mini/rootfs/sbin/init`: `backlog=16` on the `10022` and `10445`
listeners, matching the host's 16-relay admission ceiling and `MaxStartups 16`.
Nothing attacker-visible changes: the vsock side is host-internal, and the TCP
services the attacker reaches are unchanged. Predictability only.
