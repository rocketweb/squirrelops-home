# Mini A5 partial live results and fixture correction

Date: October 2, 2026. Status: **partial observations, A5 still release-blocking**.
Later update: the revised fixture [completed all eight planned phases](2026-10-02-mini-a5-eight-phase-result.md)
and cleanup. This report preserves the preceding failed runs and fix preparation.

No product source, installed service, package, database or Little Snitch rule
was changed by this follow-up. The isolated worktree is `2.1-release-gates`,
based on source commit `00239f5d07673dab5ed5dc402ec3c0fa134ee9a8`.

## Completed runs

| Run | Durable Mini evidence | Result |
| --- | --- | --- |
| First | `/Library/SquirrelOps/acceptance-backups/mini-a5-20261002.E0xeDbUY` | Four phase probes recorded; user stopped the run; cleanup complete |
| Second | `/Library/SquirrelOps/acceptance-backups/mini-a5-20261002.cJ0axKPR` | Four phases completed; UID-501 replacement child failed to bind; cleanup complete |

The first run's final .240 fresh connection timed out around the attended
stop. That observation is inconclusive, not a confirmed product failure.
The second run provides the uninterrupted four-phase results below.

The completed-run read-only export is
`/private/var/tmp/squirrelops-mini-a5-inspection.6e1da2ky/diagnostic.json`
on the Mini. Its SHA-256 is
`27b6e06e65d411fe1a6b7698ce660a07d7fb4b4b03994059f98fa8c7cc27a16b`.
The local copy and client, helper and packet receipts are in
`build/test-artifacts/a5-20261002-second-run/`. Original root-private packet
captures, full PF inventories and child diagnostics remain unchanged.

## Second-run observations

| Phase or check | Observed result |
| --- | --- |
| Healthy forwarding | Both public endpoints returned `A5 uid=309`; two sessions held open |
| Direct backend probes | Both private ports timed out; arriving SYNs recorded, no replies observed |
| Second ingress | Four SYNs arrived on en1 for the two public endpoints; no matching replies recorded on either interface |
| Failed quarantine load and first-IP cleanup | Helper reported failure and denied alias authorization for both IPs; .239 retained an established PF state; .240 cleanup was attempted successfully |
| Traffic with old live rules retained | Held sessions returned UID-309 payloads; fresh public connections also worked; direct backend probes still timed out |
| Successful quarantine | Held and fresh client operations timed out; before/after PF inventories contained no states; helper reported success and cleared pending cleanup |
| Healthy publication restored | Both fresh public connections returned UID-309 payloads; held sessions also responded again |
| Different-user listener | Child UID 501 returned `OSError`, errno 48, `Address already in use`; no listener-check or wrong-UID client phase followed |
| Cleanup | Both runs reported and exported verified scoped cleanup: children stopped, aliases withdrawn, this run's reference released; retained files and unrelated policy passed the runner's parity checks |

Second-run client phases began at 05:55:51, 05:55:58, 05:56:03 and 05:56:17 UTC
(01:55:51 through 01:56:17 America/Indianapolis). Capture timestamps are local;
client and PF snapshot timestamps are UTC. Little Snitch remained installed.
These packet-correlated denial observations are not a claim that every possible
filter interaction has been excluded.

## Confirmed fixture issues

1. The original state-summary parser accepted lowercase `all`, but this Mini
   emitted uppercase `ALL`. Its state-name expression also omitted digits in
   names such as `FIN_WAIT_2`. The retained private snapshots contain real
   established and closing states; empty original summaries were not evidence
   that those states were absent. The independent export recovered the records.
2. The fixture stopped the server and immediately attempted a different-UID
   bind while the laptop still held its TCP sessions. The child diagnostic
   confirms the bind conflict. Apple's published
   [socket-binding implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/in_pcb.c)
   includes a cross-UID conflict check against existing local socket records.
   This supports the lifecycle diagnosis but does not identify the exact
   kernel branch or TCP socket state on build 26A434. The failed test is not
   evidence that the product accepted a wrong-UID listener.

## Corrections and verification

Only the disposable fixture changed:

- Export observed uppercase prefixes and numeric closing-state names, retaining
  the address scope and rejecting invalid ports and unknown state names.
- Complete client-initiated FIN/EOF before the server is stopped for handoff.
  Retain the source tuple for the reconnect attempt, not an open client socket.
- Before any PF or alias write, verify the same close/rebind sequence on one
  ephemeral loopback port with actual UID-309 and UID-501 child processes.
- Refuse to mark the replacement phase ready unless a closing PF state on .239
  is actually present after the injected first-IP cleanup failure.

The corrected replacement case tests **closing-state reuse**, not an
established session reaching a replacement process. Established-state replacement
and the other open cases are not waived or relabeled as passing.

The state-format, invalid-state-output and client-handoff regressions were
observed failing before correction. The local suite passed 38 checks in 0.590
seconds with Apple Python as parent and Python 3.12 disposable loopback children:

```sh
SQUIRRELOPS_DIAGNOSTIC_CHILD_PYTHON=/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/sensor/.venv/bin/python \
  /usr/bin/python3 -m unittest discover \
  -s docs/testing/fixtures/pf-acceptance -p 'test_*.py' -v
```

The cross-UID loopback preflight and revised LAN phases have not run on the Mini
yet. Local same-user socket tests and mocked privilege arguments are not their
acceptance. Do not rerun the old pinned bundle.

## Revised staging, not started

The standalone ARM64 probe rebuilt successfully in 24.32 seconds. Existing CLT
linker-path warnings remain. Its production helper-source manifest is byte-for-byte
identical to the first bundle. Ruff, Bash syntax and whitespace checks passed.
Remote checksums and both no-side-effect plan commands passed after copying:

- Local bundle: `/private/tmp/squirrelops-a5-build.keG0PMTP/stage`.
- Mini: `/Users/matt/squirrelops-mini-a5-v2.AgenMyrS`.
- Laptop: `/root/squirrelops-a5-client-v2.dMvYvqvq/client.py`.
- Bundle manifest SHA-256:
  `c2e405364c5fd80e1949dc13cac0da0c37b13fd260fec399f8dc3d4c4d06a12d`.
- Mini launcher SHA-256:
  `2ba97999208b6a3c4901b8efcfdc93dbd04ffcf666040bfb189bc54e05d285c7`.
- Laptop client SHA-256:
  `00393e309433797434bf3eaae92dc70bd240d2ffd46f380ed4b3bc40c40d2417`.

The user starts the attended Mini run with:

```sh
sudo /bin/bash /Users/matt/squirrelops-mini-a5-v2.AgenMyrS/start-mini-a5.sh
```

The same temporary VIPs, public/backend ports, UIDs, anchor boundary and scoped
rollback apply. No installed service or data changes are authorized by this
command. Leave Terminal open, report `READY: healthy` promptly, and leave any
new Little Snitch prompts unanswered. Do not reuse the old laptop client or
the completed run's fixed-nonce coordinator.

Still open: different-UID and missing/wildcard phases; established-state and
half-open state replacement; simultaneous ambiguous listeners; actual old-rule
package upgrade with existing states; exact signed/notarized installer
acceptance. No commit, push, merge, tag, publication or deployment was performed.
