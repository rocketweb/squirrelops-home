# Remaining A5 TCP cases: pinned run preparation

Date: October 2, 2026. Status: **live run completed; both machines cleaned up**.
The [edge result](2026-10-02-mini-a5-edge-result.md) records the five phases,
verified ambiguity rejection and kernel-limited retained-state cases. The
remaining preparation details below preserve what was verified before use.
Matt approved the two temporary laptop reset-suppression rules after reviewing
the [counter findings](2026-10-02-mini-a5-counter-review.md).

## Approved scope

The existing disposable Mini scope remains .239/.240, public 22/445, private
61322/61445, service UID 309 and test UID 501. No installed package, service,
database, Little Snitch, Studio or .241 changes. Existing jobs remain disabled;
fresh root preflight and conflict checks remain mandatory.

The added laptop authority covers only RST packets from:

- `192.168.1.7:42839` to `192.168.1.239:22`.
- `192.168.1.7:42840` to `192.168.1.240:445`.

The [fixture contract](fixtures/pf-acceptance/EDGES.md) specifies the exact
rollback and five client phases. The implementation uses two nftables drop
rules in a unique owned table. Both require literal source/destination tuples
and timed-set membership. Set entries expire after 80 seconds; a detached
watchdog starts cleanup by 65 seconds or on parent EOF; probes stop after 55
seconds. This remains inside the approved maximum 90-second effect window.
The baseline definition is retained privately and checked after removal.
Uncertain or changed ownership is never permission for a broad restore or
blind deletion retry. No filter had been installed at the preparation stage;
the completed run's temporary rules have now been removed and parity verified.

## What this run measures

1. Healthy, real accepted TCP sockets, followed by closing only their listening
   sockets. Try cross-UID rebinding while the accepted sockets remain alive;
   record either real replacement or a kernel bind constraint. Exercise held
   payloads and fresh connections during injected quarantine/state-kill failure.
2. Real simultaneous exact and wildcard listeners, if Darwin permits them,
   and rejection by the unchanged production listener guard. Ambiguous
   listeners are never published.
3. Real half-open state, bounded same-sequence SYN retransmission, wrong-UID
   replacement, injected cleanup failure, and successful recovery. Record if
   the kernel destroys the half-open state during listener shutdown instead
   of treating that as a tested retained-state replacement.

The existing eight-phase run is not repeated. No product or attacker-visible
decoy behavior has changed. The Swift probe still compiles unchanged production
helper sources; only test listeners, clients and coordination are new.

## Verification

| Check | Observed result |
| --- | --- |
| Full offline fixture suite | 65 tests passed, 0.801 seconds |
| Real local child socket | Listening socket closed; accepted socket still exchanged payload and completed FIN/EOF |
| Real detached watchdog | Parent pipe EOF triggered its cleanup callback |
| Failed-control evidence regression | Observed failing first, then passed after retaining partial observations |
| Rule contracts | Exact two tuples, 80-second timeout, no broad flush; changed ownership/deadline/EOF paths checked |
| Laptop nftables syntax | Exact generated transaction passed `nft --check -f -`; no rules installed |
| Standalone ARM64 helper build | Passed, 27.17 seconds; existing CLT linker search-path warnings only |
| Source identity | Every canonical helper/enrollment source matched `source-sha256.txt` |
| Both remote staging bundles | Hashes, shell syntax and no-action plans verified |
| Ruff and whitespace | Passed |

The test suite's simulated failure cases intentionally print cleanup warnings;
these are mock tests, not a live failed cleanup. This pass ran no live PF
mutation, network probe or filter-lifecycle test. The 80-second timeout syntax
and supervisor behavior are verified; the real kernel/readback/cleanup result
must still be collected during the attended experiment.

## Artifacts

- Local: `/private/tmp/squirrelops-a5-build.V3gy8MyX/stage`.
- Mini: `/Users/matt/squirrelops-mini-a5-edges.OH0NAMOE`.
- Laptop: `/root/squirrelops-a5-edges.uN2BSX5p`.

| Artifact | SHA-256 |
| --- | --- |
| Mini manifest | `e295ed76ff11655e5d7cd159a5598c5d073ff97c3a2efb7280bf2e033423b214` |
| Mini launcher | `946493ae3bf8b25962c851d06a3a13f198a09a66b4665b2acbfe1c75b2e7b37f` |
| Laptop launcher | `a48df7d87c1ef816d7e6117519dc14a9842b9e81b9b1fa838ca39080fedee878` |
| Laptop edge client | `a61f8fe796119724563236f7f957a98cf80cab4a393e21409b39f893c7a4e38d` |
| Laptop watchdog | `1afff95d9c6233fc2601a85df14d491442da28de7b89006bc2b5fbac8f719d0e` |
| Reused basic client | `00393e309433797434bf3eaae92dc70bd240d2ffd46f380ed4b3bc40c40d2417` |

The earlier build at `squirrelops-a5-build.KCoqC4Ro` is superseded. Use only
the final V3gy8MyX bundle and the two verified remote destinations above.

## Attended start

On the **Mini**, with SquirrelOps still closed:

```sh
sudo /bin/bash /Users/matt/squirrelops-mini-a5-edges.OH0NAMOE/start-mini-a5-edges.sh
```

Leave Terminal open. Tell the coordinator when `READY: edge_healthy` appears,
including the printed sanitized status path. Initial readiness allows eight
minutes; later phases allow 90 seconds and the whole session has a 20-minute
deadline. Return stops early. Leave new Little Snitch prompts unanswered.

The local operator then runs
`docs/testing/fixtures/pf-acceptance/edge_coordinate.py --run --status <exact printed status.json> --output <fresh local artifact directory>`.
The output directory must not exist, preventing accidental replay into the
same evidence folder. The coordinator binds the exact nonce, fixed targets,
approved phase sequence and staged laptop launcher. It saves each response
before acknowledgement and requests a scoped stop on a failed control or
unexpected SYN-ACK. The independent laptop watchdog retains its cleanup duty
even if the coordinator/SSH connection disappears.

## Remaining release work

The live edge run is complete, with qualifications recorded in its result. Actual
old-rule package upgrade with retained states, exact signed/notarized installer
acceptance, follow-up source review/merge/CI and final release/website checks
remain. No old-package downgrade or installed-data mutation is authorized by
this experiment. No commit, push, merge, installer, tag, release or deployment
was performed during this preparation.
