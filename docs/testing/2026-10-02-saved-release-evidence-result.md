# Completed release evidence review

Date: October 2, 2026. Result: **both attended exports reviewed; the omitted
counter-format and child-event gaps are resolved**. The MacBook's previously
missing .203 alias is present again. Upgrade with existing connection state
and the documented kernel-limited cases remain unverified, not automatic passes.

No installer, product source, service, database or firewall was changed. No
additional LAN probes were run. The only live product observation was a
read-only interface inventory and loopback sensor-health request on the MacBook.

## Evidence identity

The [pinned preparation](2026-10-02-saved-release-evidence-preparation.md)
documents the script hashes, tests and exact completed archives in scope.
Matt ran both attended exports successfully. Each result was a root-owned,
mode 0644, single-link regular file. Remote and downloaded hashes matched.

| Host | Sanitized result | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| MacBook | `/private/var/tmp/squirrelops-release-review.gyfq5t1q/diagnostic.json` | 11,293 | `aafa42e6ec974a297cbebefea54e9115d3e133cf5f20e45ffceecaf1c5bb02f5` |
| Mini | `/private/var/tmp/squirrelops-release-review.yn0dt5jt/diagnostic.json` | 120,695 | `8c1b3ae61468920e7a85ba5d68521389dfc926e1f56134bad73bda952f64ce99` |

Local copies:

- `build/test-artifacts/macbook-upgrade-20261002/saved-evidence-review.json`.
- `build/test-artifacts/a5-edges-20261002-ouytf6ce/saved-evidence-review.json`.

## MacBook upgrade correlation

The before and after snapshots retain all 22 original decoy identity, type,
address, port, status and retirement records. IDs 15 through 18 were already
retired/stopped at .212 and stayed that way. Their replacement IDs 19 through
22 remain active at .212. IDs 4 and 5 at .203 remain active in both snapshots.

The five additional records, IDs 23 through 27, are the Studio deep decoy at
.214: ports 445, 22, 11434, 1234 and 8765. Their types and addresses are now
confirmed rather than inferred from the earlier aggregate count. This export
does not independently identify the five additional credential values or kinds.

The old saved alias ledger lists .203, .204, .205, .207 and .212. A fresh
`ifconfig -a` observation now finds **all five plus .214 on lo0**. Physical en0
remains .97. The sensor health response is `status: ok`, uptime 3070.86 seconds.
There is no persistent missing .203 alias in this observation. The exact cause
and duration of its earlier temporary absence are not established by these
snapshots; do not describe it as continuous alias availability or proven timing.

The before product rules contain 15 unconditional `rdr pass` translations,
zero guarded UID pass rules and zero matching tags. The after snapshot has
zero unconditional translations, **20 guarded UID pass rules and 20 matching
tag references**. This confirms the expected rule-format replacement.

Both archived PF state listings are empty, with zero unrelated or unrecognized
lines. There is therefore **no existing connection state to correlate** in
this upgrade. It cannot prove state invalidation during an old-package upgrade.
Do not rerun or downgrade the working MacBook merely to relabel this result.

## Mini counter-format review

The sixteen eight-phase snapshots contain 88 previously withheld lines; the ten
TCP-edge snapshots contain 56. All 144 have the same SHA-256:

`7a30386d3707022239512e47ad82c8880c393138227cbb7bb1317fccfdcddac2`.

The exact trimmed line is:

```text
[ Owner : nil          Priority : 0     ]
```

This is not an assumption based on similar output. The static formatting string
was read from the Mini's `/sbin/pfctl`, and this local command reproduced the
exported digest exactly:

```sh
printf '%s' '[ Owner : nil          Priority : 0     ]' | shasum -a 256
```

Every snapshot has exactly one such omitted line per recognized rule. No other
unknown counter line or supplemental numeric record is present. The original
export and its strict `comparable=false` flags remain unchanged; this is a
separate completed metadata review, not a parser modification or a gate waiver.

An independent local `jq -e` comparison passed for all thirteen before/after
phase pairs. It required matching phase names, unique rule indices, matching
complete rule hashes, recognized rule types, present numeric counter blocks,
nondecreasing cumulative evaluations/packets/bytes, and only the exact metadata
digest above among omitted lines. Its packet deltas match both existing tables
in the [eight-phase counter review](2026-10-02-mini-a5-counter-review.md) and
[TCP-edge report](2026-10-02-mini-a5-edge-result.md).

The denial observations therefore retain positive PF block-counter evidence
without the unknown-format qualification. Counters remain rule-level rather
than tuple-level. Other installed filters and uncorrelated traffic cannot be
excluded merely by recognizing this metadata, so PF-exclusive attribution is
not claimed for every timeout or second-ingress observation.

## Mini child-event review

The eight original child streams have no unknown lines. All fourteen TCP-edge
streams have stopped markers, and all sixteen previously omitted events are
now identified by exact bounded schemas:

| Event | Count | Observation |
| --- | ---: | --- |
| `ready` | 12 | Expected loopback, exact-address or wildcard listener readiness under UID 309 or 501. |
| `bind_failed` | 2 | UID 501, Darwin errno 48, matching the unsuccessful established-socket rebinds. |
| `listener_closed` | 2 | UID 309, one accepted client retained per original listener. |

There are no remaining unrecognized child-event lines in either run. Neither
run records a UID-501 LAN accept. The eight-phase run has six UID-309 LAN
accepts; the edge run has two. Loopback handoff events remain separate from LAN
results. This closes the raw-event omission qualification but does not turn a
kernel-refused bind into a successful wrong-user replacement test.

## Remaining release decisions

1. Review the kernel-constrained established and half-open cases as documented.
   Darwin prevented the established rebind; stopping half-open listeners changed
   their states before replacement. Do not claim those unachieved conditions
   passed, or repeat an identical experiment without a different justified design.
2. An actual old-package upgrade with existing connection state remains untested.
   The completed MacBook run covers preservation, restored health, user UI
   acceptance and old-rule replacement, not that additional condition.
3. Review and merge the installer fixes, map correction and documentation, then
   verify CI for the exact final source. This evidence review creates no commit,
   push or PR and does not approve its own remaining safety qualifications.
4. Accept the exact Developer ID signed, notarized final installer before the
   separate public release and website/update-channel publication steps.

No further root export is needed to resolve the counter-format or event-schema
questions covered here. The MacBook can remain running; this review does not
authorize restarting or reinstalling the stopped Mini.
