# Mini A5: retained counter and listener review

Date: October 2, 2026. Result: **PF blocking is positively observed in the
completed run; no wrong-UID LAN accepts were recorded. Full A5 remains open.**

This reviews evidence from the
[completed eight-phase experiment](2026-10-02-mini-a5-eight-phase-result.md).
There was no new live experiment, service change, filter change or probe.

## Evidence identity

Matt ran the checksum-pinned read-only exporter on the Mini. It selected nonce
`c21040d915eb`, verified the completed cleanup receipt, and produced:

`/private/var/tmp/squirrelops-mini-a5-inspection.7vejiucb/diagnostic.json`

The file was root-owned, mode 0644, regular, single-link, 50,161 bytes. Its
SHA-256 matched before and after copying over SSH:

`a43864b9143a4a49d640ca6ee1ecda9a308b2957d04dbabfa624cd5d16c8f85e`

The local copy is
`build/test-artifacts/a5-20261002-third-run/counter-inspection.json`.
The exporter reported `cleanup_verified=true` and `system_mutations=false`.
Those are retained-run observations, not a fresh privileged inventory of the
current machine. Original evidence and its permissions were not changed.

## Recognized rule counters

All 88 rule records across sixteen snapshots have recognized identities and
numeric counter blocks. For the table below, before/after comparisons require
the same phase, rule index and complete rule-text hash, with no decrease in
cumulative evaluations, packets or bytes. Rule identities are consistent
within each phase. Counters are not compared across ruleset replacement.

These are **packet-counter differences, not connection counts**:

| Phase | Block .239 | Block .240 | Guarded pass .239 | Guarded pass .240 |
| --- | ---: | ---: | ---: | ---: |
| Healthy | 7 | 7 | 6 | 6 |
| Retained states | 2 | 2 | 15 | 14 |
| Quarantined | 9 | 10 | Not present | Not present |
| Healthy again | 2 | 2 | 22 | 17 |
| Wrong UID, retained closing state | 6 | 6 | 0 | 0 |
| Missing listeners | 4 | 4 | 0 | 0 |
| Wrong-UID wildcard | 4 | 4 | 0 | 0 |
| Recovered, block-only | 4 | 4 | Not present | Not present |

During wrong-UID replacement, each block counter rose from 2 to 8 packets
and from 120 to 480 bytes. Each corresponding guarded-pass packet/byte counter
was unchanged. The existing packet correlation records six arriving probe
SYNs per VIP, including the same-tuple retry, and no matching outgoing reply.
Missing-listener and wrong-UID wildcard phases each show four arriving probe
SYNs per VIP, four additional block packets, unchanged guarded-pass counters,
and no matching reply. The positive healthy controls returned UID-309 payloads.

These observations support PF's active participation in the denials. They are
stronger evidence than client timeouts alone. PF counters are rule-level, not
tuple-level; other traffic to the VIPs and other installed filters cannot be
excluded solely by this export. In particular, the healthy-phase counters
cannot independently attribute each second-ingress packet to a specific rule.

### Exporter limitation retained, not silently overridden

Subsequent review: the [completed retained-evidence review](2026-10-02-saved-release-evidence-result.md)
identifies all 88 omitted lines by exact checksum as `Owner: nil / Priority: 0`
metadata. That resolves the unknown-format gap described below. Original flags
are unchanged, and rule-level/filter-attribution limits still apply.

The exporter withheld one additional unrecognized line per rule record,
88 lines in total. Their content is not present in the sanitized file and is
not assumed to be harmless metadata. Its original `phase_deltas` therefore
keep **`comparable=false` for all eight phases**. No original flag or evidence
file was changed, and the parser was not relaxed to force a pass.

The table is a qualified comparison of the recognized numeric records only.
The local derivation explicitly keeps every false comparability flag, every
withheld-line count, and `automatic_gate_pass=false`. It does not substitute
for complete raw-format review or claim PF-exclusive proof for every timeout.

Reproduce the qualified comparison locally:

```sh
jq -f build/test-artifacts/a5-20261002-third-run/review-counters.jq \
  build/test-artifacts/a5-20261002-third-run/counter-inspection.json
```

The derivation rejects changed/missing/duplicate matched rules and decreasing
cumulative counters. The saved result is
`build/test-artifacts/a5-20261002-third-run/reviewed-counter-observations.json`,
SHA-256 `154fc70eb3c963bbb270632b9b73818a6e3c18a174b3b2cc64cf24731b3473fc`.
The jq source SHA-256 is
`f301267064f5d99d3b730f8c274cfa15a92f0de1c4f2a0f7421a061704cac3a1`.

## Disposable process evidence

All eight expected child event streams are present, have a final stopped
marker, and contain zero withheld event lines. All eight child stderr files
are empty.

- Six LAN accepts were recorded for UID 309, matching the six fresh successful
  UID-309 payload probes in the client record.
- Zero LAN accepts were recorded for UID 501.
- One loopback accept for each UID belongs to the preliminary same-port
  handoff check. Neither is counted as a LAN accept.
- UID-309 children recorded six echo sends. These are server-side events, not
  six independently acknowledged client responses; the earlier client report
  separately records four received held-session responses and two timeouts.

The retained cleanup receipt and all eight stopped markers support the
previously recorded cleanup. No restart or repeated eight-phase run was needed
to obtain these findings.

## What remains

The counter review narrows the filter-attribution uncertainty but does not
close the entire [A5 matrix](2026-09-26-pf-safety-development.md#live-acceptance-gate-not-executed).
Established-socket cross-UID binding, deliberately retained half-open state,
simultaneous exact/wildcard ambiguity, and actual old-rule package upgrade
remain separate cases. Exact signed/notarized installer acceptance and
source/release publication steps are also still pending.

The [next-test plan](2026-10-02-mini-a5-remaining-plan.md) proposes a maximum
90-second laptop RST suppression for only two fixed synthetic connection
tuples. That new laptop filter scope was **not authorized or applied at the
time of this review**. Matt subsequently approved it; the
[staged edge-run record](2026-10-02-mini-a5-edge-preparation.md) tracks its
separate verification and execution status.
Existing product data, services, Little Snitch rules, Studio and .241 stay out
of scope. This review did not commit, push, merge, install or publish anything.
