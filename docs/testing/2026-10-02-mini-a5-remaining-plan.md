# Mini A5 remaining evidence and test plan

Date: October 2, 2026. Status: counter export
[reviewed](2026-10-02-mini-a5-counter-review.md) and the subsequent approved
[TCP-edge run completed](2026-10-02-mini-a5-edge-result.md), with both machines
cleaned up. Simultaneous ambiguity is covered. Established cross-user binding
was refused and half-open states closed before replacement, so those results
need a qualified review disposition rather than another identical run.
This is not release approval or a waiver of the
[canonical matrix](2026-09-26-pf-safety-development.md#live-acceptance-gate-not-executed).

The [completed eight-phase run](2026-10-02-mini-a5-eight-phase-result.md) is the
baseline. Do not repeat it merely to collect evidence already retained.

## First: attribute the completed observations

The completed run retained before/after rule counters and disposable listener
events, in addition to its exported packet/state metadata. A read-only exporter
now selects exactly that run, nonce `c21040d915eb`, and requires its matching
cleaned receipt before reading the evidence. It exports numeric counters,
allowlisted rule identities, rule hashes, scoped state records and synthetic
child-event counts. It does not export raw rules, packet payloads, process
inventories, credentials, PF reference tokens or arbitrary error text.

All sixteen before/after snapshots and eight child event streams are required.
Malformed or unknown lines are counted as withheld. Missing counters, changed
rules and decreasing cumulative counters are not comparable results. Loopback
handoff events are separate from LAN accepts. A stopped marker alone does not
prove the absence of omitted or malformed events; check those counts too.

This reads files only. It does not invoke live network commands, start services,
load filters, send probes, change permissions on originals or repeat tests.
The only writes are fresh root-private exporter staging and a sanitized result
directory. The SSH user cannot read the original evidence without sudo.

Historical command, now completed on the **Mini**. No repeat is needed:

```sh
sudo /bin/bash /Users/matt/squirrelops-a5-counter-export.KiGTDEeJ/inspect-mini-a5-counters.sh
```

Staged identities, verified locally and again over SSH:

| Input | SHA-256 |
| --- | --- |
| `inspect_completed.py` | `aa876cc0fb1076b3f4cecce3a144bd4eee980ffa524b6cfb11fa58447c3ef739` |
| `inspect-mini-a5-counters.sh` | `f47fabadccf05a9d6f22985a22259648c1302df2bdc9bad5ec5cd12c021b9c0d` |

Local staging is `/private/tmp/squirrelops-a5-counter-export.muEZ1cxY`.
The wrapper copies the exporter into a new root-private directory and validates
the pinned hash before execution. Remote Bash syntax and the no-action
`--successful-run` plan passed. The plan did not read private evidence.

The inspector tests increased from five to fourteen. Six new parser/selection
tests were observed failing before implementation. The complete fixture suite
passed **47 tests in 0.613 seconds**, including existing real loopback child
checks. Ruff and `git diff --check` passed. Reproduction from this worktree:

```sh
SQUIRRELOPS_DIAGNOSTIC_CHILD_PYTHON=/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/sensor/.venv/bin/python \
  /usr/bin/python3 -m unittest discover \
  -s docs/testing/fixtures/pf-acceptance -p 'test_*.py' -v
```

The completed review correlated recognized per-phase block/pass counter
changes with existing packet tuples and child accept events. PF participation
is positively observed, but unknown raw output lines remain withheld and the
exporter's automatic comparability flags remain false. The review documents
that limit; no parser check was weakened and no test was repeated.

## Approved TCP-edge scope, now completed

Matt subsequently approved the narrow laptop change below. The
[edge-run preparation](2026-10-02-mini-a5-edge-preparation.md) records the
verified bundle, 65-test result, checksum pins and historical attended command.
The table below is the pre-run plan; the linked result is authoritative for
what actually happened. Do not rerun the attended command merely to refresh it.

| Gap | Smallest useful experiment | Acceptance and limit |
| --- | --- | --- |
| Established socket and cross-UID reuse | Hold a real accepted TCP session, then attempt a different-UID bind to the same disposable endpoint while that socket remains open. Retain the bind error and socket/PF state. | If Darwin rejects the bind, report a kernel-enforced bind constraint, not a successful wrong-UID replacement. Do not loosen system socket policy to make the case possible. |
| Simultaneous exact and wildcard listeners | Try two UID-309 disposable processes with explicit port reuse, one exact and one wildcard, on the approved backend. Invoke the actual production listener guard before any publication. | Require both listener records to coexist and the guard to reject them. If the kernel prevents coexistence, record that constraint rather than calling ambiguity tested. |
| Deliberately retained half-open state | Send a bounded raw SYN sequence from the laptop, capture the SYN/SYN-ACK, retain and snapshot the incomplete handshake, retransmit the same tuple, then exercise listener/state-cleanup failure and recovery. | Require the actual half-open PF state and packet sequence. An unanswered SYN or a state already reset by the laptop is inconclusive. |

The first two proposals use disposable Mini listeners, never root-owned
listeners or installed product services. Fresh preflight, IP conflict checks,
backups and the existing narrow rollback remain mandatory. A revised harness
must be tested and checksum-pinned before the attended run.

### Additional authority approved for controlled half-open state

The laptop's normal TCP stack can reset a raw SYN-ACK because no matching
kernel connection exists. The proposed deterministic fixture suppresses only
RST packets for these two IPv4 tuples:

- `192.168.1.7:42839 -> 192.168.1.239:22`
- `192.168.1.7:42840 -> 192.168.1.240:445`

This was a **new laptop filter mutation outside the previous no-filter-change
client scope**. Matt explicitly approved these two temporary tuples and a
maximum 90-second effect window. The completed run installed and removed that
exact temporary scope. Its watchdog verified existing filter definitions
matched the saved baseline afterward; it did not restore a broad ruleset.

Read-only preparation found `iptables v1.8.10 (nf_tables)`, nftables 1.0.9,
and kernel 7.0.0-30-generic. Both routes use wlp0s20f3 with source .7. `ss`
returned no TCP entries on the two proposed source ports. These observations
must be refreshed immediately before use; they are not reservations or a
firewall baseline.

Before any approved write: save the existing filter definition privately,
reserve the test source ports, verify the Mini owns only the freshly checked
test aliases, and show the exact two-rule diff. Each rule must carry a unique
test marker and match source/destination IP, source/destination port, TCP and
RST. No allow rules, broad RST suppression, policy changes or flushes.

The proposed allowance lasts at most 90 seconds. A cleanup path independent
of the SSH connection must remove only the exact rules successfully added,
on completion, timeout, interruption or parent loss. Preserve a receipt before
each mutation; do not blindly retry ambiguous writes or deletes. Verify the
filter definition matches its original baseline afterward. If the inverse
operation or independent deadline cannot be demonstrated in tests, do not run.

## Separate package boundary

The old unconditional-rule package upgrade is not part of the disposable
experiment. Plan it on a disposable macOS installation or another explicitly
approved maintenance scope with a verified baseline and rollback. Do not
downgrade the Mini's current database or revive historical scripts that include
.241. Test the exact installed helper and retained states across the upgrade.

Exact signed/notarized installer acceptance, follow-up source review/merge/CI,
release publication and website publication remain separate states. This
continuation has not committed, pushed, merged, installed, tagged, released or
deployed anything. Product source and deception responses are unchanged.
