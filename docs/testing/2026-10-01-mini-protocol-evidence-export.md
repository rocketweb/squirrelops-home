# Completed protocol run: read-only evidence export

The operator executed the export successfully at 06:03:19 EDT on October 1.
The report was retrieved and hash-verified. See the
[packet/PF evidence review](2026-10-01-mini-packet-pf-review.md) for findings and
remaining limits. The preparation and verification record below describes the
completed export, not authorization for another live test.

## Scope and safety

Target: Mini `100.64.0.27`, boot `1790777754`. Resolve the completed run
through the exact root-private claim
`/Library/SquirrelOps/acceptance-backups/protocol-1790777754-3d18ebac2fae-attempt.json`.
Require the expected package checksum, a direct child named
`mini-protocol-20261001.*` under that root-only backup directory, and identical
checksum-pinned public/private successful cleanup receipts. The receipt hash is
`796977f62c6f4e67bf1350c7f2094ebce8325a5f01b75583ea6f9343f523d7c0`.

The export uses the existing pinned Python runtime. It verifies boot and absent
sensor/helper jobs, then reads only retained files:

- Header-only packet captures, restricted to laptop `.7`, VIP `.240`, the five
  advertised services and their five recorded backends, 05:28:50 through
  05:29:45 local time on October 1.
- Prior command records whose command is exactly `pfctl -s states`. Publish
  only scoped numeric ports, allowlisted TCP state names, arrow orientation,
  record names and withholding counts. No raw state text or PF reference tokens.

Packet byte totals include retransmissions. PF records have ordering but no
timestamps, so all state snapshots of the one completed run are included.
Unrecognized formats and unrelated traffic are withheld, not treated as empty
network state. The exporter does not query Little Snitch, issue live PF calls,
read the database or sensor log, start services, or send network probes.

The only writes are a new root-private copy of the checksum-verified exporter
and a new sanitized JSON report, owned by the operator account in a private directory. Original
evidence and permissions are unchanged. Both apps remain closed. There is no
automatic retry, service restart, filter change or package installation.

## Verification

The new exporter tests first failed because the module was absent, then passed
after implementation. An overbroad wrapper assertion initially matched the
human-facing word `sudo`; it was narrowed to actual command lines and passed.
This is new diagnostic tooling, not a claimed product bug fix.

```sh
/Library/SquirrelOps/sensor/python/bin/python3.12 -I -B -m unittest discover -s docs/testing/fixtures -p test_mini_protocol_evidence_export.py -q
sensor/.venv/bin/python -B -m unittest discover -s docs/testing/fixtures -p 'test_mini*.py' -q
```

Results: **11 new tests passed** with the pinned installed Python; **335 total,
332 passed, 3 skipped** in the full synthetic harness suite (4.447 seconds).
The three existing opt-in root/artifact checks were skipped. Local loopback
permission was used; mocked service/cleanup output is not live host activity.
Shell syntax and `git diff --check` passed. Remote copies match local hashes.

| Input | SHA-256 |
| --- | --- |
| `export-mini-protocol-evidence.sh` | `fed800b8b50c2d172676e392bf2702de6071d52226f27b533478367ced73acd8` |
| `mini_protocol_evidence_export.py` | `77188076e308febc2b46d501b7b7585d80bdfea06276f42cfa29597f37b2b8fd` |
| Existing safe-read/parser dependency | `ffcabccb69fd9700ebf62ba91ebb1cf685abae91e9838ac6a2761ff2a5e13cfc` |

## Attended command

On the Mini:

```sh
sudo /bin/bash /Users/operator/squirrelops-protocol-evidence.a1qAUUsj/export-mini-protocol-evidence.sh
```

Send the `READ-ONLY EXPORT COMPLETE` path. Administrator access is required
because the retained source evidence is root-only. The agent has not executed
this command, bypassed those permissions, changed product source, committed,
pushed, or released anything as part of this export preparation.
