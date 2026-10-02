# Mini retained-evidence review: export prepared and completed

The operator approved proceeding with read-only diagnosis after the successful
post-reboot reference cleanup. The SSH/SMB failure is still unresolved. No new
protocol probes, service actions, installer, database edits, filter changes or
release publication are authorized by this step.

## Evidence and boundary

The source run is `mini-post-reboot-240`, private backup
`/Library/SquirrelOps/acceptance-backups/mini-post-reboot-20260930._a_bdeaf`.
The successful cleanup receipt is pinned to SHA-256
`3a0a7c6a63e73b779d7e3552c9e2fdf42c67acb80676960d27813b61cc488cfc`.

Current unprivileged SSH cannot read the private backup or sensor log. The
installed Python executable is root-owned, mode 0755, and matches the expected
SHA-256 `d2555cd22a33506826f9eb069bb13fb0cc41303c7da41da5b761967d616f4147`.
The sensor job remains absent from the system launchd domain in the fresh check.
The attended export subsequently completed at 17:28:23 UTC. Its sanitized
result was retrieved with a matching checksum and reviewed in the
[diagnostic result](2026-09-30-mini-readonly-diagnostic-result.md).

Source inspection confirms this run retained **text packet-header summaries**
from `tcpdump -n -q -tttt -l -s 96` on en0 and en1, restricted to `.7` and `.240`.
It did not retain application payloads or a raw pcap for this observation.
Packet byte totals include retransmissions and cannot prove successful delivery.

## Attended command, on the Mini only

Completed command, retained for provenance. No rerun is needed.

```sh
sudo /bin/bash /Users/matt/squirrelops-readonly-export.oqYjS8yk/export-mini-readonly-diagnostics.sh
```

The wrapper verifies the installed interpreter and copies only the hash-pinned
exporter into a new private root directory. It does not re-extract or install
the package. The exporter verifies the exact cleanup receipt, unchanged boot
and absent product jobs, then reads only:

- The two retained packet metadata files, exporting scoped TCP direction,
  port, packet count, byte totals and first/last recorded times.
- Current sensor log and up to five rotations, exporting allowlisted lifecycle
  events and numeric IDs/ports only. Unrecognized warning/error text, URLs,
  decoy names and traceback content are withheld. Exception types are counted.
- Original private command records, exporting only exact successful listener
  inventories for `.240` and its advertised/backend ports. PF tokens and other
  command content are not exported.
- Little Snitch's read-only traffic history for local time 12:18:40 to 12:19:40,
  retaining records for laptop `.7` only, numeric counters and allowlisted
  process labels. A failed or empty history query does not identify a cause.

Only a new sanitized report is made readable by `matt`, in a fresh mode-0700
directory under `/private/var/tmp/squirrelops-readonly-results.*`. Source
permissions and files remain unchanged. No raw logs, planted logins or database
contents are copied. Keep the app closed and do not change Little Snitch rules.

The sensor parser considers 12:12 through 12:27 and 16:12 through 16:27 to cover
local/UTC clock candidates, retaining original timestamps rather than assuming
the log clock. Unknown packet formats are counted, not silently called a pass.

## Verification

Ten synthetic tests passed in each of the development and expanded candidate
Python runtimes. Tests cover packet direction/retransmits, rejected input,
secret-free event extraction, exception window isolation, exact listener
command selection, traffic-history redaction, guarded parents/files, changed
cleanup receipt rejection and a mocked complete export with read-only commands.
Host operations are mocked; these are not live protocol acceptance tests.

```sh
sensor/.venv/bin/python -B -m unittest discover -s docs/testing/fixtures -p test_mini_readonly_diagnostic_export.py -v
build/test-artifacts/launchd-budget-20260930-expanded/sensor.pkg/Payload/Library/SquirrelOps/sensor/python/bin/python3.12 -I -B -m unittest discover -s docs/testing/fixtures -p test_mini_readonly_diagnostic_export.py -v
/bin/bash -n docs/testing/fixtures/export-mini-readonly-diagnostics.sh
```

Staged file hashes, independently checked over SSH:

| File | SHA-256 |
| --- | --- |
| `mini_readonly_diagnostic_export.py` | `ff85896f538b1ff5410d06a06b2129d9035dfe6edb9a51cfdb88b4026bab0380` |
| `export-mini-readonly-diagnostics.sh` | `d223a860295a5b539efbc9b1777ca731153a661435cb43a11368fc101c0a25d5` |

The engineering verification skill informed redaction/guard tests and the
separation between a prepared exporter and an executed, diagnosed live result.
No product code change, build, commit, push or release occurred in this step.
