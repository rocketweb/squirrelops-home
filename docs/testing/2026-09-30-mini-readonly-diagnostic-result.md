# Mini retained-evidence review: SSH/SMB stall narrowed, cause unresolved

Read-only export completed at **2026-09-30 17:28:23 UTC**. The report was
retrieved over SSH and its SHA-256 matched the Mini's copy:
`1d6b63a54c62786406f540bdd3b8017b83b3b317b6cac0042ff42e9cefbce623`.

- Original sanitized report:
  `/private/var/tmp/squirrelops-readonly-results.0dn1_7cr/diagnostic.json`
- [Retained report](evidence/2026-09-30-mini-post-reboot/readonly-diagnostic.json)
- [Export scope and verification](2026-09-30-mini-readonly-diagnostic-preparation.md)
- [Original acceptance results](2026-09-30-mini-post-reboot-live-result.md)

The export did not restart services, install anything, modify filters or run
new probes. Reading this report is not another protocol acceptance attempt.

## What the evidence establishes

The en0 capture contains traffic between laptop `.7` and decoy `.240`.
Parsed TCP rows show these payload totals, including retransmissions. They are
not unique application byte counts or HTTP body lengths.

| Advertised service | Client to decoy bytes | Decoy to client bytes | Original client outcome |
| --- | ---: | ---: | --- |
| SSH, 22 | 0 | 0 | TCP connected; five-second banner timeout |
| SMB, 445 | 238 | 0 | Share discovery timed out without a listing |
| OpenAI-compatible, 1234 | 80 | 336 | HTTP 200 and nonempty model list |
| Ollama, 11434 | 80 | 776 | HTTP 200 and nonempty model list |
| MCP, 8765 | 192 | 1020 | HTTP 200 and nonempty tool list |

SSH's header exchange spans 12:18:55 to 12:19:00 local time; SMB spans 12:19:00
to 12:19:20. Client result timestamps record completion, not start. SSH's zero
request payload is expected for a banner-only read, not a faulty test.

Retained listener snapshots `command-263.json` and `command-267.json` show guest
PID 15923, UID 309, listening on `.240:49878` and `.240:49879`, the configured
SSH/SMB backends. Sensor PID 15614, also UID 309, owns `.240:49880` through
`.240:49882`, the three Python-backed services.

This rules out missing listening sockets in those snapshots. It does **not**
prove that the guest process accepted a particular connection, that PF sent
it to the intended socket, or that an in-guest service replied. SMB request
data reached the Mini's interface. General LAN unreachability cannot explain
the observed mix of results.

Little Snitch's history query succeeded. It records one inbound TCP connection
to each Python backend, with matching byte counters and `denyCount: 0`. No
guest-process SSH/SMB entry appears in the exported one-minute window. Absence
of a record is **not** a deny verdict and does not establish whether Little
Snitch held a connection. This is filtered history for `.7`, not a filter audit.

## The seventh row is explained

The sensor resumed original classic row 6 on port 60556 at 12:13:57 and again
at 12:15:05 following restart. The deep host became active at 12:14:30 and
12:15:36. Row **7** was deployed on port **51232** at **12:16:43.513**.
Three milliseconds later, the classic auto-deployment summary reported one
activated, zero recovered and one newly deployed.

That summary is emitted by `DecoyOrchestrator.auto_deploy()`. Together with
the recorded row identity, it establishes application auto-deployment of the
`home_assistant` decoy **before** the laptop probes. The earlier cleanup
equality guard rejected this legitimate addition. The approved continuation
already preserved it and completed cleanup; no data repair or deletion is needed.

## Remaining diagnostic gap

Source inspection shows that the listener creates a task for guest connection
handling, and emits the connection event after `onAccepted` returns. A missing
event cannot distinguish failure before acceptance from a task or guest-connect
stall. Guest stderr is retained in a bounded in-memory tail by the sensor;
this report does not contain that tail.

Relevant source: `TCPRelay.swift`, `RelayConnection.swift` and
`VirtualMachineRuntime.swift` under `app/Sources/SquirrelOpsDeceptionGuest`,
and `sensor/src/squirrelops_home_sensor/decoys/deep/guest_runtime.py`.

There are no allowlisted guest-exit, invalid-telemetry or callback-failure
events. **Twelve warning messages were withheld by the sanitizer** and remain
unreviewed; this is not a clean-log assertion. The packet parser also withheld
three en0 lines and one en1 line. Unparsed text, TCP flags and application
payloads are unavailable in this report. These limits prevent assigning the
cause to Little Snitch, PF, Dispatch, VSOCK, sshd or smbd individually.

Existing Swift tests cover relay admission, socket pumping and guest-connect
deadlines. A source search found no test instantiating the real `TCPListener`
and verifying its accept callback; the wiring assertion is a source-string
check. This is a regression-test gap, not proof of a listener defect.

## Hold and next approval boundary

Fresh read-only SSH checks after retrieval found both product jobs absent from
the system domain and explicitly disabled, no matching sensor/helper/guest or
Virtualization runtime, and no `.240`/`.241` alias on en0. PF was not re-read;
its disabled state comes from the prior successful cleanup receipt.

Recommended next scope, **not performed or newly authorized here**:

1. Add a local test of the actual listener and bounded internal checkpoints for
   listener activation, acceptance, guest-connect start/completion and relay I/O
   failures. Keep protocol responses unchanged and exclude credentials/content.
2. Verify locally, then prepare one diagnostic build and a bounded Mini retry
   plan with filters unchanged, seven existing rows preserved and safe teardown.
3. Obtain approval for the exact installation/startup/probe scope before running
   it. Correlate checkpoints with listener queues and client results, then fix
   the demonstrated cause instead of changing filters speculatively.

SSH/SMB acceptance and release readiness remain open. No product change,
new probe, rebuild, commit, push or publication occurred during this review.

The operator subsequently approved local implementation, tests and a diagnostic
build. That separate work is recorded in the
[relay diagnostics build report](2026-09-30-relay-diagnostics-build.md).
It does not authorize a new Mini installation or live test.
