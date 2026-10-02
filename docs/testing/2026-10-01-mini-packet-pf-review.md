# Mini SSH/SMB: retained packet and PF evidence review

The October 1 export was retrieved and its SHA-256 matched the Mini's copy:
`ceb8cbcbb83422a82f91e0aacefeac60accf3e13c19e2022869eba25c1c9fc4b`.
It was generated at **06:03:19 EDT (10:03:19 UTC)**. This review did not start
services, change rules or send new decoy probes.

- [Original sanitized export](evidence/2026-10-01-mini-installed-protocol/retained-packet-pf-diagnostic.json).
- Source: `/private/var/tmp/squirrelops-protocol-evidence.8qk_3u9q/diagnostic.json`.
- File: Matt-owned, mode 0600, single link, 278,436 bytes, inside a private 0700 directory.
- Exact root-private run: `mini-protocol-20261001.1px9by6q`.
- [Client results and verified cleanup](2026-10-01-mini-installed-protocol-result.md).
- [Export scope and verification](2026-10-01-mini-protocol-evidence-export.md).

## Findings

### Subsequent screenshot: pending Little Snitch approval confirmed for SMB

Matt supplied `Screenshot 2026-10-01 at 6.28.04 AM.png`. Its connection alert
matches the failed SMB probe on every displayed identity field:

- Executable: `/Applications/SquirrelOps Home.app/Contents/Library/Helpers/com.squirrelops.deception-guest`.
- PID **64290**, `_squirrelops` UID **309**, ad-hoc code signature.
- Incoming source **192.168.1.7**, local TCP port **59739**.
- The retained endpoint map identifies **59739** as the backend for `.240:445`.

This is direct evidence that Little Snitch requested approval for the exact
tested guest connection. The vendor documents that an Ask decision pauses a
connection while awaiting the user, matching the captured established TCP
state but absent application response/read callback.
[Little Snitch rule actions](https://help.obdev.at/littlesnitch6/concepts-rules),
[connection alerts](https://help.obdev.at/littlesnitch6/alert-overview).

Little Snitch is therefore a confirmed approval barrier for this SMB attempt,
not merely a candidate inferred from absent logs. This screenshot does not show
the SSH alert at backend **59738**, nor establish that no additional defect
exists. A successful controlled retest is still required for both protocols.

The red `TERMINATED` label establishes that the process is no longer running,
not why it exited. It is consistent with the already-verified test cleanup and
is not evidence that Little Snitch killed the guest.

No rule was changed. The dialog currently shows `Forever` and `Only from
192.168.1.7`; neither is a saved-rule result until a decision is made. Proposed
next scope requires approval: one time-limited rule for this exact guest
executable, incoming TCP from laptop `.7` only, followed by one new bounded
protocol test with the same installed build and verified cleanup. Backend
ports are allocated at startup, so pinning this future allowance to expired
port 59739 would not cover a new run. No all-applications, all-sources or
outgoing allowance is proposed. The rule expires at the chosen time or can
be removed immediately after the test. No new test harness is staged yet.

The agent-browser skill was used to verify vendor rule/lifetime semantics;
engineering-constraints keeps the observed SMB approval barrier separate from
an unperformed successful retest. The earlier evidence review below predates
this screenshot and is retained for chronology.

Matt subsequently reported "done continue", approving the temporary allowance
and one controlled retest. The new
[start-only retest is prepared and locally verified](2026-10-01-mini-filter-retest-preparation.md),
not started. The rule remains operator-reported; neither a rule audit nor a
successful post-approval protocol test is implied.

**Subsequent live result:** the [07:32 temporary-rule retest](2026-10-01-mini-filter-retest-result.md)
passed SSH banner and all three AI checks. SMB now reached the guest and
returned data to the relay, but share listing still timed out. Cleanup is
verified; the new observed failure is later in the path than this earlier
packet/PF review. Full SSH/SMB acceptance remains open.

### Before the screenshot

PF recorded established connections to the two expected guest backend ports.
The interface capture independently shows SSH traffic and the SMB request
arriving, but neither service sent application data back. The instrumented guest
recorded listener activation only, with no listener-read or accept checkpoint.

Together these narrow the observed failure to the host-side delivery/readiness
path before the first recorded guest listener callback. They do not establish
a VSOCK, sshd or smbd failure. They also do not identify Dispatch, a content
filter, or a particular rule as the cause. No speculative fix was applied.

### Interface evidence

All scoped packets were observed on en0; en1 had none. The selected local window
was 05:28:50 through 05:29:45. There were zero unparsed/out-of-scope packet lines
and zero lines withheld for being outside the window.

| Advertised service | Client-to-decoy TCP payload bytes | Decoy-to-client TCP payload bytes | Client outcome |
| --- | ---: | ---: | --- |
| SSH 22 | 0 | 0 | Connected; five-second banner timeout |
| SMB 445 | 238 | 0 | Share discovery timed out |
| OpenAI-compatible 1234 | 80 | 336 | Correct HTTP 200 model list |
| Ollama 11434 | 80 | 776 | Correct HTTP 200 model list |
| MCP 8765 | 192 | 1020 | Correct HTTP 200 tool list |

Byte totals include retransmissions and HTTP headers, not just response bodies.
SSH sends no request bytes in the banner-only probe, as intended. Its packets
span 05:29:02.726788 to 05:29:07.737369. SMB spans 05:29:07.812882 to
05:29:27.769034. Packet flags and application contents were not exported.

### PF state evidence

The export contains **569 successful PF state snapshots**, with zero withheld
state lines. Record filenames must be sorted by their **numeric suffix** for
chronology: the JSON array retains lexical filename order, which puts
`command-1001.json` before `command-452.json`. No new export is needed to sort
the existing records correctly. They provide ordering, not individual timestamps.

| Backend | Laptop source port | PF state pair | Samples | First record | Last record |
| --- | ---: | --- | ---: | --- | --- |
| SSH 59738 | 33823 | `ESTABLISHED:ESTABLISHED` | 2 | 452 | 461 |
| SSH 59738 | 33823 | `ESTABLISHED:FIN_WAIT_2` | 424 | 470 | 4277 |
| SMB 59739 | 59978 | `ESTABLISHED:ESTABLISHED` | 10 | 470 | 551 |
| SMB 59739 | 59978 | `ESTABLISHED:FIN_WAIT_2` | 423 | 560 | 4358 |
| Ollama 59740 | 44871 | `FIN_WAIT_2:FIN_WAIT_2` | 44 | 560 | 947 |
| OpenAI-compatible 59741 | 60271 | `FIN_WAIT_2:FIN_WAIT_2` | 43 | 560 | 938 |
| MCP 59742 | 49243 | `FIN_WAIT_2:FIN_WAIT_2` | 44 | 560 | 947 |

These are repeated observations of five flows, not hundreds of connections.
The ports agree with the published endpoint map and prior listener inventory.
PF recognized both sides as established during the SSH/SMB probes; after the
client timeouts, those flows remained asymmetric in later state snapshots.
PF state does not prove that userspace accepted a socket or that a separate
content filter released it. Do not treat this as blanket proof that all packet
filter behavior is correct or as permission to reset PF.

## Additional read-only Mini checks

The installed macOS application-firewall commands returned:

```text
socketfilterfw --getglobalstate
Firewall is disabled. (State = 0)

socketfilterfw --getappblocked /Applications/SquirrelOps Home.app/Contents/Library/Helpers/com.squirrelops.deception-guest
Incoming connection to .../com.squirrelops.deception-guest is permitted.
```

The guest's code-signing entitlements show `com.apple.security.app-sandbox = false`
and `com.apple.security.virtualization = true`. These are current read-only
observations, not historical proof of filter policy during the probe window.
No entitlements or firewall settings were changed.

Little Snitch's installed CLI help was inspected. A proposed full-model export,
intended to print field names only, was blocked by safety review because the
operation could expose unrelated private configuration. It did not execute and
was not retried or worked around. A separate bounded history-only request for
the five backend ports and laptop `.7` in the 55-second test window returned
exit 14: `littlesnitch must be run as root!`. No current Little Snitch rule or
history evidence was obtained. There is still no operator report about whether
a new prompt appeared during this specific run.

## Next boundary recorded before the screenshot

Matt was asked to inspect Little Snitch Configuration for
`com.squirrelops.deception-guest` and share only matching rules, without changing
them. SSH/SMB use this executable; the three working AI endpoints use the sensor
Python executable. A Python rule does not by itself establish the guest's rule
status. Do not assume a deny, create broad allowances, disable filters, or rerun
the consumed test window based on the present evidence.

If rules do not explain the behavior, the next useful live experiment must
distinguish socket delivery from Dispatch readiness under the installed guest's
actual identity. It needs an explicit narrow scope and observed queue/readiness
evidence, not another unchanged installer or a speculative guest-service patch.
No such live experiment is prepared or authorized by this report.

The engineering-constraints skill kept observed facts separate from the
unresolved mechanism. Original evidence and product source were preserved.
SSH/SMB protocol acceptance and release remain blocked. Nothing was committed,
pushed, installed, signed or published during this review.
