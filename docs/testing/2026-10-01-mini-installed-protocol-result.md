# Installed Mini protocol acceptance: SSH and SMB still blocked

The single approved laptop attempt completed on October 1, 2026, at
05:29:28 EDT (09:29:28 UTC). **The protocol gate failed.** All three synthetic
AI endpoints responded correctly; SSH and SMB did not. No authentication,
containment probes or file operations followed the failed gate.

This used the already-installed diagnostic package. No reinstall, restart
test, configuration edit, SQL recovery or filter-rule change was performed.

## Exact run

- Mini: `100.108.203.27`, boot `1790777754`, virtual IP `192.168.1.240` only.
- Laptop: `192.168.1.7`, route verified through `wlp0s20f3`.
- Package SHA-256:
  `3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea`.
- [Approved scope](2026-10-01-mini-installed-protocol-scope.md).
- Mini staging: `/Users/matt/squirrelops-mini-protocol.WJuCiUml`.
- Root-produced results: `/private/var/tmp/squirrelops-mini-protocol-results.75e9py0n`.
- Laptop staging: `/root/squirrelops-mini-upgrade-client.GWA3Ee6a`.

Before probing, root-owned readiness and endpoint files in a root-owned 0755
directory matched the expected package, boot, scope, sensor UID 309, unchanged
configuration and five unique mappings. The client independently rejected stale
readiness (over 30 seconds), insufficient remaining time (under ten minutes),
incorrect input ownership/modes, changed route or a reused result file.
Synthetic credentials were transferred privately and never printed.

Both client files matched their prepared SHA-256 values:

- Diagnostic wrapper: `bc36f73427a1a2f9b15260b922e72636b138d13330ad8329d32212ab0ab91c03`.
- Shared client: `15b3bb270b77d3801870d2a81b64dee266a8f823ce234f6b2be2ff360b02b7f6`.

Exact laptop command:

```sh
/usr/bin/python3 -I -B /root/squirrelops-mini-upgrade-client.GWA3Ee6a/mini_relay_diagnostic_client.py --run /root/squirrelops-mini-upgrade-client.GWA3Ee6a
```

Exit status: **1**, due to protocol failures. The exclusive result file now
exists; this one-shot client and startup claim are consumed. Do not remove
their guards or rerun them as another acceptance attempt.

## Results

| Check | Result | Evidence |
| --- | --- | --- |
| SSH 22 banner | FAIL | TCP connected; five-second banner read timed out |
| SMB 445 share discovery | FAIL | No listing or client output before the 20-second client timeout |
| OpenAI-compatible 1234 | PASS | HTTP 200, 210 bytes, valid nonempty model list |
| Ollama 11434 | PASS | HTTP 200, 651 bytes, valid nonempty model list |
| MCP 8765 | PASS | HTTP 200, 894 bytes, valid nonempty tool list |
| Private-backend/native-port denial | NOT RUN | Protocol gate failed |
| Incorrect-password handling and buildbot persona | NOT RUN | Protocol gate failed |
| SFTP/SMB read, write and delete | NOT RUN | Protocol gate failed |

[Six client records](evidence/2026-10-01-mini-installed-protocol/client-results.jsonl)
include the five protocol results and the explicit failed gate. Completion
times are 09:29:07 UTC for SSH, 09:29:27 for SMB and 09:29:28 for HTTP/gate.

## Server evidence and limits

The [pre-probe snapshot](evidence/2026-10-01-mini-installed-protocol/after-start.json)
and [post-probe snapshot](evidence/2026-10-01-mini-installed-protocol/latest.json)
show each AI service's connection counter advancing from 1 to 2. Matching
connection rows attribute those hits to the laptop. SSH and SMB remain at zero
connections and zero credential trips. The exported alert inventory still
contains the existing September 30 `decoy.trip` alert; no new alert row appears
in this snapshot. The snapshot does not expose every alert update field, so it
does not establish whether the existing alert was refreshed or notified.

The [relay diagnostics](evidence/2026-10-01-mini-installed-protocol/latest-diagnostics.json)
contain only the two `listener_activated` records, emitted at 05:27:42 local
time. No `listener_readable`, `accepted`, main-actor or guest-connect checkpoint
was recorded through the post-probe snapshot. No truncation marker appears.
The scoped socket inventory shows guest PID 64290 listening on private backend
ports 59738 and 59739. Sensor PID 63982 owns the three working Python endpoints
59740 through 59742. The exported PF mapping text agrees with these endpoints.

This narrows the observed failure to a point before the first recorded listener
read callback, rather than demonstrating a VSOCK or in-guest service failure.
It does **not** prove that Dispatch is broken, that a pending kernel connection
reached the intended listening socket, or that Little Snitch blocked it.
The lsof inventory is not a complete kernel accept-backlog measurement. Logs
are a bounded current-log tail, not complete rotated history. Packet metadata
and PF state samples remain in the private run evidence for further review.

Seven saved decoys remain present and unchanged in the snapshots; no additional
classic host listeners were reported. No production source changes were made
as part of this live test. The engineering-constraints skill keeps the failed
live gate separate from previously passing local tests.

## Cleanup and remaining work

**Cleanup is verified.** The [root-produced final receipt](evidence/2026-10-01-mini-installed-protocol/cleanup-status.json)
records completion at **05:48:09 EDT (09:48:09 UTC)**. Its SHA-256 is
`796977f62c6f4e67bf1350c7f2094ebce8325a5f01b75583ea6f9343f523d7c0`.
The root-owned, single-link 0644 file in a root-owned 0755 directory reports
stopped guest, absent aliases, original listeners preserved, installation/data
retained, only this run's PF reference released, and PF disabled. Configuration
remained unchanged. Independent SSH checks found both product jobs disabled
and absent from launchd, no matching product/guest process, and no `.240` or
`.241` alias. PF and data preservation are assertions of the guarded root
receipt, not new privileged reads by the agent. The final
[pre-cleanup snapshot](evidence/2026-10-01-mini-installed-protocol/after.json)
still contains all seven saved decoys; the final
[diagnostic snapshot](evidence/2026-10-01-mini-installed-protocol/after-diagnostics.json)
still contains only the two listener activation records. No new filter prompt
observation has yet been received.

The operator subsequently completed the
[scoped read-only export](2026-10-01-mini-protocol-evidence-export.md). Its
[review](2026-10-01-mini-packet-pf-review.md) confirms established PF states at
the expected SSH/SMB backend ports and no returned application bytes. Current
macOS application-firewall checks report disabled/permitted. Matt's subsequent
06:28 screenshot matches guest PID 64290 and SMB backend 59739 exactly,
confirming a pending Little Snitch approval for that connection. The linked
review records this new evidence and the proposed temporary guest-only test
allowance. No rule has been changed; SSH's corresponding alert and a successful
post-approval protocol retest remain unverified.
Keep both apps closed. SSH/SMB acceptance and release readiness remain open.
No commit, push, signing, notarization or release occurred.
