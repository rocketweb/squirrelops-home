# Mini SMB diagnostic: share listing completes in 20.84 seconds

The single approved SMB diagnostic completed on October 1, 2026, at
**19:14:00 EDT (23:14:00 UTC)**. The anonymous client returned **Builds,
Engineering, Time Machine Backups and IPC$**, then exited normally with code
**0** after **20.841 seconds**. Neither the 45-second diagnostic deadline nor
the output budget was reached.

This establishes successful anonymous discovery with this diagnostic client.
It does not complete authenticated SMB, file operations, containment or release
acceptance. The preceding acceptance client's 20-second deadline would be too
short for this observed duration, but its configuration and username differed.
The earlier failure cannot be attributed solely to that deadline.

**Cleanup is verified at 19:31:45 EDT (23:31:45 UTC).** The final guarded
receipt reports the guest stopped, aliases absent, original listener endpoints
preserved, only this test's PF reference released, and PF disabled. Separate
read-only checks found both product jobs disabled and absent from launchd, no
matching product/guest process, and no `.240` or `.241` interface alias.
Installation, configuration and test data were retained.

[Cleanup receipt](evidence/2026-10-01-mini-smb-diagnostic/cleanup-status.json)
SHA-256: `4cd666f50c23dd87fda61f04e41f9aa41d42c2f176e959e682f6719a1dc1e286`.
The saved `status.json` is the earlier readiness snapshot, not current status.
Final `after.json` and `after-diagnostics.json` match the saved post-client
snapshots byte for byte; they are retained evidence, not fresh live API reads.

A subsequent [read-only packaging analysis](2026-10-01-mini-smb-resolver-analysis.md)
confirmed leaked build-time DNS/hostname configuration in the exact installed
guest. The upstream Samba and resolver paths strongly fit the delay, but no
causal before/after runtime comparison has been performed.

## Exact attempt

- [Approved scope](2026-10-01-mini-smb-diagnostic-scope.md).
- [Preparation and regression evidence](2026-10-01-mini-smb-diagnostic-preparation.md).
- Mini `100.108.203.27`, boot `1790777754`, VIP `.240` only.
- Package SHA-256:
  `3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea`.
- Root-produced results: `/private/var/tmp/squirrelops-mini-smb-results.rsylu0_t`.
- Mini staging: `/Users/matt/squirrelops-mini-smb.HvkPvRep`.
- Laptop staging: `/root/squirrelops-mini-smb-client.7xhb0h1T`.
- Laptop source `.7` through `wlp0s20f3`; route rechecked before launch.
- Guest PID 99708; SMB backend 51169. Other mappings: SSH 51168,
  Ollama 51170, OpenAI-compatible 51171, MCP 51172.

Root-owned 0755 result directory and regular, single-link root-owned 0644
metadata files were verified before transfer. The laptop directory was
root-owned 0700 and its client was root-owned 0600, with matching SHA-256
`203404d31a5476dced345fbc4db0fdb2c7fe27d9e008a5be45465209c0c220da`.
Only status and endpoint metadata were transferred, privately. No synthetic
login file was read or transferred. The client validated fresh readiness,
scope, remaining time, package, boot, UID, configuration, mappings and route.

Exact command, executed once:

```sh
/usr/bin/python3 -I -B /root/squirrelops-mini-smb-client.7xhb0h1T/mini_smb_diagnostic_client.py --run /root/squirrelops-mini-smb-client.7xhb0h1T
```

The client and startup claims are consumed. Do not rerun, remove result guards
or send follow-up probes in this window.

## Results and timing

[Sanitized client results](evidence/2026-10-01-mini-smb-diagnostic/client-results.jsonl)
SHA-256: `079a387b03ed8223e475518eed8aae92956b1fde43f5602581731138700f1758`.

| Observation | Result |
| --- | --- |
| Anonymous share listing | Complete, all four expected shares |
| Client process | Exit 0, 20.841 seconds |
| Parent diagnostic timeout | Not reached |
| Captured raw debug text | 1,778 bytes, budget not reached |
| SMB connection evidence | Counter 1 to 2, source `.7` |
| Other service counters | Unchanged |
| Saved decoys | All seven retained, no additional host listeners reported |
| Credentials, containment and file operations | Not attempted by this SMB-only diagnostic |

The private debug trace remains on the laptop at
`/root/squirrelops-mini-smb-client.7xhb0h1T/private-debug.jsonl`, root-owned 0600,
single link. Its hash was independently rechecked:
`93c5c1b825f1a36aa2a019176f84933625fe0cc3b4f62bb7def34ed1239360a6`.
No arbitrary raw debug text was printed or copied to this repository.

A read-only scan of that exact trace exported only fixed known markers and
timings. Client output arrived in nine chunks:

- Connect marker at **0.065 seconds**.
- GENSEC backend marker at **10.266 seconds**.
- NTLMSSP markers at **20.397, 20.405 and 20.414 seconds**.
- Share-list header and all four shares at **20.838 seconds**.

Those are stdout arrival times, not exact packet timestamps. They establish
two roughly ten-second gaps before listing, but do not prove where the time
was spent, identify the negotiated dialect, or distinguish a server wait from
buffering elsewhere. No timing-related source change or speculative fix was
made. Explicit anonymous credentials, empty client configuration, disabled
Kerberos and a pinned port differ from the earlier all-protocol client.

## Guest evidence

The [guest checkpoints](evidence/2026-10-01-mini-smb-diagnostic/latest-diagnostics.json)
record one SMB connection:

| Checkpoint | Time EDT |
| --- | --- |
| Listener readable | 19:13:40.159 |
| Accepted / main actor entered | 19:13:40.162 |
| Guest connected / relay started | 19:13:40.166 |
| First client-to-guest read | 19:13:40.167 |
| First guest-to-client read | 19:13:50.617 |
| Both read directions EOF | 19:14:03.691 |
| Relay closed | 19:14:03.692 |

The first-read interval is **10.450 seconds**. No relay error or truncation
marker appears in this bounded trace. Client and Mini wall clocks were not
synchronized by this test, so do not derive cross-machine subsecond latency
from these two timestamp sources.

The [before snapshot](evidence/2026-10-01-mini-smb-diagnostic/before.json) and
[post-client snapshot](evidence/2026-10-01-mini-smb-diagnostic/latest.json)
show the expected single SMB counter increase and no credential trips. The
existing September 30 alert ID 3 is still the only exported alert row. The
snapshot omits alert-update fields and both apps stayed closed, so notification
and existing-alert refresh behavior were not verified.

## Remaining boundary

At report time, a question about new Little Snitch prompts is awaiting the
operator's answer. The previously reported narrow guest rule was not inspected
or changed. Do not infer its scope or persistence from successful discovery.

Guarded cleanup is verified and its receipt is preserved. Further live tests
require a new approved scope; this window authorizes no password or file tests.
The next acceptance work is private-backend containment, synthetic SSH/SMB
authentication/persona, file roundtrips, and notification behavior. SMB startup
latency remains unresolved and must be recorded separately from functionality.

The engineering-constraints skill kept successful slow discovery separate
from a claimed latency fix or release pass. No installer, product source,
configuration or filter-rule change, commit, push, signing, notarization or
publication occurred during this diagnostic.
