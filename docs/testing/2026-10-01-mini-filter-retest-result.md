# Mini temporary-filter retest: SSH passes, SMB listing still times out

The single approved laptop attempt completed on October 1, 2026, at
**07:32:29 EDT (11:32:29 UTC)**. Four of five protocol checks passed. SMB
share discovery timed out, so the client stopped before containment probes,
explicit password tests or file operations. This is not release acceptance.

**Cleanup completed at 07:34:16 EDT (11:34:16 UTC).** No installer, product
source, configuration or filter rules were changed by the agent in this run.

## Exact run

- [Approved scope](2026-10-01-mini-filter-retest-scope.md).
- Mini `100.108.203.27`, boot `1790777754`, VIP `192.168.1.240` only.
- Laptop `192.168.1.7`, route `wlp0s20f3`.
- Installed package SHA-256:
  `3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea`.
- Mini staging: `/Users/matt/squirrelops-mini-filter-retest.1moGrUKm`.
- Root-produced results: `/private/var/tmp/squirrelops-mini-filter-retest-results.4nf8sas0`.
- Laptop staging: `/root/squirrelops-mini-upgrade-client.ROWFDZto`.
- Private backend mapping: SSH 64244, SMB 64245, Ollama 64246,
  OpenAI-compatible 64247, MCP 64248.

The fresh status, endpoint map and private synthetic login passed the same
ownership, readiness-age, remaining-time, scope, package, boot and route gates.
Five endpoint mappings were unique. Credentials were transferred privately and
not printed or copied into this evidence directory. The two client hashes
matched the [prepared values](2026-10-01-mini-filter-retest-preparation.md).

Exact laptop command:

```sh
/usr/bin/python3 -I -B /root/squirrelops-mini-upgrade-client.ROWFDZto/mini_relay_diagnostic_client.py --run /root/squirrelops-mini-upgrade-client.ROWFDZto
```

Exit status **1**. The exclusive result file and startup claim are consumed;
do not remove their guards or rerun this attempt.

## Results

| Check | Result | Evidence |
| --- | --- | --- |
| SSH 22 banner | PASS | `SSH-2.0-OpenSSH_10.3`, 22 bytes |
| SMB 445 anonymous share discovery | FAIL | No client output before the 20-second client timeout |
| OpenAI-compatible 1234 | PASS | HTTP 200, 210 bytes, valid nonempty model list |
| Ollama 11434 | PASS | HTTP 200, 651 bytes, valid nonempty model list |
| MCP 8765 | PASS | HTTP 200, 894 bytes, valid nonempty tool list |
| Private-backend/native-port denial | NOT RUN | Protocol gate failed |
| Incorrect-password handling and buildbot persona | NOT RUN | Protocol gate failed |
| SFTP/SMB read, write and delete | NOT RUN | Protocol gate failed |

[Client records](evidence/2026-10-01-mini-filter-retest/client-results.jsonl)
SHA-256: `f04b621fedd135aec8bb814f1ed588114fdccfb1bfb9622d3938ea23bc25a7c9`.

## What changed in the observed failure

The [guest checkpoints](evidence/2026-10-01-mini-filter-retest/latest-diagnostics.json)
show both SSH and SMB reaching `listener_readable`, `accepted`,
`main_actor_entered`, `guest_connected` and `relay_started`. This is materially
different from the earlier attempt, which stopped before the first listener
read callback. SSH then returned its banner successfully.

For SMB connection 2, local timestamps were:

| Checkpoint | Time EDT |
| --- | --- |
| Accepted | 07:32:09.592 |
| Guest connected / relay started | 07:32:09.594 |
| First client-to-guest read | 07:32:09.594 |
| First guest-to-client read | 07:32:19.630 |
| Client EOF after test timeout | 07:32:29.536 |
| Relay closed | 07:32:29.802 |

There was **10.036 seconds** between the first reads in each direction.
These checkpoints show that some guest data returned to the relay, not which
SMB response it contained or whether the client received it. There is no
recorded relay error in this bounded trace. Neither a specific Samba defect,
Little Snitch verdict nor a timeout-only client defect is established.
Do not increase an acceptance timeout and call the underlying issue fixed.

The [before snapshot](evidence/2026-10-01-mini-filter-retest/before.json) and
[after snapshot](evidence/2026-10-01-mini-filter-retest/after.json) show one
additional connection attributed to laptop `.7` on each of the five services.
SSH and SMB counters changed from zero to one; each AI counter changed from
two to three. Credential-trip counters remain zero. All seven saved decoys
remain, with no additional host listeners reported. Saved `active` intent
does not imply a listener remains running after cleanup.

The exported alert inventory still contains the existing September 30 alert
ID 3, not a new alert row. The export does not include every alert-update
field, and both apps were closed. Alert refresh and notification behavior
therefore remain unverified by this run.

## New filter prompt

Matt reported a new prompt and supplied `Screenshot 2026-10-01 at 7.33.13 AM.png`.
It shows **python3.12 connecting out to 192.168.1.13**, not the deception
guest accepting laptop `.7`. The screenshot does not show the executable path,
PID or port. It is not evidence of an SMB-connection approval barrier, nor
proof that no other prompt was pending. Matt was asked to leave it unanswered.

The earlier temporary guest allowance remains operator-reported, not audited.
Its expiration or removal has not yet been verified. Do not broaden it or
make it permanent for this diagnostic result.

## Verified cleanup

The [root-owned final receipt](evidence/2026-10-01-mini-filter-retest/cleanup-status.json)
is a regular single-link 0644 file in the previously verified root-owned 0755
results directory. Its SHA-256 matches the Mini copy:
`23e496726d24f1e81acce52328128dfdac963d567772b8cef613c203e943ce6c`.

It reports stopped guest, absent aliases, original listeners present,
installation/data retained, unchanged configuration, only this run's PF
reference released and PF disabled. Independent SSH checks found both product
jobs disabled and absent from launchd, no matching product/guest process, and
no `.240` or `.241` alias. PF and retained-data verification come from the
guarded root receipt, not new privileged reads by the agent.

Keep both apps closed. Verify that only the temporary test allowance expires
or is removed; leave unrelated filter rules alone.

## Next boundary

The smallest useful next experiment is one bounded **SMB-only diagnostic**
with client protocol/debug timestamps and a fixed maximum duration, using the
same installed package. It should distinguish negotiation, anonymous session
setup and share enumeration, without real credentials, file writes, a new
installer, product changes or broader filter rules. Starting another live
window needs approval; none was started or staged by this report.

**Subsequent preparation:** Matt approved that diagnostic with "keep going".
The [SMB-only window is prepared and verified](2026-10-01-mini-smb-diagnostic-preparation.md),
but has not started. He reports the narrow guest rule is still active; no
rule inspection or change was performed by the agent.

The engineering-constraints skill kept the confirmed transport progress
separate from an unproven SMB cause. No commit, push, signing, notarization or
release occurred. Full SSH authentication/SFTP, SMB functionality, containment
and remaining release gates are still open.
