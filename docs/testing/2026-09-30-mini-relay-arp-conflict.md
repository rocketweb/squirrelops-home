# Mini diagnostic attempt stopped by a Studio address conflict

At 2026-09-30 23:09:48 UTC, the attended diagnostic runner stopped before
installation because `192.168.1.240` answered its ARP conflict check.

## Current evidence

- The [ARP report](evidence/2026-09-30-mini-relay-conflict/arp-check-1.json)
  records one reply for `.240`, MAC `1c:1d:d3:e0:7d:03`.
- Read-only local `ifconfig` identifies that MAC as the Mac Studio's `en0`,
  whose real address is `.18`. The Studio also has `.240/32` on `lo0`.
- The Studio's ARP table contains a permanent published proxy-only `.240`
  entry on `en0` with the same MAC. Its SquirrelOps sensor job is running,
  PID 61581 at inspection time. The exact decoy row/host identity was not read.
- The Mini's en0 MAC is `d0:11:e5:12:9a:c2`, a different machine. The responder
  is therefore the Studio, not the Mini reflecting its own interface identity.
- Mini sensor receipt remains `1790784842`. Both product jobs remain explicitly
  disabled; no matching product process was observed. The new package was not
  installed. No new laptop client attempt occurred.

The [status report](evidence/2026-09-30-mini-relay-conflict/status.json) records
`needs_review`. The runner checks ARP before its one-shot claim, PF enable,
job enablement, local-test marker or installer invocation. No such mutation was
reached in this attempt. Root PF state was not independently re-read afterward.
The Scapy deprecation warning did not cause the stop.

Verified backups remain at:
`/Library/SquirrelOps/acceptance-backups/mini-relay-20260930.um9lzv3y`.
Private copied inputs remain at `/private/var/root/squirrelops-mini-relay.BrkEjKVN`.
Public results remain at `/private/var/tmp/squirrelops-mini-relay-results.7kl1dqsk`.

## Approval boundary

The approved Mini scope explicitly excludes Studio changes. Do not bypass ARP,
delete an interface alias manually, reset PF, or start two hosts on `.240`.
Quitting the Studio app window is not a verified sensor shutdown.

Before another attempt, obtain approval either to temporarily pause the Studio
fake host using `.240` through its supported lifecycle, preserving data and
other hosts, or to plan a separate non-overlapping Mini address/configuration
migration. For a scoped Studio pause, first identify the exact host and saved
intent, verify backup and restoration, then confirm alias/proxy withdrawal
before repeating the Mini preflight. Do not assume a UI click withdrew networking.
Restore the Studio host only after verified Mini cleanup. No Studio mutation,
address migration or retry was performed during this diagnosis.

The existing Mini SSH/SMB stall remains unresolved. This attempt reached no
protocol test. The engineering-constraints skill guided evidence-first
attribution rather than treating the conflict check as a defect to disable.

## Studio pause follow-up

The user subsequently approved pausing the Studio `.240` host, then chose to
disable and boot out the whole Studio sensor. Read-only verification confirmed
the sensor job was disabled and unloaded, with no UID 309 runtime observed.
The old installed build nevertheless left ten loopback aliases and their
published proxy entries, including `.240`. The root helper remained running.
An unrelated UID 501 VM was left untouched.

A single-address helper withdrawal was prepared with root-private ledger and
network evidence, exact installed-helper/runtime hashes, stopped-state checks,
and postconditions requiring all other addresses and PF rules to remain
unchanged. It does not write SQLite or configuration. Restoration must use the
product lifecycle only after verified Mini cleanup; do not replay an old ledger
or old firewall rules.

The first attended attempt stopped before any alias mutation because its process
parser rejected Darwin's signed nobody UID (`-2`). Evidence remains at
`/Library/SquirrelOps/acceptance-backups/studio-withdraw-240.1Z2tmOnY`.
The parser was corrected and six targeted checks passed, including rejection of
a running service-account process and malformed/out-of-range identities.
The second administrator authorization was canceled (`osascript` error `-128`),
so the corrected cleanup has **not** executed and withdrawal is **not verified**.

Prepared Studio command:

```sh
sudo /bin/bash /private/tmp/squirrelops-studio-withdraw.uzLaYAtC/withdraw-studio-240.sh
```

Pinned withdrawal script SHA-256:
`7b844f97d26636ac4f7cf584726fa365e38001edddcf8bd31cd9c75a081fb15d`.
Only after `WITHDRAWAL VERIFIED` may the existing Mini runner be retried. Its
own fresh ARP check remains mandatory. The Mini jobs are still disabled and its
staged bootstrap hash remains unchanged. The laptop probe client hash and route
were rechecked without sending probes. No new package installation, LAN protocol
run, commit, push, or release occurred in this follow-up.
