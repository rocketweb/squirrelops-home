# Mac mini Home 2.1 live installation and protocol acceptance

Date: 2026-09-29. **Installation passed; functional acceptance failed.**
**Cleanup completed at 14:38:18 UTC; service/address teardown independently verified.**
The cause of the runtime failure is not yet established. This result does not
close the A5 release gate or authorize a public release.

Subsequent [real-address TCP account-control diagnostic](2026-09-29-mini-tcp-account-control.md):
the sensor account returned three valid banners. The login account's three
reads timed out, followed by late server sends. Matt approved a connection
prompt during that run; its rule and scope are unknown, so this is not an
unchanged-filter comparison. That diagnostic's cleanup passed. The fresh
six-attempt repeat passed for both accounts with no new prompt reported; its
cleanup passed and its processes/ports were independently verified absent.
Neither diagnostic exercises the product's
virtual-IP/PF/guest path or clears its release gate.
The subsequent [changed-script v3 diagnostic](2026-09-29-mini-tcp-changed-script.md)
also passed six of six fixed-banner reads and cleanup. Matt confirmed it
produced no new prompt. These diagnostic successes do not close the original
virtual-IP protocol failure or the A5 gate.

## Exact scope and artifact

- Server: Matt's Mac mini, `100.108.203.27`, macOS 27.0 build `26A428`, ARM64.
- Client: authorized laptop `192.168.1.7`, interface `wlp0s20f3`.
- Allocated decoy: `192.168.1.240`, proxy ARP on mini `en0`.
  The other approved address, `.241`, was not allocated.
- Artifact: `build/test-artifacts/SquirrelOpsHome-2.1.0-ai-setup-20260928-local-test.pkg`.
- SHA-256: `3e8c0fc78befad3365fdbff5583d9f85c6b6fe01816b5863edbebeceaa4b8f5f`.
- This is the unsigned local-test installer with ad-hoc signed executables,
  not a signed/notarized public release.
- Operator ran the attended `--resume-failed-install` recovery documented in
  [the recovery record](2026-09-29-mini-install-recovery.md).
- Authority remains limited to the
  [approved setup and protocol-test scope](2026-09-28-mini-install-test-scope.md).
  No disruptive PF fault injection, old-package installation, filter disabling,
  or product-code changes were performed.

## Installation result

The installer completed at 09:46:57 EDT (13:46:57 UTC). `/var/log/install.log`
reported helper availability to `_squirrelops`, sensor launchd loading and
postinstall completion. Both `pkgutil --pkg-info` queries returned version
`2.1.0`, install-time `1790689617`, for:

- `com.squirrelops.home.app`
- `com.squirrelops.home.sensor`

The package's durable preinstall snapshot is
`/Library/SquirrelOps/backups/preinstall.KT855w6k`.
The attended harness reported `ready_for_tests` at `2026-09-29T13:47:35Z`,
service UID 309, with a 20-minute observation window. That phase follows its
installed executable hash checks, bounded configuration digest verification,
two successful sensor health requests and existing listener baseline checks.

Sanitized server evidence directory:
`/private/var/tmp/squirrelops-mini-results.fxk5kskd`.

## Functional results

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Sensor startup | Passed initially | Harness health checks passed; a subsequent direct localhost health response was `status: ok` |
| Five decoy listeners | Present | Database marked all active; `netstat` showed all five service-UID backend listeners |
| Laptop TCP to advertised SSH/SMB | Handshake passed | Follow-up packet trace proves SYN/SYN-ACK/ACK on both advertised ports |
| SSH banner and protocol | **Failed** | Connected, sent a client banner, received no server banner; five-second read deadline expired |
| SMB negotiation | **Failed** | Connected, sent one SMB2 NEGOTIATE request, received no response within five seconds |
| HTTP decoy 11434 | **Failed** | Credential-free `GET /api/tags` timed out after five seconds with zero response bytes |
| HTTP decoy 1234 | **Failed** | Credential-free `GET /v1/models` timed out after five seconds with zero response bytes |
| Direct backend 50708 through 50712 | Expected denial observed | One three-second TCP probe to each timed out from the laptop; not proof of all containment properties |
| Native Screen Sharing through VIP 5900 | Expected denial observed | One three-second TCP probe timed out; native host address was not probed |
| Connection counters, attribution and alerts | **Failed acceptance** | Root snapshots retained zero counters, no connection records and no alerts despite the wire traffic |
| SSH/SMB failed and successful authentication | Not run | Withheld after the SSH protocol gate failed |
| SSH commands, SFTP, SMB file read/write/delete | Not run | No credentials submitted and no guest file changes attempted |
| Later localhost sensor health | Mixed observations | A request at approximately 14:01 UTC timed out, exit 28; an explicit no-proxy retry at 14:05 UTC returned HTTP 200 |
| Frontend / VoiceOver / manual UI | Not run | This was bounded remote installation and protocol acceptance |
| Disruptive A5 matrix | Not run | Separate approval and containment harness still required |
| Automatic cleanup | **Incomplete** | Halted at the immediate post-bootout loaded-service check; guest and VIP remained |
| Attended cleanup continuation | **Passed** | Exact-session continuation completed at 14:38:18 UTC; guest/jobs/test addresses gone, native listeners retained |

The private synthetic login was transferred to the authorized laptop with mode
0600 for the approved protocol tests, but the login gate was not reached. It is
not included in repository evidence. Raw packet captures also remain private.
No real account credentials, brute force, exploit, flood or native host writes
were used.

## Diagnostic evidence and interpretation

The laptop's ARP entry for `.240` matched mini `en0` MAC
`d0:11:e5:12:9a:c2`. The packet trace recorded replies from that MAC. SSH
client port 34150 sent 32 bytes and the server acknowledged all 32; SMB client
port 60298 sent 106 bytes and the server acknowledged all 106. Neither stream
received server application payload during its bounded wait.

The mini's translated sockets belonged to the expected processes, not native
SSH or SMB:

| Advertised port | Backend | Process / UID | `netstat -Lan -p tcp` queue at 14:00 UTC |
| --- | --- | --- | --- |
| 22 | 50708 | Guest PID 27646 / 309 | `3/3/128` |
| 445 | 50709 | Guest PID 27646 / 309 | `2/2/128` |
| 11434 | 50710 | Python PID 27179 / 309 | `1/1/128` |
| 1234 | 50711 | Python PID 27179 / 309 | `1/1/128` |
| 8765 | 50712 | Python PID 27179 / 309 | `0/0/128` (no application probe) |

The command labels these values `qlen/incqlen/maxqlen`. After the clients
closed, `netstat -anv -p tcp` retained matching `CLOSE_WAIT` entries with
nonzero receive counters and zero transmit counters. These observations do
not establish that application `accept()` completed, even though the client
TCP handshake did. Both the Swift guest and Python listeners are affected;
an initial guest-only hypothesis was therefore rejected. A direct connection
to a private backend on the mini is not a valid bypass test because those
endpoints are deliberately protected by PF.

The active PF snapshot contained five `rdr` entries, five tagged UID-309
`pass in quick` rules on `en0`, an echo-request allowance and a final VIP
default-deny rule. They were observed, not edited, during this run. Presence
of these rules is not proof of correct state/translation behavior.

Read-only environment inspection at approximately 14:02 UTC found:

- Apple Application Firewall disabled; block-all also disabled.
- Activated/enabled Avast Security `16.2.636` and Little Snitch `6.5` network
  extensions.
- Activated/enabled Surfshark WireGuard and transparent-proxy extensions,
  IPVanish WireGuard, and Tailscale.

Extension activation does not prove a particular connection was blocked, nor
does it mean every VPN tunnel was connected. These are possible confounders,
not confirmed causes. No filter, VPN, PF guard or native service was disabled.
A read-only guest thread sample was requested from the operator, then marked
optional after the shared Python-listener failure was established; no sample
has been incorporated into this report.

The final credential-free health retry explicitly used `--noproxy '*'`,
`--connect-timeout 2`, and `--max-time 3` against the same loopback HTTPS
endpoint. It returned HTTP 200, 40 response bytes, TCP connect time 0.000212s
and TLS time 0.016987s. This is evidence of responsiveness at 14:05 UTC, not
evidence that the decoy protocols recovered. The earlier timeout's cause is
unresolved; do not infer a permanently blocked sensor process from it.

## Evidence files and test-driver limitation

### Subsequent Little Snitch traffic-history query

Matt supplied an attended root traffic-history query after enabling Little
Snitch's separate Terminal-access permission. Its five returned rows are
preserved in
[little-snitch-user-filtered.csv](evidence/2026-09-29-mini/little-snitch-user-filtered.csv).
All are outbound UID-309 Python activity to the laptop on TCP 8080. Both
`connectCount` and `denyCount` are zero in every row; the records do not prove
successful connections or explain the inbound decoy failures. Little Snitch's
[field definitions](https://help.obdev.at/littlesnitch6/cmd-log-traffic) distinguish
inbound/outbound direction and count established connections and denials within
each statistics interval.

The original query required `SquirrelOps` in the executable fields as well as
the laptop address. Records with another process attribution or missing
executable names would therefore be omitted. Absence from this filtered output
does not clear Little Snitch or identify another component as the cause.

Subsequent unprivileged read-only inspection found `net.cfil.active_count: 1`
and `net.cfil.sock_attached_count: 52`. The observed kernel-control connection
to `com.apple.content-filter` belonged to `at.obdev.littles...`, PID 1186.
This identifies a current socket content-filter attachment, not a verdict for
the historical test flows or a complete inventory of every packet-filtering
layer. The SquirrelOps sensor launchd job remained absent. No service restart,
PF change, or filter disable was performed.

Matt then supplied a second query selecting `direction == in` and the exact
remote-IP CSV column, without an executable-name condition. Its 13 rows are
preserved in
[little-snitch-user-inbound.csv](evidence/2026-09-29-mini/little-snitch-user-inbound.csv).
Twelve are ICMP (protocol 1), attributed to ping or the kernel. One is UDP
(protocol 17), port 5353, attributed to mDNSResponder. Every denial count is
zero. There are no TCP (protocol 6) rows. The wider query therefore still does
not record the historical decoy TCP flows whose handshakes were captured on
the wire. Missing traffic-history rows do not establish which component delayed
those flows. Further queries against this same history are not a substitute
for an instrumented reproduction.

The next proposed step is the separate, not-yet-authorized
[short TCP account-control diagnostic](2026-09-29-mini-tcp-diagnostic-proposal.md).
It leaves SquirrelOps stopped and does not install a package, start a VM, publish
a virtual IP, or change PF/filter policy.

Sanitized files are in [evidence/2026-09-29-mini](evidence/2026-09-29-mini/):

- `before.json`, `latest.json`: root-produced decoy, connection, alert, owned
  alias and PF snapshots.
- `after.json`: final pre-cleanup snapshot, still zero connection/alert counters.
- `status.json`: final root-produced `needs_review` status at 14:07:40 UTC.
- `cleanup-status.json`: subsequent root-produced `stopped` status at 14:38:18 UTC;
  original failure evidence remains unchanged.
- `results.json`: initial bounded laptop probes.
- `handshake-results.json`, `handshake-headers.txt`: follow-up TCP/protocol
  diagnostics that distinguish successful connect from response timeout.
- `packet-summary-en0.txt`, `packet-summary-en1.txt`: root-produced header-only
  summaries after stopping both captures. Ethernet had 72 captured packets;
  Wi-Fi had one ARP request and no matching TCP traffic. No successful
  secondary-interface protocol test is implied.

**Do not interpret the first `results.json` SSH `connected: false` field as a
failed TCP handshake.** That initial fixture catches banner-read timeouts in
the same block as `connect()`. The preserved later diagnostic records
`connected: true` separately, and packet headers confirm it. The original
evidence was not rewritten to hide the reporting limitation.

The added fixtures passed Ruff. The existing guarded installation/recovery
fixture suite was rerun with
`sensor/.venv/bin/python -B docs/testing/fixtures/test_mini_acceptance.py`:
**28 tests passed**. `/bin/bash -n` passed on the staged bootstrap source.
Those checks do not turn failed live protocol acceptance into a pass.

## Cleanup and next boundary

Automatic cleanup ran at approximately 14:07:35 UTC but halted at 14:07:40:

```text
Cleanup incomplete: Sensor service remains loaded
```

The harness calls `launchctl bootout`, then immediately asserts that
`launchctl print` fails. Subsequent read-only inspection found the sensor job
absent and sensor PID 27179 gone. This exposes a timing-sensitive harness
check: it does not wait for the launchd job to disappear. The product package's
preinstall stop helper already has a bounded wait; this acceptance harness
does not. That explains this premature cleanup stop, not the protocol failure
or the remaining guest's shutdown behavior.

Historical independent observations after the first cleanup halt:

- `com.squirrelops.sensor` no longer present in the system launchd domain.
- `com.squirrelops.helper` still running, PID 27174.
- Service UID 309 still owns guest PID 27646, Virtualization PID 27647 and
  `distnoted` PID 27648. No broad user/process kill was attempted.
- Guest TCP listeners `.240:50708` and `.240:50709` remain.
- `.240/32` remains on `lo0`. Alias withdrawal was not reached.
- Ethernet `.115` and Wi-Fi `.254` remain unchanged. Native wildcard SSH,
  SMB, Screen Sharing and native `.115:11434` listeners remain visible.
- Both packet captures were stopped and their sanitized summaries retrieved.
- The cleanup branch did not reach anchor clearing or its owned PF-reference
  release. The harness explicitly reported protection retained. No root PF
  status re-query was possible through unprivileged SSH, so current PF parity
  is not independently certified.

At that first halt, full baseline parity and post-test SQLite backup
verification had not been reached. The installed state and existing protection
were retained pending an attended exact-session continuation. No global PF
reset or reinstall was used to recover.

Matt subsequently supplied the exact private baseline:
`/Library/SquirrelOps/acceptance-backups/mini-20260928.bukymecp`.
The [cleanup-only continuation](2026-09-29-mini-cleanup-continuation.md) was
prepared against this session, then Matt executed it successfully. Its private
backup is `cleanup-20260929.zzlg2yx9` within the original baseline.

At `2026-09-29T14:38:18Z` the guarded root script published `stopped`, test guest
stopped, aliases absent, original listener endpoints present, own PF reference
released, and PF disabled. Installation and test data were retained. Independent
SSH inspection subsequently verified both product launchd jobs absent, both
runtime PIDs gone, no assigned test addresses on any interface, no published
test proxy ARP, no test-VIP listeners, unchanged Ethernet/Wi-Fi addresses and
continued native SSH/SMB/Screen Sharing/AI listeners. Both 2.1.0 receipts remain.
The OS-owned service-UID `distnoted` was intentionally left alone.

The PF and database-backup assertions come from the successful guarded root
run; they were not independently re-queried as root. Details and evidence
distinctions are in the linked continuation record. **Keep the app closed and
do not rerun the setup or cleanup scripts:** the diagnostic session has ended,
not passed its protocol acceptance gate.

Next work requires identifying the shared listener/flow failure while
preserving containment. Obtain applicable network-filter decisions and a
reviewed minimal reproduction before attributing the cause to PF, the guest,
Python or a third-party extension. Do not remove UID/tag guards or disable
filters as an unreviewed workaround. Repeat ordinary protocol acceptance
after a verified remedy, then conduct the separately approved A5 matrix.

No product fix, package rebuild, commit, push, release publication or A5 gate
closure is claimed by this record.
