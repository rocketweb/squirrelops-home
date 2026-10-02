# Home 2.1 laptop LAN baseline

Date: 2026-09-28. Result: **installed mimic reachability and connection evidence
passed; real SSH/Samba guest acceptance not executed**.

Matt explicitly approved using the Linux laptop. This pass did not install the
candidate, start or stop decoys, change PF rules or aliases, install laptop
software, or publish anything. Tests produced expected connection and alert
records; those records were preserved.

## Scope and identity

- Client: existing SSH access to `root@192.168.1.7`, known host-key verification
  enabled. Remote hostname `laptop`, Linux `7.0.0-30-generic`.
- Client interface: `wlp0s20f3`, source `192.168.1.7/24`. Routes to the sensor
  Mac and both tested VIPs use this physical LAN, not Tailscale or Docker.
- Existing tools included SSH, SFTP, smbclient, Python, netcat, arping, nmap,
  tcpdump, and timeout. No package installation was necessary.
- Mac: existing September 26 installation identified in the
  [preflight report](2026-09-28-live-acceptance-preflight.md). It is not the
  latest local-test candidate. The installed helper hash was rechecked and
  remains `9790f88bc8ce7f685d43f11acda79de3ec00a5314c469fbd01cbf7e85be525f2`.
- Active targets, verified from the live database before probing:
  `docs.local` at `192.168.1.201` and `office.local` at `192.168.1.208`.
  Both are `mimic` hosts, not disposable OpenSSH/Samba guests.

All five unretired Studio Build Mac rows, IDs 1045 through 1049, were **stopped**
at their recorded address `192.168.1.203`. No attempt was made to use that
historical address as a live target or to restart the stopped host.

## Results

| Check | Observation | Interpretation |
| --- | --- | --- |
| Proxy ARP | Three replies from each VIP, all from `1c:1d:d3:e0:7d:03` | Both resolve to the Mac's Ethernet interface |
| Advertised SSH | Port 22 connected on both VIPs; both sent `SSH-2.0-OpenSSH_7.6` | Banner-replay reachability passed; not authenticated SSH |
| Advertised SMB | Port 445 connected on both VIPs | TCP reachability passed; not proof of SMB negotiation |
| Private SSH/SMB backends | `.201:49445`, `.201:49448`, `.208:49511`, `.208:49514` each timed out at three seconds | Direct backend access was not available in these four probes |
| Backend listener verification | All four exact backend binds were present under sensor PID 599, `_squirrelops` | The timeout result was not explained by absent listeners at the follow-up observation |
| Anonymous SMB share listing | Both `smbclient -L` attempts exited 1 with `NT_STATUS_CONNECTION_DISCONNECTED` during SMB2/SMB3 negotiation | No share enumeration or real SMB acceptance passed |
| Connection attribution | Six new records, IDs 1789 through 1794, all from `192.168.1.7` | Every successful application-side connection was recorded |
| Counters | Each SSH card increased by one; each SMB card increased by two | Six total increments match four TCP/banner probes plus two SMB negotiations |
| Alert persistence | New high-severity `decoy.trip` alert 435, titled `Port scan detected from 192.168.1.7`, incident 16 | Alert generation verified in the database; native notification presentation not tested |

The connection cursors were captured before probing: connection ID 1788 and
alert ID 434. Attribution used these cursors, source address, decoy IDs, and
counter deltas. Laptop and sensor timestamps differ in the raw records; they
were not assumed synchronized.

The installed `decoys/types/mimic.py` and `alerts/decoy_handler.py` matched the
reviewed checkout byte-for-byte. Non-HTTP mimics use the banner-replay handler,
which reads bounded client input, records a hit, and closes the connection.
They do not provide the Studio guest's full Samba implementation. The observed
SMB disconnection is consistent with that implementation, but is not a passing
SMB protocol result.

The alert handler folds repeated hits from a source into an unread alert while
retaining individual `decoy_connections` rows. One visible alert therefore does
not mean only one connection was detected. This run retained all six connection
records and one scan alert.

## Commands and evidence

The laptop used its existing authenticated SSH connection with strict host-key
checking and a temporary local connection-control socket. No synthetic or real
login credentials were sent to the decoys. At completion the control socket was
absent and the temporary local directory was empty. No remote test files were
created.

For each of the two explicit VIPs:

```text
ip route get <verified VIP>
arping -I wlp0s20f3 -c 3 <verified VIP>
```

Python `socket.create_connection(..., timeout=3)` made one attempt per listed
public/private endpoint. SSH probes read at most 256 banner bytes. SMB discovery
used `timeout 8 smbclient -L //<verified VIP> -N -m SMB3 -t 3` once per host.
No subnet-wide scan, brute force, share write, or fault injection was run.

Raw logs under ignored `build/test-artifacts/`:

- `2026-09-28-laptop-client-preflight.log`
- `2026-09-28-laptop-decoys-before.log`
- `2026-09-28-laptop-lan-baseline.log`
- `2026-09-28-laptop-smb-baseline.log`
- `2026-09-28-laptop-decoys-after.log`

## Remaining acceptance

This is useful cross-device baseline evidence for the installed mimics only.
It does not establish current-candidate upgrade acceptance, real SSH/SFTP/SMB,
second-ingress-interface isolation, listener replacement or existing-state
failure recovery, older-rule migration, Intel execution, or signed-release
containment. A5 remains open.

Next requires approval to perform the backed-up candidate installation and
start the stopped Studio Build Mac for bounded real-protocol tests. Installation
can interrupt the current 30 active service decoys. The full fault-injection
matrix still needs the separately scoped isolation described in the preflight.
