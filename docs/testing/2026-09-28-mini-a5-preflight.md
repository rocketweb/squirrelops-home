# Mac mini A5 test-host preflight

Date: 2026-09-28. Status: read-only host and client checks completed; Matt supplied
privileged PF and listener output from Terminal on the mini and confirmed both
proposed test addresses available. Recursive anchor inventory and live-test
approval scope remain incomplete.
This is not a passing A5 record and does not authorize release publication.

## Verified hosts

Matt selected the Mac mini and corrected its Tailscale address to
`100.108.203.27`. Existing SSH credentials for `matt` connected with strict
host-key verification. No host-key exception or SSH configuration change was
needed. Serial commands reuse a temporary local SSH control connection.

| Item | Observed value |
| --- | --- |
| Mini identity | Matt's Mac mini, `matts-mac-mini.tail3fdb08.ts.net` |
| OS | macOS 27.0, build `26A428`, ARM64 |
| Hardware | `Mac16,11`, 24 GiB RAM, hardware virtualization available |
| Available disk space | Approximately 41 GiB at the snapshot |
| SSH and console user | `matt`, UID 501, administrator group membership |
| Noninteractive administrator access | Unavailable; no password requested or read |
| Ethernet | `en0`, `192.168.1.115/24`, MAC `d0:11:e5:12:9a:c2` |
| Wi-Fi | `en1`, `192.168.1.254/24`, current MAC `ea:03:72:63:7e:01` |
| Default physical route | `en0` through `192.168.1.1` |
| Tailscale management | `100.108.203.27` on `utun4` |
| Existing SquirrelOps | App, sensor directory, helper binary, component receipts and launchd jobs were not found; localhost health did not respond |
| Linux client | Existing authorized SSH to `root@192.168.1.7`, hostname `laptop` |
| Client physical route | `wlp0s20f3`, source `192.168.1.7`, to both mini LAN addresses |

One ICMP probe to each mini LAN address succeeded. That establishes basic
reachability, not proof that each probe entered the expected interface. The
live tests must capture packets separately on `en0` and `en1` and verify MAC
delivery rather than assuming destination IP proves ingress.

The laptop already has SSH, SFTP, smbclient, arping, tcpdump, timeout and Python.
The mini has Python, Swift, tcpdump and netcat. No software was installed.

## Existing workloads to preserve

The mini is not an empty disposable host:

- Ollama listens on `192.168.1.115:11434`; another inference process listens on
  loopback. Do not stop, reconfigure or benchmark either service for A5.
- Wildcard TCP listeners exist on ports 22 and 445, in both address families.
  Native SSH and file-sharing services must remain untouched. A successful TCP
  connection alone is not proof that a synthetic decoy answered.
- AirPlay/Control Center and other normal macOS services have wildcard listeners.
- An active virtual-network bridge is present; this alone does not identify a
  running VM or its owner. Preserve it and all unrelated PF anchors.

The initial unprivileged inspection was supplemented by Matt's root-authorized
Terminal output below. The on-disk `/etc/pf.conf` and the supplied top-level
loaded rules contain the standard `com.apple/*` anchor hooks. The recursive
contents of Apple child anchors and PF reference ownership have not been
captured; top-level hooks alone do not prove those child rulesets are empty.

### Administrator inventory supplied by Matt

Evidence: Matt pasted output from the requested read-only `sudo /bin/sh -c`
command on the mini. This is operator-supplied terminal evidence, not a
successful remote administrator session.

- `pfctl -s info`: **Disabled**, zero current states, and all displayed state
  and processing counters zero. No rule enable/disable or state mutation was
  performed. This concerns PF, not the separate macOS application firewall.
- Top-level anchors: `com.apple`. Loaded filter rules show scrub and filter
  hooks for `com.apple/*`; loaded translation rules show NAT and RDR hooks for
  `com.apple/*`.
- Both queries for `com.apple/squirrelops` returned
  `pfctl: DIOCGETRULES: Invalid argument`. A missing ruleset is the likely cause:
  Apple's published kernel returns `EINVAL` when `pf_find_ruleset` fails in
  `DIOCGETRULES`. This is an inference, not a completed recursive inventory or
  proof of exact macOS 27 source parity. Do not create an anchor just to silence
  the message. Source: [Apple PF ioctl implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf_ioctl.c).
- The `No ALTQ support in kernel` messages accompanied successful status and
  top-level rule reads. They did not prevent those observations; no ALTQ setup
  is proposed for these decoy tests.
- Root `lsof` identifies `launchd` wildcard listeners on **22 and 445** in
  IPv4 and IPv6. Preserve them and verify decoy protocol identity, not just an
  open TCP port. Screen Sharing listeners on 5900 must also remain available.
- Additional root listeners include wildcard 88 and 18083, loopback 8021, and
  Tailscale listeners. Their full service ownership is not established by the
  socket snapshot; preserve all of them. Previously observed Ollama, local
  inference, AirPlay and remote-management listeners remain present.
- Neither proposed private backend port, 49222 or 49445, appears in the root
  listener snapshot. Recheck immediately before any approved test bind.

No live A5 case has run. The remaining inventory should enumerate child anchors
before any approved PF enable operation, since enabling PF can activate already
loaded rules. Never globally flush rules or disable PF to obtain a clean test.

## Confirmed address selection, not yet assigned

- Test server: the mini only. Client: the laptop only. No firewall changes on
  the Studio or laptop; no Tailscale, VPN, Wi-Fi or default-route changes.
- Selected test VIPs: `192.168.1.240` and `192.168.1.241` on the physical LAN.
  Matt replied, "confirmed, there is nothing on those ips", to the request to
  confirm they were unused and outside the DHCP pool. This records operator
  confirmation, not an independent router configuration audit. Three earlier
  ARP requests per address received no response. Repeat conflict checks
  immediately before use; neither address has been assigned by this task.
- Proposed advertised ports: 22 and 445 on the test VIPs, never wildcard host
  binds. Proposed private ports: 49222 and 49445, bound to exact VIPs. No TCP
  listener on either proposed private port appeared in the snapshot; recheck
  as administrator before use.
- Expected product anchor: `com.apple/squirrelops`. Do not assume it is empty
  merely because the app is absent. Inventory it first; abort on unexpected
  ownership or contents.
- Trusted test UID: the installer's validated `_squirrelops` account, pinned
  after allocation. It is currently absent. The known different UID is Matt's
  501. Do not assume the Studio's service UID is also valid on the mini.
- Limit all fault-injection listeners, captures, state cleanup and rule writes
  to the approved test endpoints. Never globally flush PF, disable it, or reload
  the main ruleset to make a test pass.

## Artifact and preparation sequence

Merged release source: `c6db88efbd77826cdc5c7e7b93eb377131835e89`, file-identical
to the accepted AI change `cb1f8e6`. The available current local-test package is
`build/test-artifacts/SquirrelOpsHome-2.1.0-ai-setup-20260928-local-test.pkg`.
Its checksum was rechecked during this preflight:

```text
3e8c0fc78befad3365fdbff5583d9f85c6b6fe01816b5863edbebeceaa4b8f5f
```

An earlier pre-guard package is retained as candidate 2, documented in
`2026-09-26-acceptance2-installer.md`. Its exact checksum, extracted rules,
installation behavior and bounded startup configuration must be verified
before choosing it for the older-rule migration test. Merely loading an old
rule fixture would not prove actual package-upgrade behavior.

Next steps, in order:

1. Complete the remaining read-only child-anchor/reference inventory and pin a
   fresh baseline before a live write. Matt has supplied PF status, top-level
   rules and root-owned listeners through Terminal. Do not request a password
   in chat or enable passwordless sudo.
2. Use the two operator-confirmed addresses. Pin endpoints, UIDs, artifacts and
   expected mutations in an executable dry-run plan. Account for the existing
   SSH/SMB listeners and inference services.
3. Prepare a root-only baseline backup and inverse operations. Keep Tailscale
   management independent of test VIPs. Cleanup must withdraw owned aliases
   and proxy ARP safely while retaining quarantine as needed; do not expose
   native wildcard services by removing protection before withdrawing a VIP.
4. Obtain approval for that exact install/test/restoration scope before any
   package installation, account creation or live PF mutation.
5. Execute and record all seven cases in the canonical A5 gate, including real
   protocol traffic, second ingress, changed/missing/ambiguous listeners,
   established state/reuse, quarantine and cleanup faults, multiple endpoints,
   older-rule package migration, and verified restoration. A root test harness
   must use reviewed helper logic with real kernel observations; injected
   command failures alone are not live acceptance.

## Actions actually taken

The initial pass performed Tailscale/SSH identity checks, unprivileged inventory,
two ICMP probes and six ARP probes. No remote files were transferred in that
initial pass. No installer,
account, service, interface, alias, PF rule, PF state or application setting was
changed. Existing local untracked acceptance notes were preserved.

Matt confirmed that he was on the mini. An SSH invocation of `osascript` with
`do shell script ... with administrator privileges` attempted to request native
authorization for read-only PF, listener and account inventory. It returned
immediately with `The administrator user name or password was incorrect.
(-60007)` and no inventory output. This does not establish that Matt entered an
incorrect password or that a dialog was shown. Privileged checks remain
unverified; no installation or firewall mutation was attempted.

Matt then ran the fallback read-only inventory in Terminal on the mini using
`sudo` and supplied the output summarized above. No password was sent in chat.
No installer, service, interface, alias, PF rule or PF state mutation was
performed. Matt subsequently confirmed the two proposed test addresses were
available. That confirmation does not authorize installation or firewall
mutation. The [bounded current-package setup proposal](2026-09-28-mini-install-test-scope.md)
records the normal startup effects and the next approval boundary.

## Local preparation after address confirmation

Both package digests were rechecked with `shasum -a 256`: the current AI-setup
package matched `3e8c0fc78befad3365fdbff5583d9f85c6b6fe01816b5863edbebeceaa4b8f5f`,
and candidate 2 matched
`7d3c8cfb5f48d8090f529fb0d94484935a7c1d1305cc02b8ee80d03425fc6853`.
This is artifact identity checking, not a new installed or upgrade test.

The current extracted package's isolated Python loaded `Settings`, applied
`_canonicalize_profile_runtime`, and exercised its `IPAllocator` with the range
240 through 241. Configuration validation succeeded; allocation returned
exactly the two selected addresses, and a second allocation returned an empty
list. Standard profile canonicalization sets a capacity of five but does not
expand the candidate address range. It also sets the classic listener limit
to three: setting `decoys.max_decoys: 0` would not disable those listeners at
startup. The setup proposal explicitly includes normal host listeners and LAN
discovery rather than claiming a VIP-only install. The Python command exited
zero with the existing Uvicorn/WebSockets deprecation warning. No sensor,
listener, VM, or network operation was started by that pure configuration and
allocator check.

The saved `fixtures/mini-a5-config.yaml` also passed the packaged model and
allocator checks. An initial direct `load_settings` probe stopped with
`PermissionError` when it tried to inspect the Studio's protected installed
data directory; it was not retried with elevated privileges. The packaged
`load_config` then passed with the supported `SQUIRRELOPS_SENSOR__DATA_DIR`
override pointing to a fresh disposable directory under `/private/tmp/`.
That test preserved the two-address candidate range and expected three classic
listeners without reading installed configuration or starting any subsystem.
It is not evidence of sensor startup or configuration layering on the mini.

Matt then approved the bounded current-package setup and protocol-test scope.
The [execution checkpoint](2026-09-28-mini-install-test-scope.md#execution-checkpoint-staged-awaiting-attended-administrator-command)
records the private staging directory, repeated read-only identity/conflict
checks, script guard tests, matching remote checksums and required local Terminal
command. Staging is complete; administrator execution and installation are not.
