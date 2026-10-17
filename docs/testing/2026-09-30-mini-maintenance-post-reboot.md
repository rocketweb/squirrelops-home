# Mini post-reboot inspection

Status: observed stopped-state checks passed; the attended SQLite quick check
passed and the expected six decoy identities/statuses remain. Receipt and
ownership metadata and the complete reported concrete PF tree have been supplied
by Matt. Read-only recovery inspection is complete for this observed baseline.
Fresh validation/backups at the upgrade boundary remain required. No upgrade,
restart, LAN probe or release follows automatically from this result.

Matt reported restarting after the maintenance-preparation instructions. Fresh
read-only SSH inspection of `100.108.203.27` returned:

- Host `Matts-Mini-2.localdomain`, macOS build `26A434`.
- New boot epoch `1790777754`, replacing `1790766531`.
- `launchctl print-disabled system`: both `com.squirrelops.sensor` and
  `com.squirrelops.helper` are disabled.
- `launchctl print` for each exact system job: service not found.
- `ps -axo uid=,pid=,ppid=,comm=` filtered for UID 309, SquirrelOps and
  Virtualization: no matching processes.
- `ifconfig -a`: mini LAN `.115` and Tailscale `100.108.203.27` remain; no local
  `.240` or `.241` alias. ARP inventory showed neither test address.
- Both installed package receipts remain version 2.1.0, install time
  `1790731448`. The new shutdown-budget candidate has not been installed.
- Both launch plists remain root:wheel, regular single-link files, mode 0644.
  The installed sensor plist still lacks `ExitTimeOut`.
- Sensor data directory remains UID/GID 309, mode 0700. Helper state and
  acceptance-backup directories remain root:wheel, mode 0700.
- Installed Python SHA-256 remains
  `d2555cd22a33506826f9eb069bb13fb0cc41303c7da41da5b761967d616f4147`.
- Noninteractive sudo requires a password. The agent has not read the new
  private pending-reboot receipt, the live database or alias ledger, or PF state.

The disabled-services hold worked across this reboot based on the current
launchd/process observations. This does not prove graceful old-version shutdown,
database integrity, removal of a stale ownership ledger, or installer upgrade
acceptance. Do not reuse pre-reboot PF references or historical cleanup receipts.

Next: attended read-only root inspection. Keep the mini app closed. Do not rerun
the old preparation/recovery scripts or enable either service. No Little Snitch,
Studio, laptop, configuration, database or packet-filter changes were made.

## Subsequent attended root evidence

Matt supplied the requested output:

- PF reports disabled, zero states and zero counters. The main rules shown
  contain Apple's wildcard filter/scrub/NAT/redirect anchor declarations.
- Top-level concrete anchor listing contains `com.apple`.
- Direct reads of `com.apple/squirrelops` filter and translation rules report
  `DIOCGETRULES: Invalid argument`. This is not proof of an empty product anchor.
  The immediate parent anchor's concrete child list and own rules still need
  to be inspected before enabling PF for any test.
- The live database is a regular, single-link file, UID/GID 309, mode 0644,
  within the previously verified service-owned 0700 directory. This is expected
  metadata, not an integrity result.
- The root-owned, single-link 0600 ownership ledger retains exactly
  `192.168.1.240|en0`, despite the observed absence of live aliases/processes.
- The preparation receipt is retained at
  `/Library/SquirrelOps/acceptance-backups/mini-reboot-20260930.7KofaDMk/pending-reboot.json`.
  It records the old boot `1790766531`, both disabled jobs and
  `stopped_state_verified: false`, as expected for a pre-reboot receipt. It is
  not being reused as current stopped-state authority.

A subsequent fresh read-only SSH check still finds boot `1790777754`, both
disabled overrides, no matching runtime processes and no `.240`/`.241` alias.
The mini's system SQLite reports version 3.54.0.

## Existing installer recovery path

Source inspection shows the app preinstall validates the root-owned ledger,
checks tracked addresses are not assigned to physical interfaces, verifies
loopback/proxy ARP absence, scopes cleanup to `com.apple/squirrelops`, rechecks
service quiescence and unchanged ownership, then retires the ledger. A stale
claim is a conservative ownership record by design; do not manually delete it.
This code path has not yet been executed on this post-reboot state.

The extracted candidate app preinstall is byte-identical to the reviewed source
(`cmp` succeeded). Candidate SHA-256 remains
`3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c`.
From `sensor/`, `.venv/bin/python -B -m pytest tests/unit/test_pkg_network_lifecycle.py -q`
passed all 40 tests.
These are local regression checks, not native post-reboot installer acceptance.

Next evidence needed: the concrete `com.apple` child listing and filter/NAT
rules, and a read-only SQLite quick check plus the bounded decoy identity/status
columns under the service account. No secrets/configuration contents are
requested. Do not run the old single-IP acceptance script: it still requires a
historical temporary cleanup receipt and does not understand this disabled hold
with a stale ledger.

## SQLite quick check and intended state confirmed

Matt's attempted multi-command paste produced only the concrete child listing:
`com.apple/200.AirDrop` and `com.apple/250.ApplicationFirewall`. No rule contents
or database result could be inferred from that output. Do not clear either
existing anchor or treat its name as proof of empty rules.

The subsequent single-line SQLite command ran as `_squirrelops`, using the system
CLI in read-only mode and an empty initialization file. Matt supplied:

```text
SQLITE_CHECK_STARTED
ok
1|deep|192.168.1.240|445|active
2|deep|192.168.1.240|22|active
3|deep|192.168.1.240|11434|active
4|deep|192.168.1.240|1234|active
5|deep|192.168.1.240|8765|active
6|dev_server|192.168.1.115|60556|active
```

This establishes a successful `PRAGMA quick_check` and the expected saved decoy
identity/status columns. It does not establish all database invariants or live
service health. Persisted `active` intent is compatible with the intentionally
disabled/unloaded services. No status repair is indicated by these results.

Next: a single attended read-only shell invocation to list concrete children
and filter/NAT rules for `com.apple` and its two reported children. This avoids
assuming that the previous multi-command paste ran completely. Unexpected
children or rules require review, not PF reset. Keep the app closed and both
product services disabled. No product, network or database changes were made.

## Concrete PF tree inspection completed

Matt subsequently ran the one-line attended command in full. Its output shows:

- `com.apple` has exactly the two reported children, `200.AirDrop` and
  `250.ApplicationFirewall`.
- Its filter rules are only `anchor "200.AirDrop/*" all` and
  `anchor "250.ApplicationFirewall/*" all`; its NAT/redirect rule output is empty.
- Both children have empty child listings, empty filter rules and empty
  NAT/redirect rules. There are no `DIOCGETRULES` errors in this concrete walk.
- The repeated ALTQ messages accompany the successful concrete read output;
  no ALTQ change or suppression is necessary for this recovery.
- Combined with the earlier root anchor listing and rules, no concrete
  SquirrelOps anchor appears in the observed tree. The earlier direct reads of
  that nonexistent name are not being used as emptiness evidence.

The packet filter was reported disabled with zero states. This is an observed
post-reboot baseline, not permission to enable, clear or replace system policy.
The two Apple anchor declarations must be preserved through any future test.

The candidate package was rehashed after this output and still matches
`3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c`.
No product/remote mutations were performed. The next proposed phase is recorded
in [the post-reboot upgrade scope](2026-09-30-mini-post-reboot-upgrade-scope.md).
