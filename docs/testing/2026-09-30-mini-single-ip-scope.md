# Approved mini-only .240 continuation

Matt approved narrowing the mini's test pool after diagnosis showed that the
Mac Studio owns `.241`. This continuation leaves the Studio, its sensor and its
aliases unchanged. It does not bypass conflict detection.

## Exact change, backup and inverse

Target host: `matt@100.108.203.27`, macOS 27.0 build `26A428`, ARM64.
Target file: `/Library/SquirrelOps/sensor/config.yaml`, UID/GID 309, mode 0600.
The existing receipt remains `1790731448`; product services, guest and owned
aliases must be absent before any change.

```diff
 scouts:
   virtual_ip_range_start: 240
-  virtual_ip_range_end: 241
-  max_virtual_ips: 2
+  virtual_ip_range_end: 240
+  max_virtual_ips: 1
```

- Original file SHA-256: `6e210567e3baae3950d91153b44090876ae6978b2a67677b1690aaf5c8f02330`.
- Revised file SHA-256: `6b492246632eee7bc3975e84fc7c75699d3dcdfc15f2ec542ec673ab243b4bd8`.
- Only those two YAML values change. All other bytes are preserved.
- No database rows, statuses, credentials, counters or history are rewritten.

Before installed-file mutation, verify host/account/receipt/payload identities,
stopped state, native listener parity, disabled PF with zero states and reviewed
empty policy. Perform bounded ARP conflict checks only for `.240`. Any answer
stops startup and records its address/MAC in sanitized `arp-check-*.json`.

Validate the proposed configuration through the product's real layered loader.
If persisted settings override the single-IP pool, stop without changing them.
The profile can set a broader capacity ceiling, but the allocator's candidate
range still contains only `.240`; local tests check that boundary explicitly.

Create and verify the existing full installation/data backup and a consistent
SQLite backup, then print the change and ask for `USE 240 AND TEST RESTART`.
Claim the package's single-use installation attempt before changing the file.
Create additional root-private `config-before.yaml`, `config-change.json`, and
`config-inverse.txt` evidence. Verify the old file's exact hash, regular/single-link
identity, owner, mode and absence of extended ACLs. Write a same-directory
temporary file with the original owner/mode, flush it, recheck stopped state
and the original inode/content, then atomically replace the file and verify it.

If anything fails, preserve the evidence and report whether configuration
replacement was started and verified. Do not automatically restore the old
overlapping pool or continue installation. There is no force/reset switch.
A separately reviewed inverse requires services/guest stopped, no owned aliases,
current configuration matching the new hash, the old backup matching its hash,
and resolution of `.241` ownership before restoring/restarting. Never overwrite
new operator edits or roll back newer database evidence.

## Candidate and acceptance

Use the existing ARM64 local-test installer, not a rebuild:
`SquirrelOpsHome-2.1.0-launchd-budget-20260930-local-test.pkg`, SHA-256
`3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c`.
It is unsigned and unnotarized. The runner uses its existing single-use
local-test opt-in; it does not disable Gatekeeper.

After the config change verifies, acquire only the test's PF enable reference
and invoke Installer. Verify installed hashes, actual launchd `ExitTimeOut=60`,
sensor health, all five Studio services on `.240`, and exact PF UID/tag guards.
Require preserved identity and intended status for every existing decoy.

Stop the sensor normally, allow the tested 70-second job-removal check, require
guest exit, alias withdrawal and unchanged intended state, then bootstrap the
installed sensor once and repeat readiness. The classic `.115:60556` listener
is preserved, not a client-probe target.

Only `READY FOR TESTS` permits laptop probes from `192.168.1.7` through
`wlp0s20f3`. The client checks the exact candidate, fresh readiness, verified
configuration, and `mini-single-ip-240` scope before any traffic. `.241` is not
a valid guest, mapping, ownership entry, test alias or packet-capture target.
Synthetic guest credentials stay in private files. SSH/SFTP/SMB synthetic file
operations, AI HTTP service checks and direct backend-port refusal remain the
same bounded test set. This does not disable normal sensor discovery or change
its native LAN subnet.

The observation window is at most 20 minutes; Return stops early. Leave new
Little Snitch/macOS connection prompts unanswered. No third-party filter rules,
global PF configuration, native mini services or Studio services are changed.

## Teardown and release boundary

Stop the mini sensor/guest and verify exit before withdrawing only its owned
`.240` alias. Clear only the mini product's PF rules, stop its helper, verify
native endpoints and baseline policy, then release only the saved test reference.
Unknown ownership or surviving runtimes retain protection and stop for review.
Never force-kill a guest or reset PF globally.

Keep the installed package, narrowed configuration, account, data and all
backups. `cleanup.json` preserves successful teardown even if another acceptance
step failed. Keep the mini app closed afterward. A public release, independent
review and the separate multi-address A5 fault/isolation matrix remain separate
gates. No commit, push, tag, publication or website update is included here.
