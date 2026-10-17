# Proposed post-reboot mini upgrade and acceptance

Status: prepared scope, awaiting confirmation of this next mutation/test phase.
Do not use the earlier runners: their boot/OS/cleanup assumptions are stale.
The reboot recovery is complete as observed, not a successful upgrade test.

## Exact target and artifact

- Mini only: `matt@100.108.203.27`, LAN `192.168.1.115`, ARM64, macOS build
  `26A434`, current observed boot `1790777754`.
- Current sensor/helper jobs are disabled and unloaded. No product runtime or
  test alias was observed. PF is disabled with zero states; Apple's concrete
  anchors are empty except for their anchor declarations.
- Preserve the root-owned stale ledger entry `192.168.1.240|en0` for the
  installer's guarded retirement, not ad-hoc deletion.
- Existing unsigned/ad-hoc local-test package:
  `build/test-artifacts/SquirrelOpsHome-2.1.0-launchd-budget-20260930-local-test.pkg`.
- SHA-256: `3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c`.
  No new rebuild or signed/notarized release is implied.

## Planned sequence

1. Freshly verify host/boot, receipts/payloads, stopped state, both disabled
   overrides, live database health and the six saved decoy identities/statuses,
   current config, exact ledger ownership/content, native services and full
   concrete PF baseline. Use fresh durable installation/config/plist/ledger and
   consistent database backups; never reuse the old temporary cleanup receipt.
   Read the live database as the service UID, not root. An occupied `.240`
   fails the ordinary ARP conflict check; do not probe or claim `.241`.
2. Preview and apply exactly two existing approved YAML changes after backup:
   `scouts.virtual_ip_range_end: 241 -> 240` and
   `scouts.max_virtual_ips: 2 -> 1`. Target:
   `/Library/SquirrelOps/sensor/config.yaml`, UID/GID 309, mode 0600.
   Validate the effective layered settings. No explicit SQL edits, status
   recovery, credential reset or history rewrite is included.
3. Acquire only a fresh test PF enable reference while preserving the existing
   Apple anchors. Restore enablement for exactly the sensor/helper at the
   installation boundary, with no intermediate bootstrap of the old sensor.
   Use the package's one-time local-test opt-in, not a Gatekeeper bypass.
   Installer owns its existing scoped network-state retirement and payload
   replacement. Verify hashes, launchd ownership and actual `ExitTimeOut=60`.
4. Verify sensor readiness and five deep services on `.240`; preserve the
   existing `.115:60556` host listener and all six decoy identities/intent.
   Exercise one normal sensor stop/restart with the new shutdown budget.
   Verify guest exit, alias withdrawal, policy cleanup and intent preservation
   before restart; a survivor stops the test with protection retained.
5. Only after fresh `READY FOR TESTS`, run the previously scoped bounded laptop
   checks from `192.168.1.7` against `.240`: SSH/SFTP, SMB synthetic file
   roundtrip, the three synthetic AI endpoints and direct backend refusal.
   Maximum observation is 20 minutes. No native mini service, `.241` or Studio
   probe. Guest credentials stay private. No Little Snitch rule decisions.
6. Stop the mini product runtime; verify guest exit before withdrawing owned
   aliases/product rules. Stop the helper, restore both disabled overrides,
   preserve unrelated/native services and Apple policy, and release only this
   run's PF reference. Keep the installation, `.240`-only config, data and all
   backups. Produce durable results, including failures and cleanup state.

## Failure, inverse and release limits

No automatic data downgrade, broad config restore, force-kill, PF reset, old
reference-token reuse, Studio operation or third-party firewall change.
If a partial install or surviving runtime prevents cleanup, stop with evidence
and remaining protection retained; no blind retry. Restoring older payloads or
data is a separate reviewed recovery, not the automatic inverse. The old pool
must not be restored or started while the Studio owns `.241`.

Configuration inverse requires the verified pre-change backup, matching current
new config, stopped runtime and separate approval after resolving `.241`.
The two enable operations are reversed by the same two disabled overrides only
at a verified safe cleanup boundary; disabling alone does not stop a loaded job.

This would establish recovered-host install/restart/protocol acceptance, not
safe unattended upgrade from a running old five-second daemon, the separate A5
multi-address isolation/fault matrix, Developer ID signing/notarization, merge,
publication, website promotion or final release readiness. Those remain separate
gates. No commit, push, install or release has occurred in preparing this scope.
