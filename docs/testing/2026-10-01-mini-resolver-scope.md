# Proposed resolver-fix acceptance scope

Prepared only. Approval to build the resolver fix is not approval to install
it or start another live window. This document defines the next exact scope.

## Targets and artifact

- Mini: `matt@100.108.203.27`, ARM64, macOS build `26A434`, boot `1790777754`.
- Client: Linux laptop `192.168.1.7`, route through `wlp0s20f3`.
- Test virtual host: `192.168.1.240` only. No Studio or `.241` operations.
- Candidate: `SquirrelOpsHome-2.1.0-guest-resolver-20261001-local-test.pkg`.
- SHA-256: `47774088cd9eadc5aaddf38949e00a8b8f6eeb56c2192a5a72830d06d84a8aec`.
- Unsigned local-test installer; payloads are ad-hoc signed, not notarized.

## Approved actions if confirmed

1. Stage the pinned inputs without executing them. On attended startup,
   verify the prior SMB cleanup receipt, the stopped/disabled jobs, seven
   saved decoys, unchanged configuration, native listeners, old payloads,
   current boot and empty/disabled PF baseline. Stop on any mismatch.
2. Make and verify root-private durable backups of the current installation,
   configuration, launch state and a consistent SQLite snapshot. Display the
   exact confirmation before product changes.
3. Check `.240` for an ARP conflict. Acquire only this run's PF reference,
   temporarily enable the two product jobs and install the pinned package.
   Verify installed payload hashes and guest manifest, kernel and initramfs.
4. Verify startup and perform one normal sensor stop/start. Check guest exit,
   alias withdrawal, policy cleanup, preserved decoy intent and resumed
   classic listeners. No force-kill or fallback networking reset.
5. Run one bounded client attempt from `.7`: SSH banner; explicit anonymous
   SMB share listing within five seconds; the three advertised AI endpoints;
   five private backend denial probes and `.240:5900` denial; one wrong
   password per SSH/SMB; synthetic `buildbot` login; SFTP and SMB read, unique
   synthetic upload, download and deletion. Later stages require earlier
   gates to pass. No real credentials, cached Kerberos login or brute force.
6. Collect scoped packet metadata, fixed-vocabulary relay diagnostics, alert
   and connection-count evidence. Raw private evidence and synthetic login
   data stay private. No payload capture or unrelated host probes.
7. After the client, the operator presses Return. Stop product services and
   guest, withdraw owned aliases, verify native listeners and empty product
   policy, restore both jobs disabled, release only this run's PF reference
   once, and verify the final receipt. The window also expires after 20 minutes.

## Data preservation and exclusions

Saved rows 1 through 7 are preserved. Configuration remains `.240` only,
SHA-256 `6b492246632eee7bc3975e84fc7c75699d3dcdfc15f2ec542ec673ab243b4bd8`.
No SQL recovery, config edits or deletions of existing files are authorized.
The test deletes only its uniquely named synthetic guest uploads. Normal
sensor discovery and automatic host-listener deployment can run; new classic
listeners are retained and reported, not silently removed.

Do not change Little Snitch rules or global PF rules. Verify that the existing
guest-only incoming TCP allowance from `.7` is active before starting. Leave
new or mismatching filter prompts unanswered and report them. Both apps stay
closed; the Studio is untouched. Native SSH, SMB, VNC, Ollama and unrelated
launchd jobs are preserved.

## Failure and inverse operation

The durable backup contains `restore-manifest.json` and the consistent
pre-upgrade SQLite snapshot. It preserves the old installation and data for
reviewed restoration. There is no automatic data downgrade. A rollback to the
old package/database requires a separate exact recovery plan and approval.

Normal cleanup reverses only this run's temporary job activation, aliases,
product rules and PF reference. The newly installed package, saved decoys,
test evidence and backups remain. If cleanup cannot verify safe shutdown,
retain protection and evidence; do not repeat a reference release or reset PF.
The exclusive server claim and client results file prohibit an automatic rerun.

No commit, push, merge, signing, notarization, GitHub release or website
publication is included. Successful live acceptance is a separate state from
public release readiness.
