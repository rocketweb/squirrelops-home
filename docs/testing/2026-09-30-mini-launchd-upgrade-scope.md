# Mini launchd-budget upgrade and restart acceptance

Attended local test only. Keep SquirrelOps closed on the mini. This does not
authorize a public release, A5 fault injection, or Little Snitch rule changes.

## Baseline and exact change

The failed ownership-fix restart has been cleaned up. Its reviewed root-owned
receipt is `/private/var/tmp/squirrelops-mini-restart-cleanup-results.v93amy48/status.json`,
SHA-256 `707399a27e4e66f62dedc90b9c8b7f6a9cb369dc8c45ba22ea9ffa7caa886042`.
It records stopped services/guest, no test aliases, native listener parity,
release of only the test's PF reference, and disabled PF.

- Target: `matt@100.108.203.27`, ARM64 macOS 27.0 build `26A428`.
- Existing installed receipt timestamp: `1790731448`. Old app, helper, guest,
  sensor entry point, classic orchestrator, Python and bounded configuration
  must match the ownership-fix package. The existing `_squirrelops` identity
  remains UID/GID 309.
- Candidate: `SquirrelOpsHome-2.1.0-launchd-budget-20260930-local-test.pkg`.
- SHA-256: `3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c`.
- Payload change: sensor launchd `ExitTimeOut=60`; package/uninstaller sensor
  removal polling allows 70 seconds. The app rebuild is pinned separately.
- Installer is unsigned and unnotarized, for local testing. The runner creates
  the existing single-use local-test opt-in, not a Gatekeeper bypass.
- Database recovery writes: zero. Deep rows 1 through 5 must already be active
  at `.240` on ports 445, 22, 11434, 1234, 8765. No second status restoration.
- Preserve all existing decoy IDs, types, bind addresses, ports and intended
  statuses, including the classic host listener. Counters/history produced by
  subsequent probes are retained as evidence.

Preflight requires fresh absence of product services, runtime and owned aliases,
unchanged native endpoints and interface addresses, PF disabled with zero states,
and the reviewed empty-policy grammar. It sends only six bounded ARP conflict
requests for `.240` and `.241`, then verifies root-private full installation,
configuration and data backups plus a consistent SQLite backup. Any drift stops
the run. Disk space is checked; no old backups are deleted to make room.

After printing the scope, require `UPGRADE AND TEST RESTART` before acquiring
a PF reference, installing or starting the product. The package's exclusive
attempt marker prevents silent retries. Return declines without installation.

## Acceptance sequence

1. Acquire and retain only this test's PF enable reference. Install exactly the
   pinned candidate using the regular installer scripts.
2. Verify installed app/helper/guest/Python/source/template hashes. The actual
   installed launchd plist must say `ExitTimeOut=60`, the expected sensor label,
   and `_squirrelops` user before readiness is accepted.
3. Require sensor health, all five Studio services and exact PF tag/UID guards.
   Verify all persisted decoy identities and intended statuses against the
   pre-upgrade snapshot.
4. Stop the sensor normally through launchd. Allow up to 70 seconds for job
   removal. Require complete runtime exit and alias withdrawal, no change to
   deep rows on shutdown, and preserved intent for every decoy.
5. Bootstrap the installed sensor once, repeat readiness and intent checks,
   then report `READY FOR TESTS` and observe for at most 20 minutes.
6. Only after readiness, permit the existing bounded laptop client from
   `192.168.1.7` via `wlp0s20f3`. It requires a fresh readiness snapshot for this
   exact package. Synthetic guest credentials stay in private files.

The client checks SSH banner, login and SFTP operations; SMB shares, login and
synthetic file operations; the three AI HTTP services; and refusal of direct
backend-port connections. It does not attack native mini SSH/SMB, use real
credentials, scan outside the approved VIPs, or run before server readiness.

Leave new Little Snitch or macOS connection prompts unanswered and report them.
Do not disable third-party filters, flush PF globally, or change native services.
Return in the attended Terminal stops early. Otherwise observation auto-stops.

## Teardown and inverse

Stop sensor and guest, verify runtime exit before withdrawing only owned test
aliases, clear only product PF rules, stop the helper, verify native endpoints
and empty-policy parity, then release only this session's PF reference. There
is no force-kill or global filter reset. An uncertain installer or surviving
guest retains protection and requires review.

Keep installation, accounts, configuration, data, history and private backups.
`cleanup.json` preserves successful teardown even when an earlier acceptance
failure is reported in `status.json`. No automatic downgrade or database rollback
is included. A reviewed restoration can use this attempt's `restore-manifest.json`
and `pre-upgrade.sqlite` with services stopped; applying it requires separate
approval and must preserve newer evidence. Keep the app closed after testing.

This tests one stopped-state package upgrade and a normal restart, not every
upgrade state or the separate A5 live PF fault/isolation matrix. Independent
review and remaining live gates are still required. The runner does not commit,
push, merge, tag, publish, or update the website.
