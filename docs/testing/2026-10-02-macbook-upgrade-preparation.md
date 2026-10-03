# MacBook 2.0.3 to 2.1 upgrade preparation

Date: October 2, 2026. Status: attended upgrade completed and user UI check
accepted. See the [result](2026-10-02-macbook-upgrade-result.md). The preparation
and pre-upgrade observations below are retained as historical evidence.

## Approved scope and baseline

Matt approved backup and a data-preserving in-place upgrade on the MacBook at
192.168.1.97. This does not authorize an uninstall, wipe, manual PF reset,
Little Snitch changes, changes to the Studio or resuming Mini work.

Pre-upgrade SSH observations:

- macOS 26.6.1, build 25G76, ARM64.
- App version/build and both package receipts are 2.0.3.
- Sensor and helper system jobs are running. The loopback health endpoint
  returned `status: ok`; this is not a full protocol acceptance test.
- App signature metadata names Rocket Web Inc, Team ID PSQ5HK5U65.
- en0 is 192.168.1.97 with hardware address `ae:29:0a:e5:cc:c5`.
- Existing lo0 aliases: .203, .204, .205, .207 and .212 on 192.168.1.0/24.
- Sensor data is mode 0700, UID/GID 309. The SSH user cannot read its database.
- Administrative access requires an attended password. No password was requested
  in chat, stored or transmitted by the agent.

## Candidate and local verification

Source: `release/2.1-docs-a5`, HEAD
`00239f5d07673dab5ed5dc402ec3c0fa134ee9a8`, plus the three reviewed-in-session
account-cleanup script corrections and their regression tests. These new
changes are not yet committed or independently reviewed.

The normal package builder compiled the ARM64 app/helper/guest with the CLT
macOS 26.5 SDK and rebuilt its standalone, hash-locked Python runtime. The
retained ARM64 guest passed the verifier; its source is unchanged from the
previously tested resolver candidate. This reuse is for local testing only.

Package: `build/pkg/output/SquirrelOpsHome-2.1.0.pkg`.
SHA-256: `669e4b2b5762f819b4b07c4f5cddc5b6797bae4cd7519282280ee049d3533c17`.

This is explicitly a local-test installer with ad-hoc-signed binaries, not a
Developer ID signed/notarized public installer. Its app uses a separate test
Keychain namespace and may require local enrollment again. Existing release
credentials are not deleted or read by this test build.

Verified in this pass:

- 126 package, security and supply-chain tests passed in 9.07 seconds.
- Full sensor suite: 2,464 passed, three explicit opt-in skips and three
  dependency warnings in 92.70 seconds. No installed service was started.
- Extracted app preinstall, sensor postinstall and uninstaller hashes match
  the current corrected source exactly.
- Extracted app passes deep/strict code-signature verification (ad-hoc).
- Isolated embedded sensor imports from the extracted payload and reports 2.1.0.
- Two real-signal shutdown tests against the packaged Python passed.
- The new backup/upgrade fixture has 15 passing checks. Its existing shared
  backup/reset/resume helpers have 30 passing checks. These are not a live upgrade.
- A failing-first regression requires the live SQLite source to be opened by
  `_squirrelops`, not the root parent. The corrected worker passes a real live-WAL
  snapshot test, preserving committed WAL data and original file ownership.

Build log and expanded payload are retained under
`build/test-artifacts/macbook-upgrade-20261002/`.

## Attended procedure

Quit the SquirrelOps desktop app on the MacBook, without manually stopping its
sensor or helper. Run the staged `start-macbook-upgrade.sh` with sudo there.
The bootstrap copies and checksum-verifies both installers and its Python
scripts in a root-private directory, then uses the candidate's private Python.

Before invoking Installer, the runner verifies the exact host, OS and installed
2.0.3 baseline. It creates a root-private recovery archive under
`/Library/SquirrelOps/acceptance-backups/macbook-upgrade-20261002.*` and verifies
copies of the existing app, runtime, helper, launch plists, config and durable
data. SQLite uses its consistent online backup API and an integrity check;
raw WAL/SHM copies are not used as recovery images. Live logs and transient
sockets are excluded. The original signed 2.0.3 package is retained for a
reviewed recovery, along with a restore manifest and instructions.
The SQLite reader runs under the sensor UID and streams a consistent in-memory
snapshot into a root-private file. This prevents read-side SQLite coordination
files from being created as root in the live sensor data directory.

The original ten-minute shared SSH connection ended before transfer. Matt
reopened it, and all inputs were staged in the mode-0700 directory
`/Users/matt/squirrelops-macbook-upgrade.woRqUgSf` on the MacBook. All five
installer/script hashes matched their local originals. Remote shell syntax
and the runner's non-mutating `plan_only` mode passed. The MacBook still
reported 2.0.3, build 25G76, ARM64 before the attended operation.

Historical attended command, **already completed; do not rerun**:

```bash
sudo /bin/bash /Users/matt/squirrelops-macbook-upgrade.woRqUgSf/start-macbook-upgrade.sh
```

The installer, not the operator, handled the sensor and helper shutdown.

Private pre/post evidence includes product launchd and PF state. There are no
manual PF writes, SQL edits, configuration changes or synthetic client probes.
The approved installer performs its normal product shutdown and replacement.
PackageKit is not force-terminated on a harness timeout. Saved device identities,
user names/notes, trust records, decoy definitions, alert identities, paired
clients and planted credentials are compared after startup. New records are
allowed. Config content must remain identical, previously active decoys must
remain active, and the count of PF translations must not decrease. Unconditional
`rdr pass` rules must be absent from the new product anchor.

Sanitized progress contains phase/counts only under
`/private/var/tmp/squirrelops-macbook-upgrade.*/status.json`. Private data,
credentials, account metadata and command logs remain in the recovery archive.

If any step fails, retain evidence and review before retrying. There is no
automatic uninstall, downgrade, networking reset or silent restoration. Recovery
must never run 2.0.3 against a migrated 2.1 database, or blindly restore a PF
reference/alias ledger. The old database and app are retained privately for that
separately reviewed recovery.

## Remaining acceptance

The [result](2026-10-02-macbook-upgrade-result.md) records the completed upgrade,
record preservation and Matt's UI acceptance. LAN decoy behavior on this MacBook
was not exercised. Pre/post PF snapshots alone do not prove retained-state
migration; that requires correlating actual old connection evidence. Final
release acceptance still applies to the exact independently reviewed, signed
and notarized package. This local candidate does not waive that gate.
