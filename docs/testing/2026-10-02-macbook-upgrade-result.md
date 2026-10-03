# MacBook in-place upgrade result

Date: October 2, 2026. Result: **2.0.3 to 2.1.0 local-test upgrade passed;
user UI check accepted**. This is not final signed-installer or complete A5
acceptance, and no release was published.

## Host, artifact and authority

Matt approved a backed-up, data-preserving upgrade of the existing MacBook
installation at 192.168.1.97. No uninstall or wipe was authorized or performed.
The host is ARM64, macOS 26.6.1 build 25G76, en0 hardware address
`ae:29:0a:e5:cc:c5`. The Mini remained outside this operation.

Installed candidate SHA-256:
`669e4b2b5762f819b4b07c4f5cddc5b6797bae4cd7519282280ee049d3533c17`.
Source, local tests and staging hashes are recorded in the
[preparation report](2026-10-02-macbook-upgrade-preparation.md).
This installer uses ad-hoc-signed binaries and is not the public release artifact.

Matt ran the exact pinned attended command. Its final output reported verified
backup, successful Installer completion, healthy restored sensor and preserved
saved records. A subsequent SSH read independently confirmed app version and
both package receipts at 2.1.0, the sensor and helper running under launchd,
and the loopback health response `status: ok` with uptime 273.31 seconds.
The installed uninstaller's SHA-256 matches the corrected source:
`1f2e64b73b20db7cbacf5caf9ac0d79053c7a1db754684dbc96b4e6a9f3166b6`.

## Preservation and runtime results

The pinned root-run comparison produced these sanitized results:

| Records | Before | After | Existing compared rows preserved |
| --- | ---: | ---: | --- |
| Devices | 60 | 60 | Yes |
| Device trust | 59 | 59 | Yes |
| Decoys | 22 | 27 | Yes |
| Alerts | 9 | 9 | Yes |
| Paired clients | 0 | 0 | Empty baseline, not populated-pairing migration coverage |
| Planted credentials | 26 | 31 | Yes |

Checks include saved device MAC/user-name/notes fields, trust decisions, decoy
identity/type/address/port, alert identity/type/creation time, and planted
credential identity/type/value/decoy association. This is not a byte-for-byte
comparison of all mutable database columns. Configuration content was unchanged.
The runner also required previously active decoys to remain active after startup.
Five additional decoy and credential records existed after startup. The later
[saved-evidence review](2026-10-02-saved-release-evidence-result.md) identifies
the five new decoys as Studio deep services on .214. It does not independently
identify the additional credential values or kinds.

The product anchor had 15 unconditional `rdr pass` rules before the upgrade.
Afterward it had 20 translations and zero unconditional `rdr pass` rules.
These observations establish rule replacement, not complete packet-level
containment or retained-state invalidation. No synthetic client probes were run
by this upgrade fixture.
The saved-evidence review confirms 20 guarded UID pass rules and 20 matching
tag references after the upgrade. Both saved PF state listings were empty, so
this run has no existing connection state whose invalidation can be tested.

Read-only interface inspection afterward found .204, .205, .207, .212 and .214
on lo0. The earlier .203 alias was absent. Saved decoy identity rows were retained;
the exact lifecycle reason for this address-set change was not known at that
point. The later read-only check finds .203 present again, alongside all four
other original aliases and new .214. Both saved .203 rows remain active and
unretired. There is no persistent missing alias in the later observation, but
the cause and duration of the temporary absence are not established.

After being asked to open the app and inspect connectivity and existing data,
Matt replied **"looks good"**. Record that as the user UI check, not as an
independent automated UI inspection or proof of an old Keychain-item migration.

## Retained evidence and recovery

On the MacBook:

- Private recovery archive:
  `/Library/SquirrelOps/acceptance-backups/macbook-upgrade-20261002.jikh0k2n`.
- Sanitized result:
  `/private/var/tmp/squirrelops-macbook-upgrade.hz8cej6y/status.json`.
- Staged inputs:
  `/Users/matt/squirrelops-macbook-upgrade.woRqUgSf`.

The sanitized status was copied locally to
`build/test-artifacts/macbook-upgrade-20261002/installed-status.json`.
Its SHA-256 is
`a5bad27ab28566eff5353e593fedcbadc108dc6e2491c7b290ae59386e9ee15f`.
Private databases, credentials and account metadata were not exported.

The archive retains the verified old app/runtime/config/durable data,
consistent pre/post SQLite snapshots, installer log, PF evidence, restore
manifest and official original 2.0.3 recovery package. The fixture verified
these during the attended run; the agent did not subsequently open the
root-private archive over SSH. No automatic rollback was attempted.
Do not rerun the upgrade bootstrap or open a migrated database with 2.0.3.

## Remaining release boundary

- Obtain disposition of the documented A5 kernel/filter-attribution limits and
  the missing upgrade-with-existing-state coverage. The saved state lists are
  empty, and the .203 alias has reappeared; those facts are now correlated, not
  pending private export. Do not repeat completed controls without cause.
- This MacBook run did not perform LAN protocol or containment tests. Prior
  Mini results retain their existing scope; they do not become MacBook results.
- Commit/review/merge the latest installer fixes and release follow-up; verify
  CI for the exact source that will be built publicly.
- Accept the exact Developer ID signed, notarized final installer before its
  separate publication step. Existing local-test acceptance does not waive it.
