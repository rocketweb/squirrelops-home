# macOS 27 installer recovery candidate

Date: September 25, 2026. Host: Matt's arm64 Mac Studio, macOS 27.0 (26A428).

## Confirmed failure

The 2.0.3 installation at 09:31 and the September 4 local-test 2.1 installation at 09:35 both failed in the sensor preinstall script with:

```text
Error: unable to open database ".../backups/preinstall.../data/squirrelops.db": unable to open database file
[preinstall] Rollback database verification failed; aborting upgrade.
```

The 2.1 attempt consumed its local-test opt-in successfully. Its unsigned-package warning was not the terminating error. The 2.0.3 attempt had already stopped the services, removed the existing 2.1 app bundle, and forgotten its app receipt before the sensor backup check failed. The sensor receipt still reported 2.1.0 afterward.

With this Mac's `/usr/bin/sqlite3` version 3.54.0 (`8fa8248e...aapl`), the existing `-cmd 'PRAGMA trusted_schema=OFF;'` plus positional `.backup` invocation returned exit status zero without creating the destination. A disposable database reproduced the exact missing-backup failure; no private installed database was needed for diagnosis.

A second reproduced case affects standalone WAL-mode files: opening one read-only with no WAL/SHM sidecars returned error 14. This affects both freshly created backup files and a source database after a clean shutdown. SQLite documents the sidecar and immutable-mode requirements for [read-only WAL databases](https://www.sqlite.org/wal.html#read_only_databases).

These results diagnose the installer failure. They do not establish why the previously installed application stopped working after the OS upgrade.

## Fix

Only the sensor package preinstall script changes in the recovery installer:

- Send the trusted-schema setting and `.backup` through the same standard-input stream, avoiding the observed CLI argument behavior.
- Require a nonempty regular destination file before proceeding, even if SQLite exits successfully.
- For an already quiesced and quarantined source with no WAL file, use an immutable read-only connection. If a WAL exists, retain normal read-only handling so committed WAL data is included.
- Normalize the newly created private backup to DELETE journal mode, close that connection, and remove its now-unused journal sidecars.
- Retain the read-only integrity check, no-symlink policy, private snapshot permissions, and failure checks before retiring the installed runtime.

No decoy responses, banners, authentication, networking policy, app binary, sensor payload, or dependency versions change. The source database's bytes are preserved by the regression cases. No installed configuration or database was edited during this work.

## Verification

The engineering-constraints workflow required a reproduced failure before the fix. The first real snapshot tests failed for both DELETE and WAL input with the same missing-backup error, while corrupt/symlink rejection passed. An additional clean-shutdown WAL case then reproduced the sidecar failure and is included in the final tests.

Final command, run from `sensor/`:

```bash
.venv/bin/python -m pytest \
  tests/unit/test_supply_chain_security.py \
  tests/unit/test_package_security.py \
  tests/unit/test_pkg_network_lifecycle.py \
  tests/unit/test_pkg_sqlite_backup.py -q --tb=short
```

Result: **111 passed in 7.28 seconds**. Bash syntax, Ruff for the new regression file, and `git diff --check` passed.

The six new cases execute the actual snapshot function with real macOS SQLite and filesystem tools, translating only root ownership to the test user's ownership. Four cases cover DELETE/WAL and cleanly closed/open writers; they verify retained rows, inclusion of committed WAL data, source-byte preservation, standalone read-only verification, and mode 0600. Two rejection cases cover corrupt and symlinked source databases. These tests are included in the macOS package CI selection.

Evidence is retained in [evidence/2026-09-25-macos27](evidence/2026-09-25-macos27). The final authoritative regression XML is `macos27-package-controls-final.xml`. Earlier red and intermediate green runs are retained separately.

## Exact recovery artifact

[SquirrelOpsHome-2.1.0-macos27-recovery-20260925-local-test.pkg](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/build/test-artifacts/SquirrelOpsHome-2.1.0-macos27-recovery-20260925-local-test.pkg)

- Architecture: arm64.
- Version: 2.1.0.
- Package SHA-256: `cff6a89c4658f28fcda70bf4c111e5c43040241821244070ecf902478b1bf168`.
- Original September 4 package SHA-256: `d4331be9d2b407786d6f7a444f17fbf4ab742f08faa5f44a0d13c4eca4158555`.
- Unsigned local-test installer, retaining the original ad-hoc-signed app components and local-test identity.
- Not installed or live-accepted yet.

This artifact was built by expanding the verified September 4 installer with `pkgutil --expand`, replacing `sensor.pkg/Scripts/preinstall` with the fixed source, and flattening to a new filename. It was expanded again for verification. A recursive comparison with a fresh expansion of the original showed exactly one changed file: the sensor preinstall script. Both app and sensor compressed payloads, BOMs, metadata, distribution settings, and all other scripts are unchanged. The new extracted preinstall matches the tested source byte for byte.

The app was not recompiled. The upgraded Xcode tools currently require acceptance of their license before compilation; no license acceptance was performed. Repackaging this installer-only fix preserves the tested binaries and avoids an unrelated rebuild.

## Retry instructions

Create a fresh one-time opt-in because the failed attempt consumed the earlier one:

```bash
sudo /usr/bin/install -o root -g wheel -m 600 /dev/null /var/db/com.squirrelops.allow-local-test
```

Then open the recovery package linked above. Do not reuse the September 4 package. Successful installer completion, restored app identity, sensor health, and Studio/LAN operation still need checking on macOS 27. The package version remains 2.1.0, so identify this candidate by filename and checksum.

The original failed upgrade's early app removal remains a separate installer-transaction limitation: if another preinstall stage fails, automatic restoration of the app is not implemented by this narrow SQLite fix. No uninstall, deletion of user data, bypass of backup validation, installation, commit, push, or publication was performed in this repair turn.
