# Native Mini clean baseline and old-version upgrade

Date: October 2, 2026. Status: corrected cleanup completed; official 2.0.3
installation failed; Mini work paused at Matt's request.

Historical attended command, **do not rerun**:

```bash
sudo /bin/bash /Users/matt/squirrelops-mini-clean-upgrade.LtUQXpyS/resume-mini-clean-upgrade.sh
```

The copied package and script digests, shell syntax, read-only runner output
and Gatekeeper acceptance of the old package were verified on the Mini.
The second attempt removed the app, helper, runtime and live data but stopped
at account teardown. The subsequent attended resume completed the corrected
cleanup, then failed while installing the original, unmodified 2.0.3 package.
The user supplied the final output. Private evidence is retained at
`/Library/SquirrelOps/acceptance-backups/mini-clean-upgrade-20261002.tvk708n4/resume-mtw69mgk`.
The wrapper reported product jobs stopped/disabled, without an automatic
restore or PF reset. The exact installer failure has not been inspected;
do not infer its cause or assume no partial payload exists.

Matt paused the Mini path and supplied a working macOS 26.6.1 ARM64 MacBook
with 2.0.3 already installed. Its separately approved, data-preserving upgrade
is tracked in [the MacBook preparation](2026-10-02-macbook-upgrade-preparation.md).
The Mini archive remains retained. Neither Mini command should be rerun.

## Second attended attempt: partial uninstall and account recovery

Original private archive:
`/Library/SquirrelOps/acceptance-backups/mini-clean-upgrade-20261002.tvk708n4`.
The runner verified seven paths, totaling 248,128,917 regular-file bytes,
before invoking the installed uninstaller. The user supplied its exact failed
command record: exit 1, `Could not safely remove the sensor service identity.`
No installer command had been reached in that execution path.

Read-only inspection confirmed the app, helper binary, launch plists, sensor
runtime and data were absent. The original uninstaller and three package
metadata files remained. `_squirrelops` UID/GID 309 still existed, both jobs
were disabled, and lo0 had only its native addresses. The separate archive
retains recovery copies of the removed product files and data. It is not an
automatic OS rollback.

Two independently reproduced account-validation defects caused the rejection:

- The Mini's otherwise valid service account used `RealName: _squirrelops`;
  teardown accepted only `SquirrelOps Sensor`.
- `dscl` reported absent `GroupMembership` and `GroupMembers` on stderr with
  exit 0 and empty stdout. The helper incorrectly interpreted that as an
  unrecognized membership record instead of absence.

The source fix applies consistently to app preinstall, sensor postinstall and
uninstall recovery. It permits only the canonical or exact service-record
display name, retaining UID/GID uniqueness, non-login shell, home, hidden flag
and empty-membership checks. The membership parser captures both streams,
recognizes only the exact missing-key response and verifies the record still
exists. Silence, permission errors, mixed output and nonempty groups do not
authorize removal.

Regressions were observed failing before each correction. The focused package
lifecycle/SQLite/component tests passed **58 tests**. The reset/resume fixture
suite passed **30 tests**. The corrected read-only identity predicate also
passed against the Mini's actual account. No remote account change or retry
of the uninstaller was performed during those checks.

The subsequent expanded package/security/supply-chain run passed **126 tests**
in 8.16 seconds. Ruff, shell syntax and `git diff --check` passed. The staged
resume inputs were copied to the Mini and all six package/script hashes
matched before the attended resume described above.

The resume script verifies every retained payload against the original
manifest, requires the exact failed command and original residual files,
checks the root-owned deprovisioning marker for UID 309, and rechecks stopped
services/network state. It makes a single-use recovery claim and writes new
evidence under the existing archive without replacing the original evidence.
It executes the checksum-pinned corrected uninstaller from a root-private
staging directory, then reuses the original 2.0.3 installation/health/stop
sequence. The official old package remains unmodified. No field is changed in
Directory Service merely to make an old check pass.

Corrected uninstaller SHA-256:
`1f2e64b73b20db7cbacf5caf9ac0d79053c7a1db754684dbc96b4e6a9f3166b6`.
Resume runner SHA-256:
`9aafd26e22f9bdb2bb4b66e7f9d71c7cd023f278856a8ea50b160c1c70db300e`.
Shared runner SHA-256:
`90504c8a7a1f422e5692bac138ecd7e15f5ad0479cb51579f2f4284cd065afe0`.
Resume bootstrap SHA-256:
`d568bbb48a4183804b484062fb3f28dc39c33e4e9dc01098b211fe98af58c4d7`.

The source fixes still need commit/review, inclusion in a rebuilt 2.1 package
and release acceptance. They do not retroactively repair the previously built
candidate or establish that the Mini old-version install/upgrade has passed.

## First attended attempt: signed UID parser correction

The initial attempt stopped with `Malformed process inventory` before the
recovery archive was created and before any removal or installation. Read-only
inspection showed the rejected row was UID `-2`, PID `653`, executable
`/usr/sbin/distnoted`. Both product launchd jobs were absent.

The reset script incorrectly required every displayed UID to be unsigned.
It now accepts bounded signed or unsigned decimal UID representations and
normalizes them to the unsigned 32-bit value before comparing ownership. PID
validation remains nonnegative and bounded; malformed entries still stop the
operation. It does not skip negative-UID rows or weaken product process checks.

Two regression cases failed first with the reported parser error. After the
correction, all **26 fixture tests passed**, including malformed IDs, signed UID
ownership matching, product-process rejection and the exact bootstrap checksum
pin. The corrected parser also passed against a fresh process inventory from
the Mini, with no product runtime found. Shell syntax and `git diff --check`
passed. These are preflight/parser checks, not a completed reset or upgrade.

Corrected runner SHA-256:
`40585701dab4df67c946568032ad4a63262643a5dd28ae669ca9fc44d51f9e0a`.
Corrected bootstrap SHA-256:
`1f35981e499e517c512dbee1790e84d307462d3eb71b6aa1a24799397b06d8c1`.
The same staged command is used; package bytes and destructive scope are unchanged.

Matt explicitly authorized wiping the existing SquirrelOps installation and
data on the Mini, installing an older version, and testing an in-place upgrade.
This supersedes the macOS VM proposal. It does not authorize wiping the Mac,
changing Home Assistant, Tailscale, Little Snitch, native services, the Studio,
`.241`, or global PF policy.

## First attended operation

`fixtures/start-mini-clean-upgrade.sh` stages checksum-pinned inputs privately
and runs `fixtures/mini_clean_upgrade.py`. It:

1. Verifies the Mini's en0 hardware address, stopped product processes, disabled
   PF with no starter references, and absence of test aliases. It checks the
   exact reviewed installed uninstaller and official old package.
2. Creates a mode-0700 recovery directory under
   `/Library/SquirrelOps/acceptance-backups/mini-clean-upgrade-20261002.*`.
   Copies durable files with their ownership and modes and verifies SHA-256
   manifests against both source and copy. Transient Unix sockets are omitted.
   Prior acceptance evidence is not copied or removed.
3. Runs the installed uninstaller with `--remove-data`. This removes the app,
   sensor runtime/config/database/history/pairing data, helper, product launch
   plists, service account and group, owned helper state, package receipts and
   the package's normal rollback snapshots. Three known package metadata files
   left by the uninstaller are removed only after their manifests match the
   archived originals. Unexpected leftovers stop the operation.
4. Installs the original, unmodified GitHub 2.0.3 package. A synthetic Lite
   configuration keeps Scouts off and Home Assistant integration disabled.
   Normal LAN discovery and up to three classic host listeners may run during
   startup; no automatic fake-host/VIP deployment is enabled. Only the two
   product jobs are enabled for this install. No UI or user Keychain items are
   opened or removed.
5. Checks installed app/sensor versions and the old API's `status: ok` health
   response, then stops and disables both product jobs. Checks PF remains
   disabled, test aliases absent, and root PF rules unchanged. Leaves the old
   installation and its newly generated data ready for the migration phase.

The archive is outside the uninstaller's `/Library/SquirrelOps/backups` target.
It includes the app, full sensor tree, normal package backups, helper binary,
two launch plists, helper state and service identity markers when present.
Account metadata, package receipts and launchd state are recorded privately.
Recovery is possible from these files but is not an automatic OS rollback:
reinstall the saved current package to recreate its service account, stop both
jobs, verify the UID/GID against the manifest, then restore selected files
after review. Do not blindly restore PF ownership ledgers or transient sockets.

If the original 2.0.3 installer fails on macOS 27, retain its actual failure.
Do not patch the package, bypass signature assessment, retry automatically or
claim that an old-to-new upgrade passed. If interrupted while PackageKit may
still be installing, the wrapper does not race it with automatic service
cleanup. Review installer state first.

## Artifact evidence

Official release: <https://github.com/rocketweb/squirrelops-home/releases/tag/home-v2.0.3>

- `SquirrelOpsHome-2.0.3.pkg`, 40,397,159 bytes.
- SHA-256: `252bd6bd559b4dbf578410aa959611675d3b627163ee885f404857cb67ab23f8`.
- GitHub asset digest, downloaded bytes, sidecar and release metadata agree.
- `pkgutil --check-signature`: Rocket Web Inc `PSQ5HK5U65`, trusted timestamp,
  trusted Apple notarization.
- `xcrun stapler validate`: success.
- `spctl -a -vv -t install`: accepted, Notarized Developer ID.
- Initial sandbox signature checks were unreliable. The results above came
  from the subsequent host-level verification, not that failed sandbox check.

The current 2.1 resolver candidate is staged only for its private interpreter
and recovery artifact. Its SHA-256 is
`47774088cd9eadc5aaddf38949e00a8b8f6eeb56c2192a5a72830d06d84a8aec`.
It is not installed by this first operation and is not the final signed release.

## Verification before handoff

- Package lifecycle/SQLite backup/component-plist tests: **49 passed**.
- Reset fixture tests: **8 passed**. They exercise read-only plan output,
  backup manifests, actual `ditto` copying with a transient Unix socket and a
  symlink, launchd response handling, target exclusions and the actual 2.0.3
  configuration schema. The socket test required host execution because the
  sandbox forbids Unix socket binding.
- These tests do not execute the uninstaller or installer on the development
  Mac and do not establish that the Mini operation has completed.

## Remaining migration phase

After the old baseline succeeds, exercise its installed helper with synthetic
state and one bounded client run. Record an actual old unconditional redirect
and existing TCP/PF state, then upgrade **without uninstalling 2.0.3**. Verify
old state cleanup, guarded installed rules, data preservation and startup.
Uninstalling again between old and new would invalidate that upgrade test.

Final exact signed/notarized installer acceptance and publication remain
separate gates. No commit, push, tag, release or website change is implied.
