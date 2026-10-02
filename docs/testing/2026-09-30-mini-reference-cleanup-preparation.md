# Mini PF-reference cleanup: attended execution complete

Matt approved a cleanup-only continuation after the
[post-reboot run](2026-09-30-mini-post-reboot-live-result.md) stopped on its
six-row intent guard. This continuation preserves the exact seven observed
rows, validates the original six without weakening their identity/intent
checks, and releases only the original test-owned PF reference. It does not
repair a database or retry the installer. The attended continuation completed
at 17:12:32 UTC on 2026-09-30 (13:12:32 EDT). The preparation record below is
retained, with the successful execution evidence added here.

## Attended result and independent checks

Matt ran the staged command and entered the exact confirmation. The
[root-produced completion receipt](evidence/2026-09-30-mini-post-reboot/cleanup-complete.json)
was verified over SSH as a root-owned, single-linked, non-writable-by-others
regular file in its root-owned results directory. It matches the original
source results, boot and package digest and records:

- `phase: stopped`, `own_pf_reference_released: true`, `pf_enabled: false`.
- `guest_stopped: true`, `aliases_absent: true`, `jobs_disabled: true`.
- `reviewed_decoy_count: 7`, `config_change_verified: true`.

Execution evidence:

- Original private backup:
  `/Library/SquirrelOps/acceptance-backups/mini-post-reboot-20260930._a_bdeaf`.
- New private cleanup evidence:
  `/Library/SquirrelOps/acceptance-backups/mini-post-reboot-20260930._a_bdeaf/reference-cleanup-20260930._xy460p7`.
- Sanitized results:
  `/private/var/tmp/squirrelops-mini-reference-cleanup-results.22mxy1fp`.

Independent read-only `launchctl print`, `launchctl print-disabled`, `ps`,
`ifconfig` and `sysctl kern.boottime` checks confirmed the same boot, both
product jobs disabled and unloaded, no product/guest/Virtualization runtime,
and no `.240` or `.241` interface alias. The remaining UID-309 `distnoted`
process is not the product runtime. The diagnostic Python process itself was
excluded from its process inventory.

PF-reference absence, disabled PF, native listener/policy parity, the fresh
database backup and seven-row preservation are verified by the pinned root
continuation and its receipt, not a second unprivileged PF/database read.
No additional administrator commands or system changes were made during this
verification. The consumed cleanup command must not be rerun.

The mini remains intentionally held stopped. Installation, narrowed
configuration, all seven decoys and backups are retained. This completes
cleanup only, not SSH/SMB acceptance or release readiness.

## Exact authority and scope

- Mini only, `100.108.203.27`, ARM64, build `26A434`, boot `1790777754`.
- Original failure results:
  `/private/var/tmp/squirrelops-mini-post-reboot-results.3p_hssk9`.
- Original private execution:
  `/private/var/root/squirrelops-mini-post-reboot.lQlvs3JI`.
- Resolve the private backup only through the root-private original claim:
  `/Library/SquirrelOps/acceptance-backups/post-reboot-1790777754-3a3cda47a7ea-attempt.json`.
  Require the expected parent, backup-name pattern and exact package digest.
- Preserve IDs 1 through 6 exactly, plus ID 7, `home_assistant`, native address
  `192.168.1.115`, port `51232`, active intent. Missing, additional, changed or
  reordered rows fail the continuation; no SQL writes are performed.
- The sole allowed system mutation is one `pfctl -X` for the privately retained
  token proven to match this run's original successful `pfctl -E`. No other
  reference, PF rule or enablement command is changed. Releasing the last
  reference may return PF to the original disabled state; other references
  are preserved, so PF may remain enabled.

No installer invocation, service start/stop/enable/disable, process signal,
alias withdrawal, packet-filter rule rewrite/reset, Little Snitch action,
LAN probes, credential reset or database repair is in this continuation.
If one of those is needed, stop and review instead.

## Checks and evidence

The new script leaves all historical pinned runners unchanged. Its command
allowlist blocks every privileged operation except the single armed reference
release. It reads the original command history as data, never as commands to
execute, and verifies:

1. Pinned original runner modules, scope and public/private failure snapshots.
2. Exactly one matching PF-reference acquisition, no previous release attempt,
   successful installation from the exact private stage, and verified disabled
   jobs at the original stopping boundary.
3. Original native-listener and concrete-anchor policy baselines reconstructed
   from the recorded read operations; original PF disabled with zero states.
4. Current stopped/disabled runtime, no owned alias or proxy ARP, original
   native listeners/route intact, unchanged empty policy, installed payload
   checksums, package receipts and narrowed configuration.
5. Fresh service-identity read-only database access, exact seven-row comparison,
   and a consistent private SQLite backup with an integrity check. Configuration
   and private pre-release command evidence are retained too.

After the preview and attended confirmation, these live guards run again.
An exclusive, fsynced attempt file is written into the original private backup
before the release. The reference is cleared from the runner's in-memory retry
state before dispatch. A timeout or ambiguous outcome never retries. The
original evidence, installer and all data stay in place. There is no automatic
inverse that enables PF or starts services; a new guarded startup is a separate
approved action.

The script verifies the reference is absent after release, repeats the stopped,
policy, listener, configuration and seven-row checks, and records the actual PF
enabled/disabled state. Failure preserves evidence and requests review.

## Local verification

The engineering-constraints skill required a regression against the actual
recorded seven-row snapshot before implementation. That regression failed with
the exact old intent error, then passed with the scoped continuation guard.

- `sensor/.venv/bin/python -B -m unittest discover -s docs/testing/fixtures -p test_mini_post_reboot_cleanup.py -q`:
  **18 passed**.
- Same **18 passed** using the candidate's extracted Python with `-I -B`.
- Full local `test_mini*.py` suite with extracted-artifact coverage and loopback
  permission: **262 run, 261 passed, 1 skipped**, 4.097 seconds. The skip remains
  the historical opt-in root launchd probe, not a cleanup pass.
- Tests cover exact-row preservation, refusal on drift/missing/extra rows,
  pinned backup routing, private token provenance, previous release refusal,
  PF parser errors, the command allowlist, backup/consent/recheck prerequisites,
  marker-before-release ordering, retained unrelated references, uncertain
  release without retry, token redaction and bootstrap input pins.
- Ruff, bootstrap `bash -n`, plan-only execution and `git diff --check` passed.

Host operations in the tests are mocked. The simulated `CLEANUP COMPLETE`
messages in unit-test output are not live cleanup evidence.

## Historical staging and command

Fresh private mini directory:
`/Users/matt/squirrelops-mini-reference-cleanup.PnCxjRUZ`.
The directory is mode 0700, and all nine inputs are regular single-linked
mode-0600 files owned by `matt`. Remote digests match the local reviewed inputs.
The unchanged candidate is copied only to extract a pinned private interpreter;
it will not be installed. Remote plan-only execution and shell syntax passed.
The original failure status digest still matches.

| Artifact | SHA-256 |
| --- | --- |
| `mini_post_reboot_cleanup.py` | `197d68478fcf9a4ebced1d501840155876bb59a8bfd8be77d27db0a2181f054e` |
| `finish-mini-post-reboot-cleanup.sh` | `85a3e7513ac1fca19d5d05b8840e84ef223f4e15b25b6ed9ecbd83c5482e5084` |
| Unchanged candidate | `3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c` |

The command below has completed. It is retained for provenance; do not rerun:

```bash
sudo /bin/bash /Users/matt/squirrelops-mini-reference-cleanup.PnCxjRUZ/finish-mini-post-reboot-cleanup.sh
```

The attended confirmation used was:

```text
RELEASE THIS TEST PF REFERENCE
```

Keep the app closed. Do not rerun the consumed command, reset networking or
change Little Snitch rules. SSH/SMB protocol acceptance is still unresolved
and was not part of this cleanup.

No installer rebuild, installation, reference release, commit, push or
publication was performed while preparing this continuation.
