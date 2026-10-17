# Relay acceptance cleanup defect and exact-run continuation

Status: local fix verified; attended cleanup completed October 1 at 04:58:44 EDT.

## Live cleanup result

The operator ran the exact staged continuation and entered its confirmation.
The [root-produced completion receipt](evidence/2026-09-30-mini-relay-idle/cleanup-complete.json)
records `stopped`, `own_pf_reference_released: true`, `pf_enabled: false`,
`jobs_disabled: true`, `guest_stopped: true`, `aliases_absent: true`, unchanged
configuration and all seven preserved decoys. Its checksum is
`8b2832aee1663b1b26b989c949e37a88cc215468f0b14902462adc104767142b`.

- Private cleanup evidence:
  `/Library/SquirrelOps/acceptance-backups/mini-relay-20260930.m06dh5r3/relay-reference-cleanup-20261001.nbvt6vy_`.
- Sanitized receipt:
  `/private/var/tmp/squirrelops-mini-relay-cleanup-results.9wrszkx6/status.json`.
- Receipt timestamp: `2026-10-01T08:58:44Z`.

Fresh SSH checks confirmed the unchanged boot, both jobs absent from launchd and
explicitly disabled, no product/guest runtime and no `.240` or `.241` aliases.
The remaining service-account `distnoted` is not the product. The receipt was
verified as a root-owned, single-linked mode-0644 file in a root-owned mode-0755
directory. PF-reference absence/disabled PF, policy parity and database preservation
are verified by the pinned root continuation, not an independent unprivileged PF
or database read. The successful command is consumed; do not rerun it.

The historical preparation below is retained. The next proposed action is the
[start-only protocol window](2026-10-01-mini-installed-protocol-preparation.md),
not another installer run. Cleanup completion does not establish SSH/SMB acceptance.

## Confirmed cause

The [diagnostic run](2026-09-30-mini-relay-idle-window.md) installed and restarted
successfully, then failed at cleanup. The operator's read-only inspection found
the original PF reference still present, PF enabled, no completed release call,
and no reference inventory recorded after acquisition.

`PostRebootUpgrade` inherits `Upgrade`, not `LaunchdUpgrade`. Its cleanup method
calls `LaunchdUpgrade.release_reference(self)`. That method uses zero-argument
`super()`, which rejects this unrelated instance before reaching PF:

```text
TypeError: super(type, obj): obj must be an instance or subtype of type
```

The broad secret-redaction wrapper hid the programming error behind the generic
PF-release warning. A local reproduction using the actual diagnostic class and
mocked host boundary produced this exact hidden cause with **zero host command
calls**. Thus this pinned code path never reached reference inspection or
release; the conclusion does not rely on absence of a command log alone.

## Local fix and verification

The current diagnostic runner now restores the stopped/disabled hold and calls
its actual `Upgrade` base release implementation directly. Exact-reference
verification, clearing retry state before dispatch, post-release absence checks
and public secret redaction remain unchanged. Historical post-reboot and launchd
runners remain byte-for-byte preserved. Their old commands must not be rerun.
The diagnostic bootstrap checksum was updated locally, but neither its consumed
Mini staging nor its private evidence was changed. Its baseline is now stale;
the updated installer runner is not a new authorized live attempt.

The engineering-constraints skill required failing-first tests. Two new tests
failed on the original method: the real release chain never reached PF and the
simulated release timeout never cleared retry state. Both pass after correction.
The test now mocks only the host command boundary, not the defective wrapper.

- Diagnostic runner: 23 tests, 22 passed, 1 optional exact-package test skipped.
- Exact-run cleanup: 18 passed, including all seven actual saved rows,
  reference provenance, policy drift, command allowlist, confirmation/backup
  prerequisites, marker-before-release, retained unrelated references, no retry
  after timeout and token redaction.
- Both focused suites also passed under the pinned installed Python runtime.
- Full `test_mini*.py` suite: 313 tests, 310 passed, 3 opt-in tests skipped,
  4.049 seconds, with local loopback permission. An earlier sandboxed run was
  blocked on four loopback-listener tests; the permitted rerun passed.
- Shell syntax, input-checksum parity and `git diff --check` passed.

Mocked cleanup completion messages are not evidence of a live reference release.
No app, sensor, helper or guest code changed for this defect. No installer rebuild
is required, and no new installation was performed.

## Prepared cleanup scope

The new continuation is adapted from the previously successful cleanup-only
implementation, not from the defective borrowed method. It is bound to:

- Mini `100.108.203.27`, ARM64, build `26A434`, boot `1790777754`.
- Existing package SHA-256
  `3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea`.
- Both installed receipts at `1790818368`, verified read-only over SSH.
- Original backup `/Library/SquirrelOps/acceptance-backups/mini-relay-20260930.m06dh5r3`.
- Original private stage `/private/var/root/squirrelops-mini-relay.r2RulhrI`.
- Original results `/private/var/tmp/squirrelops-mini-relay-results.b0fp2kjt`.

The script verifies the original claim, pinned runner/scope/evidence, one matching
reference acquisition, no recorded release, original native listeners and PF
policy, current payload hashes, stopped/disabled jobs, no runtime/listeners or
owned aliases, unchanged configuration and all seven saved decoys. It takes a
fresh consistent private SQLite backup and records scope before asking for consent.

After confirmation, it rechecks live state and writes an exclusive durable attempt
marker before releasing exactly the verified test reference once. No installer,
service start/stop, signal, SQL edit, alias edit, rule edit, global PF reset or
Little Snitch change is allowed by its command dispatcher. Other references remain
untouched; releasing the last reference may return PF to its original disabled
state. Uncertain dispatch is never retried. There is no automatic inverse that
re-enables PF or starts services; that requires a separately reviewed startup.

## Historical staging and command, now completed

Fresh private Mini staging: `/Users/matt/squirrelops-mini-relay-cleanup.Vr2YfX9H`.
Local and remote digests match. Shell syntax and remote plan-only execution passed.
The unchanged package is present only to extract a checksum-pinned private Python
runtime; the cleanup script never invokes Installer.

| Input | SHA-256 |
| --- | --- |
| `mini_relay_cleanup.py` | `0bacc4d9768392e0c268b87402ed928d2c21b2153f7ee02acbbeed70335b6b9e` |
| `finish-mini-relay-cleanup.sh` | `efc60b26015263ed0b41b50966fa653e6cdab41156cf461b9dfc92219d4a4544` |

```sh
sudo /bin/bash /Users/matt/squirrelops-mini-relay-cleanup.Vr2YfX9H/finish-mini-relay-cleanup.sh
```

Confirmation: `RELEASE DIAGNOSTIC TEST PF REFERENCE`.

Keep both product apps closed. No new laptop probes, reference release, commit,
push or publication occurred during the original preparation. After verified cleanup,
the next needed live work is a coordinated protocol window using the already
installed diagnostics, not another blind installer retry.
