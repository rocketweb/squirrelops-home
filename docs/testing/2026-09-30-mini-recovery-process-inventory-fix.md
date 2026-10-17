# Recovery process-inventory correction

Update: the v2 command subsequently reached and failed its native shutdown proof.
Do not rerun it. See the
[native probe failure record](2026-09-30-mini-native-recovery-probe-failure.md)
for the current state and required evidence review.

The first reboot-recovery attempt stopped before confirmation or product
mutation. Its durable evidence remains at
`/Library/SquirrelOps/acceptance-backups/mini-reboot-20260930.7XLNJln0`.
That directory is preflight evidence, not a verified complete recovery backup:
the failure occurred before the SQLite snapshot and disposable launchd proof.

## Confirmed causes

1. Actual mini `ps -axo uid=,pid=,ppid=,comm=` output included
   `-2 900 1 /usr/sbin/distnoted`. The old parser required unsigned digits in
   every identity field. `dscl . -read /Users/nobody UniqueID` independently
   returned `-2`, while `id -u nobody` returned `4294967294`.
2. Read-only validation then caught the recovery observer itself in the process
   list. It uses the pinned installed Python under root during recovery, or Matt
   during read-only inspection. The product identity guard correctly rejects
   other non-service-account Python processes, but needed to distinguish the
   current, verified observer.

The parser now accepts bounded signed/unsigned UID representation, while keeping
PID/PPID unsigned, rejecting malformed/duplicate/out-of-range rows, and retaining
the reported UID. It excludes only `os.getpid()` after checking its effective
UID, non-sensor identity and exact pinned Python executable path. Any other
unexpected product process remains a blocker. No service-account or shutdown
permissions were broadened.

## Verification

Following the engineering-constraints skill, both regressions were observed
failing before their respective fixes: the real signed-UID row raised
`Malformed process inventory`, and the observer test retained PID 910 when it
should have excluded only that verified observer.

- Full harness: `unittest discover -s docs/testing/fixtures -p 'test_mini*.py' -q`
  reported 200 total, 199 passed, 1 skipped in 3.719 seconds with loopback-test
  permission. No LAN probes or product service changes occurred.
- Focused recovery suite under both development and extracted candidate Python:
  18 total, 17 passed, 1 skipped.
- The root/system-domain proof remains unverified and mandatory before product
  mutation in the attended runner; local root authority was not available.
- Actual revised `Recovery.rows()` and `runtime_rows()` passed read-only on the
  mini: 417 process rows after excluding the verified observer, one signed
  nobody UID, sensor PID 887, runtime cohort PIDs 887/1870/1871.
- Sensor and helper remained at PIDs 887/888 with one launch each; boot identity
  is unchanged at 1790766531. No new disabled override was observed.
- Ruff, shell syntax, checksum parity and `git diff --check` passed.

## New staging, same approved scope

Use `/Users/matt/squirrelops-mini-reboot-v2.qegfyw1y` on the mini. The original
staging and root evidence were preserved. Only the parser/observer fix and its
bootstrap checksum changed; the approved recovery scope is unchanged.

| File | SHA-256 |
| --- | --- |
| mini_reboot_recovery.py | 9632faaac479ab98898191ef1866117bb8f2982a55759446ec796d8561ee4048 |
| stop-mini-reboot-recovery.sh | ca7aab8e9550dd589836bbb3d35ac10085f72845a40eeaa547c1b96d46a6c52d |
| approved-scope.md | a23cf3bbbcd97eff1f6a971cc5989fdfd4660c8c2ee6d50dea318ceeb6c7d48a |

```sh
sudo /bin/bash /Users/matt/squirrelops-mini-reboot-v2.qegfyw1y/stop-mini-reboot-recovery.sh
```

Confirmation remains `STOP MINI AND HOLD`, only after preflight and the native
disposable proof pass. Keep the app closed and new Little Snitch prompts
unanswered. Share the resulting completion or stop output before any installer
or LAN acceptance continuation. No commit, push, installation or release was
performed during this correction.
