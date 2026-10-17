# Reboot-safe mini recovery prepared, not executed

Update: this historical staging was tried and stopped on process parsing.
Use the separately verified
[v2 inventory correction](2026-09-30-mini-recovery-process-inventory-fix.md)
instead of the original command below. Preserve this preparation record.

The approved recovery is staged at:
`/Users/matt/squirrelops-mini-reboot.37SbZXTy` on `matt@100.108.203.27`.
Directory mode 0700 and input modes 0600 were verified over SSH. Plan-only mode
passed with the installed private Python; no recovery, installer or LAN probe
was executed. Latest observed sensor remains PID 887, runs 1, exit timeout 5.
Current boot is epoch 1790766531 and OS build is 26A434.

The exact behavior and inverse are in
[the recovery scope](2026-09-30-mini-reboot-recovery-scope.md).
Historical pinned acceptance scripts were not edited. This is a separate
stop-and-hold operation, not an exception to their old guards.

## Verification this session

- `unittest discover -s docs/testing/fixtures -p 'test_mini*.py' -q`:
  198 total, 197 passed, 1 skipped, 3.762 seconds with loopback permission.
  An earlier sandboxed run denied four pre-existing loopback listener tests;
  those passed with the appropriate local test permission.
- New recovery tests: 16 total, 15 passed, 1 skipped, both in the development
  environment and in the extracted candidate's isolated Python.
- Ruff, shell syntax, remote plan-only mode, source/hash parity and
  `git diff --check` passed.
- Regression check with the old temporary receipt directory substituted failed
  the durable-storage assertion; restored implementation passed.
- Actual user-domain KeepAlive experiment disproved disable-only shutdown:
  the first process completed its eight-second cleanup, then a new process
  launched despite the disabled override. This route is not used for recovery.
- The next-launch replacement experiment was denied without administrator
  privileges. No local noninteractive sudo session is available. The revised
  root/system-domain native proof is deliberately skipped in local tests and
  runs as a mandatory gate on the mini before product mutation. Do not describe
  the privileged shutdown or mini recovery as already accepted.
- Disposable local probe jobs were unloaded. Their effective-enabled override
  records remain; no installed SquirrelOps job was targeted by those tests.

The engineering-constraints skill led to testing the actual launchd behavior
before preparing a live-service shutdown, and preserving a required host proof
when local administrative validation was unavailable.

## Exact staged pins

| Input | SHA-256 |
| --- | --- |
| mini_reboot_recovery.py | d995d90efe477209b29ede3c43d0aa06365010b39a2c01ab33386a1e3ccb552b |
| stop-mini-reboot-recovery.sh | 041ab97e76c9771e1299c328c0f5b1277a6220b2cd36b5f40dcc7cbbcc9c4cc8 |
| approved-scope.md | a23cf3bbbcd97eff1f6a971cc5989fdfd4660c8c2ee6d50dea318ceeb6c7d48a |

The bootstrap pins four unchanged dependency modules and the installed runtime
hash as well. It does not extract or install another package. New durable root
evidence uses a fresh directory beneath `/Library/SquirrelOps/acceptance-backups`.
The before/after database snapshots are read as UID/GID 309 and copied into
private root evidence; no root-owned live SQLite sidecar is introduced.

## Next attended action

On the mini, keep the GUI closed and run only this new command:

```sh
sudo /bin/bash /Users/matt/squirrelops-mini-reboot.37SbZXTy/stop-mini-reboot-recovery.sh
```

If preflight and the disposable system-job proof pass, review the backup and
scope, then enter `STOP MINI AND HOLD`. Return declines product mutation.
Share the resulting `RECOVERY COMPLETE` or `STOPPED` output. Do not rerun an old
acceptance/cleanup command, restart the app, reset PF, or approve new Little
Snitch prompts while this recovery is under review.

The next acceptance runner still needs to be prepared against the actual durable
receipt and current PF baseline after successful recovery. It must handle the
two disabled jobs at an explicit installation boundary and restore the hold on
teardown. It must not reuse the vanished temporary receipt or assume PF is
disabled. No installer rebuild, commit, push, public release or website update
was performed in this session.
