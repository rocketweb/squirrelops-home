# Mini post-reboot acceptance: payload-check fix

## Result

The acceptance runner, not the installed application, caused the preflight
failure. The corrected runner is tested and staged in a new private directory
on the mini. The installer is unchanged. The attended upgrade, restart and LAN
acceptance are still pending; this is not a release-readiness result.

## Failure and root cause

The original run stopped with:

```text
STOPPED: RuntimeError: Unsafe preflight evidence: /Applications/SquirrelOps Home.app/Contents/MacOS/SquirrelOpsHome
```

Evidence retained from that attempt:

- Private directory: `/Library/SquirrelOps/acceptance-backups/mini-post-reboot-20260930.7j8q2wae`.
- Sanitized status: `/private/var/tmp/squirrelops-mini-post-reboot-results.37l5b9r5/status.json`.
- Status was `needs_review`, with no verified configuration change.

`validate_existing()` used `base.safe_file()`, which caps small evidence files
at 1 MiB, for installed payloads. The actual app executable is 7,791,648 bytes.
Read-only checks confirmed it is a root:wheel-owned regular file, mode 0755,
single-linked, and has the expected SHA-256:
`a0e3ed122b57ed94857d49e8123ac6491672cbb204e150fa252f4046b28910b6`.
No ownership or permission change was needed.

The failure occurred before completed backups, consent, configuration edits,
PF enablement or installer invocation. The reported private directory is
preflight evidence, not proof of a completed installation/data backup.

## Correction

`mini_post_reboot_acceptance.py` now uses a dedicated installed-payload check
both before and after installation. It:

- Requires regular, single-linked, root:wheel-owned, non-group/world-writable
  files with a separate 64 MiB payload size bound.
- Opens without following a final symlink and hashes in bounded chunks.
- Rechecks file identity, metadata and size during open and hashing.
- Requires the exact existing SHA-256 pin.

The original 1 MiB evidence-file guard remains unchanged. Historical runners,
package bytes, approved scope, database intent, configuration pins and firewall
policy were not changed. The bootstrap pins the corrected runner.

## Verification

The engineering-constraints skill guided the failing regression before the fix
and the distinction between local tests and live acceptance.

- A real disposable 7,791,648-byte file reproduced the exact preflight failure
  before the fix. The same regression now passes through the payload checks.
- `SQUIRRELOPS_TEST_PACKAGE_EXPANDED="$PWD/build/test-artifacts/launchd-budget-20260930-expanded" sensor/.venv/bin/python -B -m unittest discover -s docs/testing/fixtures -p test_mini_post_reboot.py -q`:
  **31 passed**, including checks of actual extracted candidate payload bytes
  with simulated installed ownership. The privileged helper fixture maps its
  installed destination to the bundled source copied by app postinstall.
- The same **31 passed** with the candidate's extracted Python using `-I -B`.
- Full `test_mini*.py` fixture suite with the same artifact environment and
  loopback permission: **244 run, 243 passed, 1 skipped**, 3.852 seconds.
  The skip is the historical opt-in root launchd probe, not this workflow.
  Host mutations are mocked; disposable local loopback listeners are real.
- Ruff on the runner, client and tests; bootstrap `bash -n`; bootstrap input
  pins; plan-only execution; and `git diff --check` passed.
- On the mini, the corrected checker ran read-only as `matt` against all six
  installed pinned files: app, privileged helper, guest launcher, sensor main,
  orchestrator and Python. All metadata and checksum checks passed.
- Fresh read-only checks confirmed boot `1790777754`, both product jobs
  disabled/unloaded, no product/UID309/Virtualization runtime, and no `.240` or
  `.241` aliases. The inventory excludes the diagnostic Python process itself.
  Root-only PF, ledger and database checks must still run in the attended gate.

## Corrected staging

New mini directory: `/Users/matt/squirrelops-mini-post-reboot-v2.UU8waUaT`.
It is mode 0700, owned by `matt`. All ten inputs are regular single-linked
mode-0600 files owned by the staging user. Every remote digest matches its
expected local value. The original staging and failed-run evidence are retained.

| Input | SHA-256 |
| --- | --- |
| Corrected runner | `b97147d63a35f8a7b93eade3f01c7a2dfc03a80a6f09b3c29cec7156885cc068` |
| Corrected bootstrap | `4e6fdb557e28ac976f83f4fd76f20f2497d5edefbf5d4a4b896e47f7fd40154b` |
| Unchanged package | `3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c` |
| Unchanged approved scope | `288eb8eb45a50caaac9538f02ac1cc23ca697573e967771a06314cfb2725f24e` |

The unchanged candidate is
`build/test-artifacts/SquirrelOpsHome-2.1.0-launchd-budget-20260930-local-test.pkg`.
It remains an unsigned local-test installer with ad-hoc payload signatures.
The existing laptop wrapper at
`/root/squirrelops-mini-upgrade-client.VNbggFA7` is unchanged. No LAN probes were
sent, and no synthetic credentials were transferred during this correction.

## Next attended step

Run in the mini's Terminal, with SquirrelOps still closed:

```bash
sudo /bin/bash /Users/matt/squirrelops-mini-post-reboot-v2.UU8waUaT/start-mini-post-reboot-acceptance.sh
```

After fresh verified backups and the scope preview, enter
`UPGRADE HELD MINI AND TEST 240`. At `READY FOR TESTS`, leave Terminal open,
do not press Return, and tell Codex. Leave any new Little Snitch prompt
unanswered and report it. If the script says `STOPPED`, report the output rather
than retrying. The existing mini-only approval is unchanged.

No installation, service/PF changes, commit, push, rebuild or publication was
performed for this correction. No live acceptance pass is claimed.
