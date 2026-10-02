# Mini recovery runner: database metadata correction

## Observed failure

The attended runner stopped in preflight with `Current SQLite database is
unsafe`, before its confirmation prompt, recovery transaction, PF enable, or
package installation. Sanitized status time: `2026-09-30T01:13:08Z`.

Preserved attempt:

- Backup: `/Library/SquirrelOps/acceptance-backups/mini-upgrade-20260929._skls8il`.
- Results: `/private/var/tmp/squirrelops-mini-upgrade-results.bx28zmd3`.
- Root staging: `/private/var/root/squirrelops-mini-ownership.sLW9EBWQ`.

Matt supplied the root-only `stat` result for the exact installed database:

```text
type=Regular File uid=309 gid=309 mode=644 links=1 bytes=512000
```

Read-only SSH checks confirmed both product launchd jobs remain absent, the
sensor receipt timestamp is still `1790711659`, and UID 309 has only the OS
`distnoted` process. The data directory remains `_squirrelops:_squirrelops`,
mode 0700, with no extended ACL shown by `ls -lde`.

## Root cause and correction

The runner incorrectly required all group/other file permission bits to be
zero. The package's `configure_sensor_permissions` protects the data directory
with mode 0700; it does not impose mode 0600 on every database file. `open_db`
creates the SQLite file without an explicit chmod, and the service plist does
not set UMask. The reported 0644 file is compatible with that implementation.
This was a test-runner assumption, not evidence of database corruption.

The corrected guard accepts only regular, single-link, UID/GID-309 files with
mode 0600 or 0644 and the existing size limit. It independently checks the
parent is a real UID/GID-309 directory with exact mode 0700. Both paths must
have no extended ACL, using the same `ls -lde` inventory convention as the
package installer. It still rejects group/other write bits, executable/special
modes, links, wrong ownership and excessive size. Errors now include safe
numeric metadata so another mismatch will be diagnosable without file contents.

No installed permissions, data, package, third-party filter rule, or service
state changed. Historical backup protections and the five-row scope remain
unchanged. The recovered-data confirmation is still required.

## Verification and replacement staging

Engineering-constraints verification reproduced the observed 0644 rejection
before changing the guard. Added tests cover the accepted private layouts,
unsafe metadata, parent access, ACLs, diagnostic details, and bootstrap digest
parity. The first digest test also caught stale bootstrap pins before staging.

Final command, using the candidate's extracted Python:

```bash
build/test-artifacts/ownership-fix-extracted-20260929/sensor.pkg/Payload/Library/SquirrelOps/sensor/python/bin/python3.12 \
  -I -B -m unittest discover -s docs/testing/fixtures -p 'test_mini*.py' -q
```

Result: **129 passed**. Ruff on the changed runner and tests passed. Local and
remote `bash -n` passed. All six staged checksums matched the local files.

New mini directory: `/Users/matt/squirrelops-mini-ownership-v2.290wspVB`, mode
0700. The original staging directory and failed attempt remain untouched.
The laptop client at `/root/squirrelops-mini-upgrade-client.Ud9OIx96` is unchanged.

| Input | SHA-256 |
| --- | --- |
| candidate.pkg | `2d5f4d287ca3ce971fd201f539d27a9272431f160a5a5debddc8d1b0b4dc7c82` |
| mini_acceptance.py | `47b6c6df59083230ac63f97f1b32c55fa804f71839d433bfbc9fb952bf7bd40a` |
| mini_upgrade_acceptance.py | `4c732720e89da4b4a872b56e951b1b70b121e2db603185ecb36d298c99c464d3` |
| mini_ownership_acceptance.py | `98d8729e112e8ff48bbf320b094ab96471e597dd48cec6a726b17807d07986e6` |
| approved-scope.md | `6a1b627d0a143a8c7eb661f0b5d13f5e2547c69196bc69b3207ec771fb2b59fe` |
| start-mini-ownership-acceptance.sh | `2e2cf33fae6d178fd0c251ebcd96930073b2a078458fc7345deae1a14ac22dd4` |

Next attended command, on the mini with SquirrelOps closed:

```bash
sudo /bin/bash /Users/matt/squirrelops-mini-ownership-v2.290wspVB/start-mini-ownership-acceptance.sh
```

Review the five-row preview and type `RESTORE FIVE AND UPGRADE` to authorize
that exact recovery and upgrade. Leave Terminal open at `READY FOR TESTS`.
Leave any new filter prompts unanswered and report them.

The replacement runner has not been executed on the mini yet. Current PR #52
head remains `a50179417e8f726ceb03bb6914a42cb996d2ead6`; its sensor and supply-chain
checks now pass, but independent review remains required. Normal live acceptance
and the separate A5 isolation matrix are still open. No product rebuild,
commit, push, merge, or release was performed for this local runner correction.
