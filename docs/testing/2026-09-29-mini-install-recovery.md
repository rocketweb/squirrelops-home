# Mini installation failure and bounded recovery

Date: 2026-09-29. Status: recovery installation passed on the mini;
subsequent live protocol acceptance failed. See the
[live acceptance report](2026-09-29-mini-live-acceptance.md) for evidence and
cleanup status. The historical failure and approved recovery below are retained.

## Observed failure

The second attended setup passed the named-anchor PF inventory and reached
Installer. Its private baseline is
`/Library/SquirrelOps/acceptance-backups/mini-20260928.4e0684b8`; its sanitized
status is `/private/var/tmp/squirrelops-mini-results.wfoowu0l/status.json`.
The exact package remains SHA-256
`3e8c0fc78befad3365fdbff5583d9f85c6b6fe01816b5863edbebeceaa4b8f5f`.

The mini's `/var/log/install.log`, at 00:02:30 local time, reports:

```text
[postinstall] Privileged helper is unusable by _squirrelops.
```

The app component had installed and started the helper. The sensor component
created `_squirrelops` with UID/GID 309, restored the bounded configuration,
and stopped at its service-account helper check. The sensor launchd bootstrap
comes after that check and was not reached. The log's earlier unsigned-package
warning was not the terminating error: PackageKit proceeded through payload
extraction and component scripts under the explicit local-test opt-in.

Read-only SSH checks confirmed:

- `/Library/SquirrelOps/sensor` is `root:wheel`, mode **0700**.
- The account UID and primary GID are 309, with shell `/usr/bin/false`.
- App and helper executable digests match the candidate.
- Neither product launchd job is loaded; neither component receipt exists.
- Neither approved VIP appears in interface or proxy-ARP output.
- Existing Ethernet, Wi-Fi and Tailscale addresses remain present.

Matt supplied the attended harness's completion output confirming test service
stop, alias withdrawal and release of only its PF reference. Installed files,
the service account and private data were retained. PF release was reported by
the root harness, not independently re-queried by unprivileged SSH.

## Cause and local correction

The harness sets `umask(077)` for private evidence and then called
`SENSOR.mkdir(mode=0o755)`. The mask reduces that mode to 0700. Package extraction
retained the existing parent directory's mode. The package's helper probe runs
the installed Python as `_squirrelops`; that user cannot traverse a root-owned
0700 ancestor. The probe suppresses its stderr, so the package reported the
generic helper-readiness failure rather than the underlying access problem.

The fresh-install harness now explicitly sets the newly created sensor
directory to 0755 after protecting its configuration with mode 0600. It still
refuses to reuse or overwrite an existing installation in fresh-install mode.
This fixes the acceptance setup; no product source or package bytes changed.

## Exact recovery scope

Use `--resume-failed-install` only for this mini and this failed attempt.
It is not a general upgrade, repair, uninstall or remote root-command service.
The existing approved VIP, interface, package, protocol-test and cleanup scope
in [the setup record](2026-09-28-mini-install-test-scope.md) remains unchanged.

Before any permission correction or installation, recovery must verify:

1. The original host, OS build, routes, interfaces and free-space conditions.
2. The exact failed baseline, its pinned prior script and bounded config.
3. Matching installed app/helper/guest hashes, root-owned executable files,
   and the observed root-owned 0700 sensor directory.
4. The exact non-login service identity 309:309, no service-UID processes,
   no running product app and neither product launchd job loaded.
5. The expected mode-0600 service-owned configuration with unchanged digest,
   and empty service-owned mode-0700 data/log directories. Unexpected content
   is preserved and stops recovery; it is never deleted to make the check pass.
6. No component receipts, staged service identities, outstanding local-test
   opt-in, owned test addresses, or assigned/published test VIPs.
7. PF disabled with no states, complete empty named-anchor inventory, and the
   existing listener baseline. Repeat the PF inventory immediately before use.

Mutation preview:

| Target | Change |
| --- | --- |
| New root-private acceptance baseline | Save the existing config, state description, recovery inverse and observations; retain every earlier backup |
| `/Library/SquirrelOps/sensor` | Change this **one directory only**, 0700 to 0755; no recursive chmod/chown |
| Config, private data and logs | Preserve contents and restrictive permissions |
| Service-account execution | Run only a credential-free isolated Python UID probe before Installer; require UID 309 |
| PF | Acquire and record only the test-owned reference after inventory; preserve unrelated anchors |
| Installer | Retry the identical checksum-pinned package using the one-time local-test opt-in; normal package preinstall creates its own additional durable snapshot |
| Test lifecycle | Same bounded guest tests and stop/withdraw/release cleanup as previously approved |

The account, installation and backups are not removed. No new API credentials
or root access are granted to the SSH user. The inverse for the specific
permission change is restoring that one directory to root:wheel 0700, **only
after** product services are stopped and test aliases are absent. This returns
the directory to the observed broken pre-recovery state, not a working install.
Retain all data and do not reset PF globally. On an uncertain installer or
cleanup failure, preserve protection and inspect evidence rather than forcing
the inverse.

## Local verification

- Reproduced the umask defect with a real temporary directory: expected 0755,
  observed 0700. The regression failed before the explicit mode correction.
- `sensor/.venv/bin/python -B docs/testing/fixtures/test_mini_acceptance.py`:
  **28 tests passed**. Includes the corrected permissions, preservation of an
  existing directory, accepted exact recovery fixture, and rejection of changed
  data, config, binary, phase, UID, directory mode, symlink and running process.
- Executed bootstrap argument construction with the actual `/bin/bash` and
  `set -eu`. Caught the Bash 3.2 empty-array/nounset error before staging and
  verified both fresh and recovery argument lists after correction.
- Ruff passed; `bash -n` passed. Recovery plan mode is non-mutating.
- These tests are local fixtures, not live installation or A5 acceptance.

## Staged recovery inputs

Server directory: `/Users/matt/squirrelops-mini-test.yktIwbVu`.
The second-attempt scripts are retained there as
`start-mini-acceptance.pf-retry.sh` and `mini_acceptance.pf-retry.py`; their
checksums were verified before replacement. Initial-attempt copies also remain.

| Input | SHA-256 |
| --- | --- |
| `start-mini-acceptance.sh` | `2ea3332bdb536fea9d8fdd9f4602dd4b8d70a94085437cb5e91de5a99eb8fc72` |
| `mini_acceptance.py` | `47b6c6df59083230ac63f97f1b32c55fa804f71839d433bfbc9fb952bf7bd40a` |
| `mini-a5-config.yaml` | `6e210567e3baae3950d91153b44090876ae6978b2a67677b1690aaf5c8f02330` |
| `candidate.pkg` | `3e8c0fc78befad3365fdbff5583d9f85c6b6fe01816b5863edbebeceaa4b8f5f` |

After remote hash and shell-syntax verification, the attended recovery command
is:

```sh
sudo /bin/bash /Users/matt/squirrelops-mini-test.yktIwbVu/start-mini-acceptance.sh --resume-failed-install
```

On `READY FOR TESTS`, leave Terminal open. If recovery stops, retain the new
evidence and report the reason. Do not rerun fresh-install mode, remove the
service account, or open the app against the partial installation.

No commit, push, package rebuild, public release or A5 gate closure is claimed.

Pre-execution staging check: all four remote hashes match the table, and `bash -n`
passed on the mini. All 28 tests also passed using the candidate package's
extracted, isolated Python interpreter. Privileged recovery had not yet been
executed at that checkpoint; the linked live report records the subsequent run.

At that staging checkpoint, the attempted fresh laptop ARP conflict check could not run: SSH to
`root@192.168.1.7` timed out before connecting. Do not count that attempt as an
ARP result. Wake/reconnect the authorized laptop before the next protocol-test
window, then repeat the two-address conflict check. Earlier unanswered probes
and Matt's address confirmation remain historical evidence only.
