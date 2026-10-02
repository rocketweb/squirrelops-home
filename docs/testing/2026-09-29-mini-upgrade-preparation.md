# Mini shutdown-fix upgrade: preparation and staging

Date: 2026-09-29. Status: **attended execution installed the package but failed
guest readiness**. See the [live result](2026-09-29-mini-upgrade-live-result.md).
Matt approved the [exact package and bounded scope](2026-09-29-mini-upgrade-protocol-scope.md).
This preparation record is retained for reproducibility. It does not establish
live protocol success or release readiness. Do not rerun the consumed command.

## Implementation

The new `fixtures/mini_upgrade_acceptance.py` reuses the earlier read-only PF
inventory, scoped ownership parser and sanitized database snapshots. It replaces
fresh-install assumptions with exact existing-install checks and an independent
private backup. The earlier acceptance and cleanup scripts are unchanged.

The runner hashes the old payload and bounded configuration, checks the existing
account/receipts/stopped state, inventories PF and native listeners, and sends
six bounded ARP conflict requests. It verifies copied backup manifests and a
consistent SQLite backup before PF enable or installation. Stale Unix sockets
are inventoried but not copied. Prior package backups are preserved outside the
installer's pruning path. A persistent exclusive attempt marker prevents replay.

Cleanup polls launchd disappearance, ignores only exact `/usr/sbin/distnoted`
processes belonging to the service account, and stops on unknown processes. It
does not force-kill an orphaned guest. Alias withdrawal must complete before
product-rule clearing and release of the recorded PF reference. Incomplete
cleanup retains evidence and requires review rather than broader resets.

The installed shutdown module, app, helper, guest and Python hashes are verified.
Readiness also requires guest endpoints and matching exact TCP tag/UID guards.
Only packet-summary text is captured, not full packet payload archives.

The laptop client discovers backend ports from that guarded snapshot, requires
fresh readiness for this package, validates its own source route, and creates
an exclusive results file. SSH, SMB and service-specific HTTP responses precede
authentication and synthetic file operations. Failed gates prevent later writes.
It has no retry/reset mode and no hardcoded backend-port range to scan.

## Verification

The engineering-constraints skill guided regression-first checks and separate
local versus installed-system claims. Three checks first reproduced the old
behaviors: counting `distnoted` as a surviving runtime, accepting unknown service
processes, and treating a launchd error as proof of absence. They passed after
the guards were implemented.

| Check | Result |
| --- | --- |
| `sensor/.venv/bin/python -m unittest discover -s docs/testing/fixtures -p 'test_mini*.py' -q` | 105 passed outside the network sandbox |
| Extracted installer Python with `-I -B -m unittest discover -s docs/testing/fixtures -p 'test_mini_upgrade*.py' -q` | 30 passed |
| Ruff on the two new runners and their test files | Passed |
| `bash -n` on new bootstrap, locally and on mini | Passed |
| Mini staged runner using installed Python, without `--run` | Plan-only passed |
| Laptop staged client without `--run` | Plan-only passed |
| Local and remote package/script/scope hashes | All matched |

An initial full test run inside the network sandbox had four permission failures
in existing disposable loopback-listener tests. They passed outside that sandbox.
No privileged operations or actual LAN probes were executed by the unit tests.
Tests do not establish that the root preflight, upgrade or live cleanup has run.

## Staged paths and identities

Mini: `/Users/matt/squirrelops-mini-upgrade.Um4HlMcy`, `matt:staff`, mode 0700.
Laptop: `/root/squirrelops-mini-upgrade-client.tnStT9B9`, `root:root`, mode 0700.

| Artifact | SHA-256 |
| --- | --- |
| `candidate.pkg` | `541fc783c41fd2f9a6baba1fe8edae93078a0a24089b8e6d4ede77ba051b7fb1` |
| `mini_acceptance.py` (unchanged dependency) | `47b6c6df59083230ac63f97f1b32c55fa804f71839d433bfbc9fb952bf7bd40a` |
| `mini_upgrade_acceptance.py` | `c61154c3b6b62cc945c62aae58eb0c6bfe259305539ef604a36708b52e098110` |
| `approved-scope.md` | `783395f91247dc2997db4af96515503a7f20222d0e6781a55a2b222e8d229648` |
| `start-mini-upgrade-acceptance.sh` | `c99a6126adec99d4d8780d5cfec45eea0498071eae115f9a4a7239e1b8c7670d` |
| Laptop `mini_upgrade_client.py` | `15b3bb270b77d3801870d2a81b64dee266a8f823ce234f6b2be2ff360b02b7f6` |

Fresh read-only checks still found macOS 27.0 build 26A428, mini en0 `.115`, en1
`.254`, absent product launchd jobs and only the expected macOS `distnoted`
process under service UID 309. The laptop routes through `wlp0s20f3` with source
`.7`; `ssh`, `sftp`, `smbclient`, Python and pexpect are available. Root-only
configuration, PF, data and conflict checks remain in the attended preflight.

## Next operator action

Keep SquirrelOps closed. Run this in **Terminal on the Mac mini**, not Studio:

```sh
sudo /bin/bash /Users/matt/squirrelops-mini-upgrade.Um4HlMcy/start-mini-upgrade-acceptance.sh
```

Report the printed status and sanitized-results path. At `READY FOR TESTS`,
leave Terminal open and tell Codex. Do not press Return until the client tests
finish; it stops early. The observation window ends automatically after 20
minutes. Leave any connection prompt unanswered and report it.

After readiness, Codex must verify root ownership and freshness of the printed
results, copy only the synthetic guest login through a private transfer to the
laptop (never display it), and transfer the endpoint/readiness snapshots with
mode 0600. Then run the staged client once, collect sanitized evidence, and
verify teardown. Do not reuse earlier root scripts, old ports, old credentials
or old result-directory paths. No new sudo command should be improvised after
a guarded stop without inspecting its evidence first.

No commit, push, public release, third-party filter changes or A5 fault injection
occurred during this preparation.
