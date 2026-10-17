# Resolver-fix Mini acceptance: prepared locally, not started

**Subsequent approval:** Matt approved the exact next run. The
[staging handoff](2026-10-01-mini-resolver-staging.md) records verified remote
copies and the attended command. No live run had started at that handoff.

The next acceptance run is prepared for the exact rebuilt installer. Nothing
was installed, started, remotely staged, committed, pushed or published in this
preparation. Mini and laptop access was read-only; no decoy probes were sent.
See the [proposed scope](2026-10-01-mini-resolver-scope.md) for approval.

## Current evidence

Read-only SSH inspection at `2026-10-02 01:01:26 UTC` confirmed the Mini remains
ARM64 on macOS build `26A434`, boot `1790777754`. Both product jobs are disabled
and unloaded, no product process was found, and neither `.240` nor `.241` was
present as an interface alias. The sensor receipt remains 2.1.0 with install
time `1790818368`. The old guest manifest and executable match their recorded
hashes. The unrelated recovery-test launchd job was not changed.

The laptop still routes `.240` through `wlp0s20f3` with source `.7` and has
Samba `4.19.5-Ubuntu` and `pexpect`. These checks did not contact the decoy.
Privileged PF, database and ownership checks await the attended preflight;
the current Little Snitch rule was not independently inspected.

## Reused safeguards and new checks

The runner inherits the reviewed relay upgrade's installation, normal restart,
20-minute observation, stop, alias withdrawal, hold restoration and single
PF-reference release methods without editing historical fixtures. Its package
pin, current receipt, old/new payload inventory and scope are refreshed.
The root-private claim from the completed SMB diagnostic resolves the exact
prior backup; its successful cleanup receipt is pinned at
`4cd666f50c23dd87fda61f04e41f9aa41d42c2f176e959e682f6719a1dc1e286`.

Both old and new guest manifests are pinned. The packaged production bundle
validator checks the kernel/initramfs checksums and ownership before installation
and before readiness. Large guest images use the validator's own streaming
bounds, not the smaller executable/evidence bounds.

The laptop client preserves the reviewed protocol, containment, authentication
and synthetic file-operation sequence. It has a new single-use results path,
exact package/scope/boot checks and five distinct mappings on `.240` only.
SMB uses empty client configuration, disabled Kerberos and explicit IP/port.
Anonymous listing explicitly uses an empty username/password. All four expected
shares must appear, exit must be zero and total client time must be at most
five seconds. A slow success fails the normal protocol gate before containment,
authentication or file writes. This threshold is a regression gate, not a
claim that local handshake time and Linux share-listing time are identical.

## Verification this turn

New tests initially failed because the new modules were absent. Disabling the
timing guard later made both the boundary test and mocked full client test fail;
the latter attempted a prohibited later probe. Restoring the guard passed.
The same mock verifies that a second run fails before any client traffic.

```sh
SQUIRRELOPS_TEST_RESOLVER_PACKAGE_EXPANDED="$PWD/build/test-artifacts/resolver-20261001-expanded" \
  sensor/.venv/bin/python -B -m unittest discover \
  -s docs/testing/fixtures -p test_mini_resolver_acceptance.py -q

SQUIRRELOPS_TEST_RESOLVER_PACKAGE_EXPANDED="$PWD/build/test-artifacts/resolver-20261001-expanded" \
  build/test-artifacts/resolver-20261001-expanded/sensor.pkg/Payload/Library/SquirrelOps/sensor/python/bin/python3.12 \
  -I -B -m unittest discover -s docs/testing/fixtures -p test_mini_resolver_acceptance.py -q

SQUIRRELOPS_TEST_RESOLVER_PACKAGE_EXPANDED="$PWD/build/test-artifacts/resolver-20261001-expanded" \
  sensor/.venv/bin/python -B -m unittest discover \
  -s docs/testing/fixtures -p 'test_mini*.py' -q
```

- **12 focused checks passed** with development Python and isolated packaged Python.
- Full harness: **369 total, 366 passed, 3 existing optional skips**, 4.729 seconds.
- The first sandboxed full run failed four existing disposable-listener tests
  with `Operation not permitted`; rerunning with localhost socket access passed.
- Exact new payload pins, every bootstrap input hash, both plan-only defaults,
  shell syntax and `git diff --check` passed.
- No live guest was started by these harness tests. Mock cleanup messages in
  the logs are not evidence of live cleanup.

Logs: `build/test-artifacts/resolver-20261001-harness-tests.log` and
`resolver-20261001-harness-tests-unsandboxed.log`. The earlier real-guest,
packaged-runtime and full sensor results remain in the
[resolver fix report](2026-10-01-guest-resolver-fix.md); they were not rerun here.

## Pins and handoff

| Input | SHA-256 |
| --- | --- |
| Installer | `47774088cd9eadc5aaddf38949e00a8b8f6eeb56c2192a5a72830d06d84a8aec` |
| Mini runner | `1c79da779c82208f8524ddf4eaac338b8d68ad2dd7dc96e487bc66375ecaaab4` |
| Mini bootstrap | `a56ab1bdb308092d4994bb9633167c0b287755afcbe5c1bb7ee10a60d89557d9` |
| Laptop client | `6c3c9c28a9e994ea11f856ca76de46fac58507a72cad97ee962c6df88e6676ec` |
| Scope | `18ced0435d5818755d7503bbb0339e56f7d72d7fbae6642a4830bef996b2333a` |

After approval, stage the bootstrap and all pinned inputs in a new Mini
`/Users/matt/squirrelops-mini-resolver.*` directory. Name the package
`candidate.pkg`, the scope `approved-scope.md`, and the existing config
reference `single-ip-config.yaml`. Do not reuse consumed staging or claims.
Verify all hashes and run only plan mode during staging. The operator runs
the bootstrap with sudo on the Mini and confirms
`INSTALL RESOLVER FIX AND TEST 240` after backup verification.

Prepare the laptop client in a fresh root-owned 0700
`/root/squirrelops-mini-resolver-client.*` directory. At `READY FOR TESTS`,
privately transfer fresh root-produced `status.json`, `endpoints.json` and
synthetic `login.json`, then invoke the client once with `--run DIRECTORY`.
Do not print the login. Its built-in freshness, package and route checks must
pass. Review sanitized client results and before/after alert and connection
evidence, ask the operator to press Return, then verify the cleanup receipt,
disabled jobs and absent aliases. Report any new filter prompt without changing
or renewing the filter rule.

The engineering-constraints skill informed failing-regression verification and
the distinction between prepared local checks and unperformed live acceptance.
No live or public release gate is marked complete by this document.
