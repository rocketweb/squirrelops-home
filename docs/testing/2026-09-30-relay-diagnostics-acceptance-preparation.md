# Relay diagnostic acceptance preparation

September 30, 2026. Local phases complete; the Mini run is staged, not executed.
No installation, service startup, new decoy probes or filter changes occurred
on the Mini in this pass. Nothing was committed, pushed or published.

Candidate: `SquirrelOpsHome-2.1.0-relay-diagnostics-20260930-local-test.pkg`.
SHA-256: `3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea`.
It remains unsigned, with ad-hoc payload signatures and no notarization.
No product source changed. All 237 source hashes recorded at build time matched
again, the package checksum passed, and strict app/deep and Python signature
checks passed. See the [build report](2026-09-30-relay-diagnostics-build.md).

## Additional verification

| Check | Result |
| --- | --- |
| Compiled app suite | 400 passed in 38 suites, including six screens at minimum/default/wide sizes |
| Compiled helper suite | 121 passed in eight suites |
| Shutdown tests with extracted installer Python and user-domain launchd opt-in | 28 passed, two dependency deprecation warnings |
| Actual release guest executable with byte-identical root-owned guest inputs | One comprehensive live test passed in 59.37 seconds |
| Full acceptance-fixture suite with old/new package-byte checks | 293 run: 292 passed, one intentional root-only recovery-probe skip |
| New diagnostic runner/client tests included above | 21 passed |
| Bootstrap syntax, whitespace and source parity | Passed |
| Local test guest cleanup | No remaining process matching either diagnostic test path |

The live test used the executable extracted from the exact installer. It covered
SSH, SFTP and SMB file operations, banner reconnects, wrong-password recovery,
16-slot capacity/recovery, half-close behavior, host containment, both diagnostic
streams and clean shutdown with open sockets. Listeners were loopback-only; the
guest had no network device. Installed services and PF were untouched.

An initial run against user-owned extracted guest files correctly failed with
`Guest file is unsafe: DeceptionGuest`. The ownership guard was not relaxed.
The successful rerun read the existing root-owned guest files in `/Applications`
without modifying them. Their manifest, kernel and initramfs SHA-256 values all
matched the new package:

```text
a8bf96c81c1eb25b63a6a9316044032b4842457ff472b0199da5aeb22ed77b2b
4c78ec153e7b8cf17011d44423ec2e11c9618933d4b931c60e63c240bf6db2f5
7b908f98c92c580622fb260f33facc4ee22e88c281d8802db561af4edd52948d
```

This is release-executable protocol evidence, not root-installed sensor-identity
or Mini LAN/PF/content-filter acceptance. The earlier 2,436-test sensor run and
30-test guest suite remain in the build report. This pass checked that their
product source was unchanged rather than relabeling them as new runs.

## Runner verification

The new runner reuses reviewed backup/shutdown/PF cleanup primitives without
rewriting consumed historical scripts. It requires the current narrowed config,
seven saved rows, empty ownership ledger, held jobs, exact boot and installed
receipt. No old config edit or database repair is repeated. Normal new classic
host listeners are retained and reported; saved-row drift or new virtual-host
scope is rejected.

Temporarily substituting the historical stale-ledger and fixed-six-row guards
made two regression tests fail. Restoring the new guards returned them to green.
The queue-export test failed before implementation and passed afterward. The
real package-byte test caught an inherited old helper hash. Strict signature
verification passed; the new runner now pins the actual new helper hash:
`60b7292f8b843fe0196f8c0025511df0a0d5665528f0c9902895f5939995c351`.
No installer change was needed.

Four synthetic-listener tests initially failed because the sandbox denied local
sockets. The full suite passed with loopback permission. Its remaining skip is
a root-only disposable system-launchd recovery experiment, not this normal
upgrade. The new runner exports fixed-vocabulary checkpoints and numeric TCP
queue/state metadata for UID 309 at `.240` with client `.7`, excluding raw log
text, other peers, credentials and PF references. Missing records still do not
establish a firewall verdict.

## Fresh host checks and staging

Read-only SSH confirmed Mini ARM64, build `26A434`, boot `1790777754`, sensor
receipt `1790784842`, and expected installed app/helper/guest/Python hashes.
Both product jobs were absent and explicitly disabled, with no matching product
process or `.240`/`.241` alias. PF and SQLite were not re-read as root; the
attended preflight must verify them afresh.

Laptop `.240` routing remains `wlp0s20f3`, source `.7`. SSH, SFTP, Samba
`4.19.5-Ubuntu` and Python `pexpect` are available. No dependency was installed.

Mini staging is mode 0700, UID 501:
`/Users/matt/squirrelops-mini-relay.C5Jt9KuC`.
The package and every script/config-reference/scope hash matched the local files.

| Input | SHA-256 |
| --- | --- |
| Bootstrap | `fd25b2326f1d463946cb2bdf031803e4b76657ab60a2ddbbd7793ccfddfd9b60` |
| Runner | `d0869d08e99ca8054f319649cb9f7023a09dcfe84692158355f5bd9cbc4e8298` |
| Scope | `0a1faf62ad5c5a301a43a775316da538ef448b710e3a1026932006de4f25dc6b` |

Fresh root-private laptop staging:
`/root/squirrelops-mini-upgrade-client.GWA3Ee6a`.
Only two scripts were copied. Plan mode passed without traffic. No credentials,
live snapshots or results file were supplied. Client SHA-256:
`bc36f73427a1a2f9b15260b922e72636b138d13330ad8329d32212ab0ab91c03`.
Underlying client SHA-256:
`15b3bb270b77d3801870d2a81b64dee266a8f823ce234f6b2be2ff360b02b7f6`.
After staging, the Mini remained disabled, with no product process or test alias.

## Next attended action

Review the [exact scope](2026-09-30-mini-relay-diagnostic-scope.md). On the Mini,
with SquirrelOps closed:

```sh
sudo /bin/bash /Users/matt/squirrelops-mini-relay.C5Jt9KuC/start-mini-relay-diagnostic-acceptance.sh
```

After fresh checks and verified backups, enter `INSTALL DIAGNOSTICS AND TEST 240`
only if the displayed scope matches. This covers one installation, one normal
restart, one bounded laptop run and verified cleanup, leaving config and the
seven existing decoy rows intact. Normal sensor discovery/auto-deployment can
run; new classic host listeners are preserved. No Little Snitch rule is changed.
Keep new filter prompts unanswered. Tell Codex when `READY FOR TESTS` appears
and leave Terminal open. The observation window is at most 20 minutes after
readiness, excluding backup/installation time. Failure can require review.

At readiness, retrieve fresh status/endpoints and the separately private
synthetic login into the new laptop directory without printing it. Recheck
package/scope/boot/source-route/deadline, then execute the client once. Correlate
its output with checkpoint/queue snapshots and counters. Failed initial
protocols skip authentication and writes; do not retry. Ask the operator to
press Return after review, then verify final cleanup. Never reuse consumed
staging or an old PF reference.

## Remaining release phases

| Phase | State |
| --- | --- |
| Source tests, diagnostic installer, exact guest protocols | Locally verified; uncommitted changes retained |
| Mini upgrade/restart and second-machine protocols | Staged; awaiting attended approval |
| Mini alert/counter attribution and cleanup for this package | Pending live run |
| A5 live listener/state/failure cases and older-rule migration | Open; separate exact scope required |
| Independent review, final signed/notarized build and acceptance | Open |
| Commit/push/merge, CI, tags, release, website/tap verification | No new action in this pass |

The engineering-constraints skill informed negative controls, exact-artifact
checks and the separation of local success from unresolved Mini behavior.
The Mini SSH/SMB stall is still unresolved until the new evidence is read.

Logs under `build/test-artifacts/`:

- `relay-diagnostics-20260930-SquirrelOpsHomeTests.log`
- `relay-diagnostics-20260930-SquirrelOpsHelperTests.log`
- `relay-diagnostics-20260930-packaged-shutdown.log`
- `relay-diagnostics-20260930-packaged-live-guest.log` (ownership rejection)
- `relay-diagnostics-20260930-release-live-guest.log` and XML (pass)
- `relay-diagnostics-20260930-all-fixtures.log`
- `relay-diagnostics-20260930-queue-negative.log`
- `relay-diagnostics-20260930-source-parity.log`
