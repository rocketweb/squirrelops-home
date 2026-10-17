# Classic-decoy ownership fix and installer rebuild

Date: 2026-09-29. Local source fix and package rebuild. No installation,
mini data repair, firewall change, commit, push, or release was performed.

## Cause and change

The [failed mini upgrade](2026-09-29-mini-upgrade-live-result.md) exposed an
ownership error in classic startup. The query selected every active/degraded
row except `mimic`, including the five `deep` service rows. The three-listener
limit stopped two rows. The factory treated the remaining unknown `deep` types
as HTTP file shares, which could then fail on occupied native ports and be
marked stopped. Deep startup correctly respected the resulting stopped state.

The classic manager now uses a positive type allowlist shared by selection and
admission: `file_share`, `dev_server`, and `home_assistant`.

- Startup, profile changes, degraded recovery, and auto-deploy capacity ignore
  deep, mimic, and unknown-family rows.
- Enable, disable, and restart decline foreign IDs without changing them.
- Instance construction, persistence, and deployment reject unsupported types
  before generating bait, writing rows, opening listeners, or publishing events.
- Studio's five services no longer consume the classic listener limit.
- Existing operator-stopped rows remain stopped. No schema or data migration
  attempts to infer which stopped hosts should be re-enabled.

The `/decoys` API remains authoritative for all families. Its routes and status
aggregation were not changed. The historical migration's descriptive
service-name backfill was also left unchanged; it is not a lifecycle owner.

## Regression evidence

Forty-two new ownership/restart cases and three presentation snapshots were
added. External guest/network operations are fakes in the lifecycle tests;
SQLite, migrations, lifecycle selection, and persistence are real.

The finalized 41-case lifecycle matrix was rerun against the preserved old
package's modules: **33 failed, 8 passed**. Active Studio restart and migration
replay failed; intentionally stopped hosts and the previously excluded mimic
paths were among the controls that passed. The separate isolated-interpreter
restart test also failed against that old package with
`Guest state changed during classic startup`.

The corrected source passed the 124-test focused lifecycle/API/runtime set.
The final full-suite result is recorded below. The three presentation snapshots
were captured from the old package and pass with the new factory.

| Check | Result |
| --- | --- |
| Sensor full suite, initial run | 2,398 passed, 1 opt-in live guest test skipped |
| Sensor full suite, final snapshot-inclusive run | 2,401 passed, 1 opt-in live guest test skipped; live acceptance passed separately |
| Focused ownership, deep/classic lifecycle, routes, isolated restart | 124 passed |
| Classic route-presentation snapshots | 3 passed |
| Ruff, `src tests` | Passed |
| Pyright, `src/` | 0 errors, 29 warnings |
| Pyright, four changed/new test modules | 0 errors, 5 warnings in existing deep test fixtures |
| Swift app tests | 400 passed |
| Swift helper tests | 121 passed |
| Swift guest tests | 23 passed |
| Extracted Python restart plus SIGTERM/SIGINT child-process tests | 3 passed |
| Real extracted guest runtime, SSH/SFTP/SMB acceptance | 1 passed, 59.55 seconds |
| Extracted app, strict deep code-signature verification | Passed, ad-hoc signature |
| Installer signature | Unsigned local-test package, not notarized |

The persisted deep-host test provisions a host, stops the runtime, closes the
database, reopens it, optionally replays migrations, and runs classic startup
before deep startup. Active services resume through the deep manager. Deliberate
stops remain stopped. Service IDs/state are unchanged by classic startup, and
the planted credential rows survive deep restart unchanged. Native-port
conflicts are simulated; these tests never bind SSH/SMB on the host.

The packaged restart test launches the selected Python interpreter with `-I`
and checks module provenance inside that runtime. It reopens the database and
runs the startup sequence twice. This detects a stale installer even if the
checkout itself contains the fix. The two packaged signal tests retain coverage
for the earlier asynchronous shutdown fix.

## Deception review

Reviewed against `squirrelops/docs/deception-integrity.md`.

This changes lifecycle ownership, not attacker-facing service behavior. It
restores the intended guest protocols after restart instead of substituting
HTTP or losing the host. It adds no service authentication, lockout, rate limit,
header, TLS change, banner removal, credential-strength change, or delay.

The old and new extracted sensor source trees differ only in
`decoys/orchestrator.py` when bytecode caches are excluded. Guest resources are
byte-identical. Response handlers, credential generation, guest configuration,
persona, relay policy, and telemetry code are unchanged.

The new snapshots pin each supported factory's route methods, status codes,
headers, and exact response-body bytes with fixed synthetic bait and a custom
credential filename. Existing HTTP response, credential detection, AI surface,
and persona archive tests also passed in the full suite. These are route-content
snapshots, not a claim that dynamic wire timestamps or measured network latency
are identical. No timing code changed; the real guest test covers existing
timeout/half-close behavior without introducing new timing policy.

Real guest acceptance covered scanner-style SSH banner requests, failed logins
followed by a valid login, the existing capacity ceiling, guest EOF behavior,
macOS-shaped persona commands, SFTP reads/writes, SMB reads/writes/deletes,
20 reconnect cycles, half-closed SMB connections, connection telemetry, host
canary isolation, and clean exit with both protocol relays open.

The first live attempt correctly rejected the user-owned expanded guest
directory. The release runtime requires root-owned guest resources. For the
passing test, it read the existing root-owned installed resources, whose
manifest, kernel, and initramfs hashes exactly match the new package. The
runtime executable came from the new package. No installed files were modified,
no trust check was disabled, and the disposable guest used loopback only.

## Exact artifact

Checkout: `/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current`

Branch: `feature/ai-setup-2.1`

Base commit: `3b990e83d43c232dec142c1d665381e9f64375c5`, plus this uncommitted fix.

Build host: macOS 27.0 (26A428), ARM64, Xcode Swift 6.4 and its macOS 27 SDK.
The builder verified 39 pinned Python runtime distributions.

Installer:
`build/test-artifacts/SquirrelOpsHome-2.1.0-ownership-fix-20260929-local-test.pkg`

SHA-256:

```text
2d5f4d287ca3ce971fd201f539d27a9272431f160a5a5debddc8d1b0b4dc7c82
```

Packaged `decoys/orchestrator.py` matches the source file byte-for-byte:

```text
b984836e15cb63beb4b548d1f0cc20d123044b0c6625944288cd96b62725b414
```

The previous shutdown-fix package is preserved under its original unique
filename. This package remains version 2.1.0 and is distinctly named for local
acceptance. It is not a signed/notarized public release.

Build command, from the checkout root:

```bash
SQUIRRELOPS_LOCAL_TEST_BUILD=1 SKIP_PKG_SIGNING=1 bash scripts/build-pkg.sh
```

Apple packaging tools emitted `write: Permission denied` diagnostics during
component analysis, as in the preceding build. The builder exited zero,
expansion succeeded, the embedded source matched, and strict app verification
passed. These checks do not establish a successful installed upgrade.

Logs are retained under `build/test-artifacts/ownership-fix-20260929-*`, including
`old-runtime-matrix-red.log`, `old-package-red.log`, `focused.log`,
`sensor-tests.log`, `sensor-tests.xml`, `ruff.log`, `pyright-src.json`,
`pyright-tests.json`, `swift-tests.log`, `extracted-subprocess-tests.log`,
`live-guest.log` (expected ownership rejection), `live-guest-root-owned.log`,
`build.log`, and the signature/checksum records.

## Remaining installed acceptance

Keep the mini closed/stopped. Its earlier failed upgrade already marked five
deep rows stopped; installing this fix alone does not restore their prior
active intent. A separate reviewed continuation must verify the stopped
baseline and cleanup, back up current state, identify only the five affected
rows using the retained pre-upgrade evidence, and preserve genuinely stopped
hosts and forensic history. Do not rerun the consumed upgrade harness.

That continuation needs approval for the exact replacement artifact and any
live data restoration. Then repeat real installation, restart, second-machine
SSH/SMB operations, alert correlation, and cleanup verification. Local loopback
guest acceptance is not evidence of LAN alias/PF ingress or third-party filter
compatibility. No Little Snitch rule was approved or changed in this work.

The engineering-constraints skill guided red-before-green verification. The
deception integrity review constrained the patch to lifecycle ownership, and
the my-voice guidance kept operator documentation explicit about recovery limits.
