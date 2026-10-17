# Home 2.1 live acceptance preflight and maintenance proposal

Date: 2026-09-28. Status: **read-only preflight passed; live acceptance pending**.

Matt approved proceeding toward release and acceptance. The checks below do not
waive the [A5 live PF gate](2026-09-26-pf-safety-development.md#live-acceptance-gate-not-executed).
No installer, service restart, PF mutation, alias mutation, tag creation, or
release dispatch was performed in this pass. A single administrator prompt was
used only for read-only firewall, ownership-ledger, and database queries.

## Source and artifact identity

- Chrissy approved PR #49 at `0c9ce026adfad24be0f0fe40dfeadbbfe6936eb3`.
- Merged main: `6db225c8133f91bd9042924d9b6a5e2896076a05`.
- GitHub's comparison from the candidate to the merge reports no changed files.
- The local candidate worktree remains at `0c9ce02`; it was not reset or switched.
- Merged-main [App CI](https://github.com/rocketweb/squirrelops-home/actions/runs/36464531204),
  [Sensor CI](https://github.com/rocketweb/squirrelops-home/actions/runs/36464531033),
  and [Supply Chain CI](https://github.com/rocketweb/squirrelops-home/actions/runs/36464531245)
  all completed successfully.

Proposed upgrade artifact, relative to this worktree:
`build/test-artifacts/SquirrelOpsHome-2.1.0-availability-local-test.pkg`.
Its freshly verified SHA-256 is:

```text
cc285b1c0061c1d424b602d43b1dc7e9a5573851a40e4a6a81f445eed32855e7
```

The extracted app passed `codesign --verify --deep --strict`. This is an
unsigned local-test package with ad-hoc-signed executables, not a notarized
release installer. It must not be uploaded as the public release artifact.

Fresh executable hashes show that the current installation is not this package:

| Executable | Installed SHA-256 | Candidate SHA-256 |
| --- | --- | --- |
| App | `596df4e68eecf53cb4b49e1addd892913f27f7424957f260e84481a7cbc80b9f` | `f390cc64e9abc47fc502c1bfd56de67d1e5c967ee371733ecf068284f0c8f9a2` |
| Helper | `9790f88bc8ce7f685d43f11acda79de3ec00a5314c469fbd01cbf7e85be525f2` | `92a00ba7ff524f517193ec370c9c5d6108ea678705a675674d129e59c318b341` |
| Guest runtime | `70c457a39df459987b3dc25afb8919e7988fc51d1c344754e548a946ec0c926b` | `ffe268c31243004ebab5aaef12725a7e5308cbd5f81fa804edd6205a82704387` |

Both installed component receipts say 2.1.0, installed at
`2026-09-26T21:00:43Z`. Version labels alone cannot identify this candidate.

## Observed host and blast radius

- macOS 27.0, build `26A428`, ARM64. Console UID 501; sensor UID/GID 309.
- Sensor and helper launchd jobs are running.
- The rebuilt helper's live read-only resolver selects Ethernet `en0`, address
  `192.168.1.18`, gateway `192.168.1.1`, subnet `192.168.1.0/24`.
- Wi-Fi `en1` also has an address, `192.168.1.79`. The system default route is
  through VPN interface `utun7`; tests must explicitly verify physical ingress.
- The database reports 30 active and 1,249 stopped decoy rows. These are a
  point-in-time inventory, not a new finding that stopped rows are defective.
- The root-owned ledger, live loopback aliases, and unreleased virtual-IP rows
  agree on ten addresses on `en0`: `192.168.1.200`, `.201`, `.206`, `.208`,
  `.209`, `.211`, `.214`, `.215`, `.216`, and `.217`.
- The `com.apple/squirrelops` anchor has 30 redirects and 30 TCP UID-guarded
  passes for UID 309. Twelve VIPs have default-deny rules; the additional `.207`
  and `.228` are quarantine-only in this snapshot, not additional owned aliases.
- PF is enabled. Its global state count was zero at the snapshot. This is not
  evidence of successful state cleanup or a substitute for established-flow tests.
- No process matched the guest-runtime executable name at the observation time.
  This does not establish whether a stopped guest was intended or failed.

An installed upgrade can interrupt all 30 active service decoys, not just one
SSH/SMB test host. Existing guarded rules mean this Mac's current installation
is **not** a baseline for migration from the older unconditional `rdr pass` rules.

## Fresh local checks

The CLT/macOS 26.5 SDK command from `docs/DEVELOPMENT.md` rebuilt the test bundles
successfully in 10.92 seconds. Existing CLT linker and Swift capture warnings
remain; no product source was changed to suppress them.

The rebuilt `SquirrelOpsHelperTests` bundle ran with
`SQUIRRELOPS_TEST_LIVE_LAN=1`: **121 tests in eight suites passed in 4.988 seconds**.
This includes actual LAN observation and `pfctl -n` syntax checks. PF load,
quarantine-failure, and state-cleanup paths use injected runners, not live rules.

From `sensor/`:

```bash
.venv/bin/python -m pytest tests/unit/test_package_security.py \
  tests/unit/test_pkg_sqlite_backup.py -q --tb=short -ra
```

Result: **27 passed in 0.71 seconds**. Backup tests use disposable fixtures,
not the installed database. No new installed-system rollback claim is made.

Raw records are ignored local artifacts under `build/test-artifacts/`:

- `2026-09-28-acceptance-preflight-build.log`
- `2026-09-28-acceptance-preflight-helper.log`
- `2026-09-28-acceptance-preflight-package.log`
- `2026-09-28-acceptance-readonly-pf.log`

The PF snapshot is diagnostic evidence, **not a restorable system backup**.

After this preflight, Matt authorized the Linux laptop. The separate
[laptop LAN baseline](2026-09-28-laptop-lan-baseline.md) records reachable mimic
ports, blocked direct backends, six attributed connections, and a persisted
scan alert. The Studio guest was stopped; no upgrade or real-guest acceptance
is implied by that follow-up.

## Next maintenance scope, not yet executed

### 1. Back up and upgrade this Mac

Obtain approval for this exact package and interruption of the current 30 active
service decoys. Do not infer maintenance approval from the read-only password prompt.

Before installing:

1. Refresh the inventory and package digest. Abort on unexpected drift.
2. Prepare a root-only backup outside the installer's snapshot-retention path,
   under `/Library/SquirrelOps/acceptance-backups/` with a unique directory.
   Preserve the app, installed privileged helper, sensor payload/configuration,
   launchd plists, helper ownership ledger, package receipts, existing installer
   snapshots, and the relevant network observations. Never print stored secrets.
3. Quiesce the sensor within the approved maintenance window before the durable
   data copy. Create a standalone SQLite backup, verify its integrity, and
   retain checksums and ownership/mode metadata. Preserve both the files and the
   database required to recover enrollment and credential history.
4. Abort if backup verification, available disk space, or recovery prerequisites
   fail. Do not rely only on the package's automatic preinstall backup.
5. Create the one-attempt local-test opt-in and install only the digest-pinned
   package. Its scripts replace the app/helper/sensor and restart the services;
   they manage only SquirrelOps network state. No global PF reset is authorized.
6. Verify installed executable hashes, service health, settings/enrollment,
   durable-data continuity, advertised addresses, and restored decoy status.

Rollback preparation must retain the old payload and a verified data snapshot,
with exact service stop/restore/start operations reviewed before installation.
If rollback is needed, preserve post-test data separately before restoring the
quiesced snapshot. Reconcile only the recorded SquirrelOps network scope through
validated helper behavior. Do not blindly reload stale rules or ownership state,
discard new records, flush unrelated anchors, or disable global PF. If safe
recovery cannot be established, keep affected test endpoints quarantined and stop.

### 2. Second-machine protocol acceptance

Confirm a client machine and access first. The earlier Linux client was
`192.168.1.7`; its current availability and SSH authorization are not assumed.
No remote command was run during this preflight.

Use only the newly verified Studio Build Mac VIP, not a remembered example IP.
Record the pre-test counters and source address, then exercise the bounded
SSH/SFTP/SMB procedure in `docs/USER_GUIDE.md`. Verify actual content, source
attribution, connection evidence, and alert behavior. Write/delete only named
synthetic test files in the disposable guest. Distinguish incident grouping
from missing connection telemetry. Record ordinary-protocol behavior separately
from availability and containment checks.

### 3. Isolated A5 fault injection and older-rule migration

Use an isolated Mac for the full failure matrix and older-rule upgrade, or
prepare a separately approved isolation harness. The production helper replaces
the complete `com.apple/squirrelops` anchor. Do not send it a test-only replacement
that could omit the ten existing owned aliases.

The exact host, two conflict-checked VIPs, ingress interfaces, private ports,
UIDs, anchor, and inverse operations must be pinned before executing this stage.
An incomplete ARP entry does not prove an address is free, and seeing two active
interfaces does not prove packets reached both. Do not enable new interfaces or
change VPN policy to make a test pass without approval.

Cover all seven cases in the A5 record: healthy ingress, direct backend and
second-interface denial, different-UID/missing/ambiguous listeners, established
state and retransmission/reuse, quarantine plus state-cleanup failures,
multi-endpoint recovery and alias gating, older-rule package migration, and
verified restoration. Record actual packets, listener receipts, and PF state.
Mocked tests and the current guarded-rule upgrade do not close this stage.

## Release decision

Platform scope corrected September 30, 2026: Home 2.1 supports Apple Silicon
only. Intel execution is not a release gate. See
[macOS release support](../RELEASE_SECURITY.md#macos-release-support).

Release approval and the merged code review are recorded. The remaining gates
are acceptance evidence, not another request to approve the same source. Final
Developer ID-signed/notarized artifact acceptance remains separate from this
ARM64 local-test package. No gate is marked passed by this plan.

Proceed to protected signed tags and the approved release workflow only after
the documented gates are closed. Chrissy's protected-environment approvals remain
independent. Do not bypass them, publish the local-test package, or promote the
website/Homebrew tap as part of this maintenance scope.
