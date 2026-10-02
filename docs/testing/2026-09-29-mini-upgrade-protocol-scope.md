# Mini shutdown-fix upgrade and protocol acceptance proposal

Date: 2026-09-29. Status: **Matt approved this exact installer and bounded
privileged test scope with "approved"**. Preparation and staging do not establish
installation or live acceptance. Execution results are recorded separately.

## Why this is the next test

The changed-script control passed all six TCP banner checks, with no new prompt
reported by Matt and verified cleanup. It does not establish that virtual-IP
SSH/SMB decoys work. See the [completed control](2026-09-29-mini-tcp-changed-script.md).

Fresh read-only inspection found the mini still on the September 28 package.
Both product launchd jobs were absent, no matching product runtime was found,
and neither test VIP was assigned. Installed app, helper and guest executable
hashes matched the older acceptance package. The private configuration was not
readable as `matt`; its current digest remains a root preflight requirement.
PF state was last verified by the completed diagnostic, not by this unprivileged
inspection. Recheck it before any startup.

The newer package fixes cleanup before Uvicorn replays shutdown signals. Testing
it covers both ordinary protocols and that fix. Reusing the earlier fresh-install
or recovery scripts is unsafe against the now-installed baseline.

## Exact artifact and verification

- Server: `matt@100.108.203.27`, mini, macOS 27.0 build `26A428`, ARM64.
- Client: existing authorized laptop `root@192.168.1.7`, `wlp0s20f3`.
- Package: `build/test-artifacts/SquirrelOpsHome-2.1.0-shutdown-fix-20260929-local-test.pkg`.
- SHA-256: `541fc783c41fd2f9a6baba1fe8edae93078a0a24089b8e6d4ede77ba051b7fb1`.
- Source fix: `3b990e83d43c232dec142c1d665381e9f64375c5`.
- This is an **unsigned, unnotarized local-test installer**, not a public release.

Fresh local verification: package checksum matched; `pkgutil --check-signature`
confirmed no package signature; extracted app `codesign --verify --deep --strict`
passed for its ad-hoc signatures. Both real-process shutdown regression tests
passed against the extracted installer Python/runtime:

```sh
# From this checkout's sensor directory; no installed service is started.
SQUIRRELOPS_TEST_SENSOR_PYTHON='/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/build/test-artifacts/shutdown-fix-extracted-20260929/sensor.pkg/Payload/Library/SquirrelOps/sensor/python/bin/python3.12' .venv/bin/python -m pytest tests/unit/test_runtime_shutdown.py -k server_signal -q
```

Result: **2 passed, 9 deselected**. Earlier broader results and their limits are
in the [shutdown fix report](2026-09-29-signal-shutdown-release-followup.md).
Those broader suites were not rerun during this proposal preparation.

## Proposed changes and safeguards

| Target | Proposed effect |
| --- | --- |
| One installed app bundle, sensor runtime, helper and two product LaunchDaemons | Upgrade to the checksum-pinned package; retain version label 2.1.0 |
| Existing `_squirrelops` account, configuration, database and pairing material | Back up privately; preserve account and configuration, allow normal package migrations without resetting data |
| `192.168.1.240` and `.241` | At most two temporary /32 aliases with proxy ARP on mini `en0` after fresh conflict checks |
| PF | After inspecting loaded policy, acquire only a test-owned enable reference; permit product-owned containment/redirect rules |
| Test services | One deep guest, up to three classic host listeners, management API on 8443 and existing bounded discovery on `192.168.1.0/24` |
| Laptop client | Bounded protocol and synthetic file tests against verified decoy endpoints only |

Before mutation, an existing-install-aware harness must validate the exact old
payload identities and stopped state, actual service UID/GID, configuration,
interfaces (`en0` .115 and `en1` .254), free space, listeners and VIP conflicts.
Abort on drift. Do not assume a silent ARP check guarantees future availability.

Create and verify a unique root-private backup outside installer pruning, under
`/Library/SquirrelOps/acceptance-backups/`. Preserve old installed payloads,
configuration, consistent SQLite backup, certificates/pairing material, existing
package backup inventory/content, receipts, launchd metadata and network/PF
baseline. Check SQLite integrity and copy identities before installation. The
package's own upgrade snapshot/pruning must not erase the independent baseline.

Enumerate loaded PF filter/NAT rules and named anchors, including the macOS 27
recursive-query limitation. Abort before enabling on unexplained policy. Record
the test's own PF token privately. Never globally disable/flush PF or reload the
main ruleset. Keep host SSH 22, SMB 445, Screen Sharing 5900, Ollama, Tailscale,
VPNs and unrelated interfaces/anchors untouched.

No Little Snitch, Avast or other filter-rule edits. If a prompt appears, leave
it unanswered and record the process and requested connection. The earlier
approval's identity, scope and lifetime are unknown.

After approval, prepare and verify the bounded harness and its cleanup tests,
stage pinned files, then provide **one attended sudo command in Terminal on the
mini**. Do not use persistent root access or request passwords in chat. Keep the
app closed. Use the package's one-use local-test opt-in, without bypassing OS
security controls. The installer starts product services, so containment must
be ready before installation, not added afterward.

## Acceptance and limits

Observation window: at most 20 minutes after readiness; Return stops early.

1. Verify installed hashes, retained configuration, API health, actual guest/VIP
   mapping, UID-guarded redirects and original native listener parity. Abort if
   a product alias is outside the approved pair. Discover backend ports anew.
2. From the laptop, require an SSH banner, SMB negotiation and HTTP response
   before attempting authentication. Permit at most three bounded connection
   attempts per selected service for initial readiness. TCP success alone fails
   protocol acceptance. Stop credential/file tests when identity is uncertain.
3. Per verified SSH/SMB service, try one deliberately wrong synthetic password,
   then one valid synthetic guest login. Read persona data and perform SFTP/SMB
   upload, download/content comparison and deletion of one uniquely named
   synthetic file per protocol. No credential spraying, exploitation or host
   filesystem access. Keep synthetic secrets out of arguments and shared logs.
4. Compare connection/alert records before and after, checking source attribution
   to `.7`, protocol evidence and expected alert grouping. Record all failures.
5. Check direct access to each discovered private backend is denied. Observe
   real ingress before making any secondary-interface isolation claim; merely
   targeting the Wi-Fi address is insufficient. Capture only scoped packet
   metadata needed for diagnosis; keep raw private evidence out of shared reports.
6. Verify normal shutdown with the new package and independently recheck stopped
   processes/listeners, withdrawn VIPs and retained native endpoints.

This is ordinary acceptance, **not** the separate A5 fault-injection/old-rule
upgrade matrix. It does not authorize signing, release publication, a website
change, commit, push or merge.

## Cleanup and inverse

The harness must include a tested, bounded cleanup path before execution:

- Stop the sensor normally and poll for launchd/process exit. Check exact guest
  identities; do not count OS-owned `distnoted` as a surviving sensor merely
  because it shares the service UID. Never kill all processes of that UID.
- Verify guest/backend exit, then withdraw only ledger-owned proxy ARP and VIP
  aliases while containment remains in place. Verify absence before removing
  the product rules. On uncertainty, retain protection and stop for review.
- Stop the helper and release only the recorded test PF reference after safe
  withdrawal. Preserve any other owner's PF reference or rules.
- Verify native service endpoints, routes and baseline PF policy; retain private
  logs, data, backups and the upgraded installation in the stopped state.

The default failure state is **stopped with evidence retained**, not an automatic
downgrade. The preserved old payload/data form the rollback source; restoring
them requires a reviewed exact-path inverse and separate approval. Do not reuse
the old session-specific cleanup script or uninstall the app to recover.

Approved scope: install the exact shutdown-fix package on the mini, then
run the bounded ordinary SSH/SMB/HTTP acceptance and cleanup above. The new
harness is prepared separately; this document is the execution scope, not a
claim that installation or acceptance has occurred. Backups omit stale Unix
socket files, which cannot be restored as durable data; their original paths
and metadata remain in the private manifest.
