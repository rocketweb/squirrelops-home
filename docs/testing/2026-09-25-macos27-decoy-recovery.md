# macOS 27 decoy creation recovery

Date: September 25, 2026. Host: Matt's arm64 Mac Studio, macOS 27.0 (26A428).

## Status

Repair candidate prepared and locally verified. **Not installed or accepted
against the running application's decoy-creation flow.** No database cleanup,
history deletion, service restart, VPN change, commit, push, or publication was
performed while preparing this candidate.

The prior LAN-repair package was installed by the user, who confirmed the app
worked but reported repeated password prompts and inability to create decoys
or mimics. That updates the pending-install status in the earlier
[LAN recovery report](2026-09-25-macos27-sensor-lan-recovery.md); it does not
constitute successful decoy acceptance.

## Observed failures and repairs

### 1. Newly deployed mimics were evacuated as apparent conflicts

Protected sensor logs show a successful deployment at 13:05:42 followed by:

```text
IP conflict: real device at 192.168.1.200, evacuating mimic 'business.local'
```

The sensor also reported the Mac's own Ethernet MAC at both its physical
address and virtual address as ambiguous. On this machine, Python/psutil sees
`02:00:00:00:00:00` for Ethernet, while directly invoked system `ifconfig`
sees its real MAC. A live check caught that `ifconfig` launched by Python is
also redacted. The initial subprocess-only repair was therefore rejected
before packaging, despite passing mocked regression tests.

The final repair adds the read-only `getLocalInterfaceMACs` operation to the
existing authenticated helper RPC channel. The native helper executes only
fixed `/sbin/ifconfig -a` arguments, excludes placeholders and invalid values,
and returns current identities. Allocation, conflict checks, and scan inventory
use this observation. The sensor does not learn its own identity from untrusted
ARP replies or saved configuration. Failed identity observation blocks new
allocation; failed routine telemetry does not itself prove that an existing
decoy should be removed. Real foreign-MAC conflicts remain detectable.

Live native-helper test on this machine: 24 unique local link identities,
selected LAN `en0`, address `192.168.1.18`, gateway `192.168.1.1`; the real
Ethernet MAC was present and was not the privacy placeholder. No alias, PF,
route, or VPN mutation was needed for that check.

### 2. Durable host reservations were omitted during allocation

Installed logs repeatedly show:

```text
sqlite3.IntegrityError: UNIQUE constraint failed: decoy_hosts.bind_address
```

The allocator previously reserved nonretired mimic service addresses but not
all nonretired host identities. A stopped Studio host can release its OS alias
while retaining its address for reactivation. Reproduced with fresh test
databases: a stopped Studio host, or a host with no remaining service rows,
reserved `.200`, but the old allocator still returned `.200` for a new mimic.

Allocation now reserves every unretired `decoy_hosts.bind_address`, plus the
legacy mimic/deep service reservations. Tests confirm `.201` is allocated
instead, and genuinely retired addresses can be reused while history stays
intact. The unique index is unchanged. The exact colliding installed database
row was not inspected; logs prove the collision, and the reproduced allocation
defect explains a path to it.

### 3. Classic listeners could still choose the VPN

Classic decoys had a separate bind-address resolver that preferred the global
UDP route even after the helper selected Ethernet. The regression uses an
`en0` address of `192.168.1.18` and VPN route address `100.96.4.79`.

The configured interface is now authoritative. A route-selected address is
preferred only if that interface owns it; otherwise its usable physical address
is used. A missing LAN does not fall back to the VPN or wildcard bind. Live
read-only resolution selected `192.168.1.18` while the VPN remained enabled.

### 4. Local-test credential isolation

The previous recovery package retained an older test UUID while changing its
ad-hoc signature. That violates the documented per-build Keychain-isolation
rule and may explain repeated Keychain prompts, although the precise prompt
wording was not captured. This package has a fresh, validated UUID distinct
from the previous package. It neither deletes existing credentials nor widens
their access controls. New local enrollment and actual prompt behavior still
need installed acceptance; administrator installation approval remains normal.

## Verification

The engineering-constraints skill required observed failures before repairs.
The initial six regression cases failed before the first changes. The missing
helper identity API then failed in Python and Swift before its implementation.
Live checks, rather than mocked tests alone, exposed the Python-child redaction.

| Check | Result |
| --- | --- |
| Full sensor suite, `python -m pytest -q --tb=short` | 2,246 passed, 1 skipped, 82.33 seconds |
| Focused cross-component sensor tests | 223 passed |
| Native helper suite, including live read-only LAN/MAC observation | 114 passed |
| Tests against source extracted from the exact installer | 260 passed |
| Bundled Python isolated-mode import | New identity module and helper method present |
| Extracted sensor source versus working source | Identical, excluding Python caches |
| Extracted app/sensor payloads versus staging | Identical |
| Strict deep app signature verification | Passed |
| Guest manifest and arm64 architecture verification | Passed |
| Fresh local-test Keychain UUID | Valid and different from prior package |
| Ruff and `git diff --check` | Passed |

The skipped test is the existing opt-in live guest test. Full-app SwiftUI tests
were not rerun: the available Command Line Tools lack the SwiftUI macro plugin,
and the full Xcode installation requires license acceptance. No license was
accepted. The installer retains prior app executable code, guest image/runtime,
and dependencies, rebuilds the native helper, updates the sensor, and re-signs
the app components for local testing.

The package tools emit `write: Permission denied` warnings despite a successful
build exit. Full extracted-payload comparisons and signature validation passed.
Actual installation remains a separate, unresolved gate.

Evidence is retained under `build/test-artifacts/`:

- `macos27-decoy-recovery-red.log`
- `macos27-decoy-helper-red.log`
- `macos27-decoy-helper-focused.log`
- `macos27-decoy-helper-tests.log`
- `macos27-decoy-recovery-full-green.log`
- `macos27-decoy-packaged-tests.log`
- `macos27-decoy-package-build-final.log`
- `build-macos27-decoy-repair.sh`

## Deception review

The changes repair address ownership, reservation, and intended LAN publication.
No protocol handler, banner, bait content, authentication policy, guest
containment setting, rate limit, or security header was changed by this repair.
Existing decoy protocol/response tests ran in the full sensor suite. Correct
binding and retention intentionally restore reachability; this report does not
claim new wire-level timing measurements or second-machine LAN acceptance.

The new helper method reads fixed system metadata only. Existing peer-UID
authentication and socket permissions apply; it adds no caller-selected command
execution and no new network-mutation authority.

## Exact candidate

[SquirrelOpsHome-2.1.0-macos27-decoy-repair-20260925-local-test.pkg](/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/build/test-artifacts/SquirrelOpsHome-2.1.0-macos27-decoy-repair-20260925-local-test.pkg)

- Version: 2.1.0, arm64, unsigned installer with ad-hoc-signed app components.
- Package SHA-256: `a7a09b0f15bfc368d48674e64359f22fa951c6e0c3720e147fe0068aabe0c6fc`.
- Embedded helper SHA-256: `1eb7536b22858e5574ff8a665520368be358fbd6f8ee2ae2bf18d28da69cb881`.
- Not notarized or a public release. Existing local-test opt-in policy applies.

## Pending installed acceptance and rollback boundary

Obtain permission before installing this exact candidate and testing live
creation. Batch the following into one administrator-authorized transaction
where possible; do not request or export Keychain private keys.

1. Preserve the installed app and helper before Installer can remove them.
   Let the existing sensor preinstall create and verify its quiesced database
   snapshot. Retain private backup paths and installer logs for rollback.
2. Create the one-time local-test opt-in and install the exact package above.
   Verify installer exit status, installed helper hash, and service health.
3. Reopen the app. Verify local enrollment, Settings loading, and preserved
   devices/history. Record any password prompt's exact wording and process.
4. Create or resume one classic decoy on the selected LAN, then Fill Capacity
   for mimics. Record actual host IDs/addresses and any per-device errors.
   No duplicate `decoy_hosts.bind_address` errors should occur.
5. Observe at least one completed ARP scan after creation. Mimics must remain
   active, their own MAC must not trigger evacuation, and genuine foreign
   address claims must still cause safe withdrawal.
6. Enable a Studio host and verify readiness, SSH/SMB listeners, and guest state.
   From an authorized second LAN machine, connect to the addresses displayed
   by this installation and verify the corresponding alert activity. Do not
   assume old `.203` still belongs to a decoy.
7. If acceptance fails, preserve diagnostics before changes. Restore only the
   backed-up application/helper and the verified installer snapshot as an
   explicitly approved rollback; do not clear history or drop uniqueness.

Passing local tests is not completion of steps 2 through 6.
