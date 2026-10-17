# Home 2.1 PF safety and control fixes: batch 2

Date: 2026-09-26. Status: **implemented and locally tested, not release-approved**.

A5 now has a kernel-owner-gated rule design and independent recovery attempts.
Its live PF acceptance gate remains open. A10's empty-page startup loop and
A12's malformed pairing-proof server error are fixed in source. The seven
fixes in the [first batch](2026-09-26-code-review-fixes.md) remain in place.
Other review items are not implicitly closed.

No installed app, helper, sensor, Keychain item, PF rule, virtual IP, proxy-ARP
entry, or network interface was changed. No installer was built or installed.
Nothing was committed, pushed, tagged, or published. Candidate 2 contains
neither review-fix batch.

## A5: design and remaining limits

The previous rules used `rdr pass`, which bypasses filter evaluation. If the
post-load listener check failed and quarantine loading failed too, that
unconditional redirect remained active.

The new design separates translation from permission:

1. A redirect marks the packet with an internal, per-VIP/per-port PF tag.
2. A TCP pass rule requires that tag, the exact translated destination, the
   selected ingress interface, and the socket's `_squirrelops` UID.
3. Untagged private-port probes and other traffic encounter the existing
   all-ingress default-deny rule for the virtual IP.

The helper resolves and pins the UID itself. The RPC request cannot choose it.
Missing, root, and unknown UIDs cannot produce a TCP publication rule. The
existing pre-load and post-load exact listener/PID checks remain, including
fresh checks that the service-account UID has not changed. The kernel guard
adds a UID boundary; it does not pin an individual process or protect against
a compromised process already running as `_squirrelops`.

This design follows the installed macOS `pf.conf(5)` manual's incoming socket
owner and tag semantics. Apple's published
[PF implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf.c)
also shows the `natpass` filter bypass, UID lookup against the translated
destination, and connection-state handling. Source inspection supports the
design but does not establish behavior of every macOS release. The local
macOS 27 parser accepts the generated rules.

The recovery path now:

- Records successfully loaded rules before the post-load ownership check, so
  the cache does not describe the previous generation after a failed rollback.
- Attempts state cleanup even when quarantine loading throws or returns a
  nonzero status. Failure on one endpoint does not skip later endpoints.
- Retains pending cleanup after any recovery failure, reports a bounded error
  naming failed phases, and does not echo child-process diagnostics.
- Refuses new alias publication from a cache entry with pending cleanup.
- Includes the allowed UID in TCP endpoint signatures, so an account-UID change
  cannot silently reuse the old endpoint's PF state. Pure quarantine endpoints
  do not incur unnecessary cleanup for a UID change.

**Existing PF states remain a separate safety boundary.** A state may bypass
new rule evaluation. A successful parser run or fresh-flow UID guard does not
prove old states were removed. The failure path continues to return an error
when quarantine, state cleanup, or PF verification fails. It does not claim
successful quarantine based only on the UID guard.

### Deception review

No decoy authentication, rate limit, lockout, TLS policy, banner, persona,
payload, or guest configuration changed. Translation destinations and service
ports are unchanged. Internal tags are not placed in the network byte stream.
The pass rule uses `flags any keep state` to avoid introducing an additional
TCP-flags restriction relative to the old unconditional translation path.
ICMP echo and the default-deny policy remain unchanged.

Healthy service behavior is intended to remain the same. Traffic to a listener
owned by another UID is intentionally blocked instead of exposing a host
service. New packet-filter evaluation can affect behavior and timing; no
byte-level/timing equivalence claim is made without the live checks below.
This is a reviewed control-boundary design candidate, not acceptance of new
attacker-visible decoy behavior.

## A10 and A12

A10: `fetchAllPages` now terminates on an empty page even if the advertised
total is larger than the cursor. This matches the app's existing refresh
pagination behavior. Its regression returns an empty page with a stale total,
then deliberately throws on a second read to bound the unfixed loop. The old
code made that second read; the fix makes one read and completes startup.

A12: the verify route accepts only a 64-character lowercase ASCII hexadecimal
proof before calling the constant-time comparator. Malformed input follows the
existing wrong-proof path: HTTP 403 and one failed attempt. This avoids the
non-ASCII `TypeError` without bypassing attempt accounting, changing valid
proofs, or adding a new decoy restriction. Tests cover accented text, emoji,
full-width digits, non-hex ASCII, empty text, and incorrect length. Existing
full pairing and concurrency tests still pass.

## Local verification

Checkout: `/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current`.
Branch: `feature/deception-depth-2.1.0-current`. Base commit:
`6b6ef8b5fe3d694695a9bc74982cbe80d05baeb5`, plus the preserved dirty release
work. The base commit alone does not identify these bytes.

`build/test-artifacts/review-batch2-source-sha256.txt` records 417 source, test,
configuration, and build inputs. Its SHA-256 is
`cd4d00546b668c12bfa69e8b3254d89496581fa942b93f4efb8074ff1d2e43db`.
All entries match after compilation. Documentation has a separate manifest.

| Check | Result | Evidence in `build/test-artifacts/` |
| --- | --- | --- |
| PF fault regressions before fixes | Four tests failed with 11 assertions | `pf-guard-red.log` |
| Live-cache ordering before fix | One regression failed | `pf-cache-red.log` |
| UID-signature mutation check | Removing the fix made the UID-change regression fail; fix restored | `pf-owner-signature-red.log` |
| Pagination before fix | One regression failed: two reads instead of one | `review-pagination-red.log` |
| Malformed proof before fix | Three Unicode cases failed with `TypeError`; three ASCII invalid cases already passed | `review-input-red.log` |
| Pairing focused suite after fix | 35 passed | `review-input-green.log` |
| Complete helper suite | 121 tests in 8 suites passed, including read-only LAN observation | `review-batch2-SquirrelOpsHelperTests.log` |
| Complete app suite | 390 tests in 37 suites passed | `review-batch2-SquirrelOpsHomeTests.log` |
| Guest-runtime suite | 10 tests in 2 suites passed | `review-batch2-SquirrelOpsDeceptionGuestTests.log` |
| Complete sensor suite | 2,274 passed, one opt-in live-guest test skipped, 83.75 seconds | `review-batch2-sensor.log`, `review-batch2-sensor.xml` |
| macOS PF parser | Single- and multi-service generated rules accepted with `-n`; no rules loaded | Included in helper suite |
| Release-mode compilation | Full PF build passed in 45.75 seconds; final app rebuild passed in 19.02 seconds | `pf-final-release-build.log`, `review-batch2-release-build.log` |
| Ruff and whitespace | `ruff check .` and `git diff --check` passed | Terminal output |
| Accepted pull gesture | Source and test hashes still match the accepted fixture | `pull-calibration-source-sha256.txt` |

The helper suite includes fault injection for quarantine command exceptions,
nonzero exits, failed state cleanup, later-endpoint cleanup, retained pending
work, and eventual successful recovery. It also verifies distinct tags for
different services/hosts and rejection of missing/root/unknown UIDs. The
retained-live-rules test asserts the generated guard after a mocked failed
replacement; it is not a packet-filter emulator or a real packet-path test.

This batch did not repeat the disposable live SSH/SFTP/SMB guest test. The guest
runtime and protocol implementation are unchanged from its passing first-batch
run. That historical guest test does not validate the new PF path. No installed
package or Intel execution claim is made.

Builds used CLT and the installed macOS 26.5 SDK on macOS 27.0 (26A428), ARM64.
Existing CLT linker/app-capture and Python deprecation warnings remain.

### Reproduction

The full native and Python commands are in the
[first-batch record](2026-09-26-code-review-fixes.md#reproduction-commands).
Use absolute native test-bundle paths for resource lookup. To isolate the PF
tests, add `--filter PFListenerGuardTests` to the helper test command. The helper
tests use `pfctl -n -f -` only for real PF parsing; other PF commands are injected
fakes. `SQUIRRELOPS_TEST_LIVE_LAN=1` enables observation, not network mutation.

## Live acceptance gate, not executed

October 2 update: the [Mini eight-phase result](2026-10-02-mini-a5-eight-phase-result.md)
now records listener replacement with real closing PF states, packet-correlated
denial observations, failure injection, recovery and cleanup. The heading above
is retained for existing links and the original September 26 record. This is
partial coverage of the matrix below, not full A5 sign-off. The subsequent
[TCP-edge result](2026-10-02-mini-a5-edge-result.md) verifies simultaneous
exact/wildcard rejection and records established cross-UID bind refusal and
half-open state closure before replacement. Those kernel constraints need a
qualified review disposition, not a claimed retained-state replacement pass.
Filter-attribution qualifications remain open. The
[MacBook upgrade result](2026-10-02-macbook-upgrade-result.md) now covers the
actual 2.0.3-to-2.1.0 package upgrade, saved-record preservation and replacement
of 15 unconditional `rdr pass` rules. The
[completed saved-evidence review](2026-10-02-saved-release-evidence-result.md)
confirms both archived state listings were empty and all original aliases are
present in a later read-only check. It resolves the Mini counter-format and
child-event omissions, but not the kernel-limited cases or upgrade with existing
states. This remains partial coverage of case 6, not full A5 sign-off.

Use an isolated Mac or obtain approval for an exact maintenance scope on this
Mac. Before any live write, identify the interface, unused policy-valid test
VIP, anchor, listener ports, and test UIDs. Capture the existing rules, relevant
state, alias/proxy-ARP ownership, and installed artifact identity. Prepare the
inverse operation and verify it will leave production decoys unchanged.

Required cases:

1. From a second machine, connect through advertised SSH/SMB and other decoy
   ports with sensor-owned backends. Confirm normal payloads, source addresses,
   and alerts. Compare protocol responses with the previous accepted behavior.
2. Probe backend ports directly and probe a second ingress interface. Neither
   may expose the backend or wildcard host services.
3. Replace a disposable backend with a different-UID listener. Verify it receives
   no new forwarded connection, including while quarantine replacement fails.
   Cover missing listeners and ambiguous exact/wildcard bindings too.
4. Create connection state before replacement. Exercise established sessions,
   SYN retransmission, same-tuple reconnects, and backend-port reuse. Inject
   state-cleanup failure as well as quarantine failure. Do not infer safety
   from fresh connections alone; inspect actual packet delivery and PF state.
5. Verify successful recovery clears pending work, while a failed recovery
   cannot authorize a new alias or report quarantine success. Check multiple
   endpoints so one cleanup failure cannot hide another.
6. Upgrade from the previous unconditional-rule version with existing states.
   Verify package/network cleanup and the exact installed helper's new rules.
7. Restore the recorded test scope and confirm production service and network
   parity. If safe cleanup cannot be proved, retain scoped quarantine and ask
   for direction. Never flush unrelated anchors or disable global PF/networking.

**A5 stays release-blocking until those results are available.** Further
development can address the remaining control findings without operating the
live firewall. This pass does not resolve A9, A11, A13 through A22, section C,
or the remaining decoy-realism review items.
