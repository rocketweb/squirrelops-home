# Home 2.1 code-review fixes: first batch

Date: 2026-09-26. Status: **seven findings fixed in source; not a final release**.

Subsequent development: [batch 2](2026-09-26-pf-safety-development.md) implements
the PF ownership guard and recovery changes, and fixes A10/A12. A5 still needs
live PF acceptance. This first-batch record and its source hashes are historical.

This follows `CODE_REVIEW-deception-depth-2.1.md` in the parent checkout. The
original review is preserved. This report closes A1, A2, A3, A4, A6, A7, and A8
within the boundaries below. A5 remains a release blocker. The remaining review
items are not implicitly resolved by passing tests.

No installer was built or installed, no installed service or credential was
changed, and no live packet-filter rule or virtual LAN address was changed.
Nothing was committed, pushed, tagged, notarized, or published. Candidate 2
predates these fixes and must not be described as containing them.

## Exact source

- Checkout: `/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current`.
- Branch: `feature/deception-depth-2.1.0-current`.
- Base: `6b6ef8b5fe3d694695a9bc74982cbe80d05baeb5`, plus existing release work and
  this uncommitted batch. The base commit alone does not identify the source.
- Host: macOS 27.0, build 26A428, ARM64. Compilation used Command Line Tools
  with the installed macOS 26.5 SDK. No toolchain/license settings changed.
- `build/test-artifacts/review-complete-source-sha256.txt` records 416 source,
  test, configuration, and build inputs. Manifest SHA-256:
  `251a5fee607b43c41510d08147c8956928623e6a246e7b9b6d7e5e76e2bbaa07`.
  All entries were checked after compilation. This is local evidence, not a
  signed attestation. Earlier source/package manifests remain historical.

## Changes and proof boundaries

| Finding | Change | Regression evidence |
| --- | --- | --- |
| A1: local MAC inventory failure aborts scanning | Continue scanning exact previously known IP/MAC pairs in degraded mode. Pause new identities, address changes, offline reconciliation, and automatic deployment until host identity filtering recovers. Emit a degraded scan-complete event. | Raising and empty helper results, cold start, rejected new/remapped/proxy identities, preserved online state, and recovery tested. |
| A2: setup-key completion race | Serialize challenge, verify, and completion under one pairing lifecycle lock. Consume the setup key and outstanding sessions before the first database await after CSR validation. | Same-challenge and different-challenge races each allow one completion. Cancellation after database commit cannot reuse the key. |
| A3: unreadable credentials can crash dashboard actions | Replace ten client force unwraps in four dashboard views with a throwing client accessor. Retain pairing/repair state. | Static guard covers the affected views; runtime test verifies normal request failure with a missing client and recovery with a restored client. |
| A4: window reopening duplicates connections | Introduce one app-scoped connection owner; reuse unchanged pairing, cancel/disconnect before replacement, check startup cancellation, and invalidate an owned WebSocket URLSession when discarded. | Reopen/replacement tests, suspended-startup cancellation test, and real URLSession invalidation callback. |
| A6: queued accepts bypass the relay ceiling | Acquire the existing allowance synchronously on the listener queue before enqueuing MainActor work. Still record rejected connections. | Three accepted socket descriptors against a two-slot test ceiling, without allowing MainActor to drain: third descriptor closes and all three telemetry callbacks occur. |
| A7: early exit leaks a relay slot | A connection lease owns both descriptor and allowance, releasing them once on close or deinitialization, including missing receiver/device paths. SocketRelay retains the lease. | Early receiver exit, allowance reuse, idempotent close, descriptor validity, and production-wiring checks. |
| A8: host kills guest before its retry budget expires | Increase the host ready-record deadline from 20 to 210 seconds: three 60-second retry-backoff windows plus 30 seconds of boot/scheduling allowance. | Budget regression plus a shortened process-boundary timeout proving the child terminates and no backend ports are published. |

A1 deliberately does not fall back to unfiltered discovery. A cold start with
no trusted inventory will report degraded completion but cannot safely discover
new devices until local-MAC inventory works. Existing ARP-conflict alerts are
not cleared on that degraded evidence.

A2 deliberately consumes a valid setup key even if persistence fails or its
acknowledgement is lost. A fresh key is required in that case. Invalid proofs
or CSRs do not consume the key. This is a fail-closed integrity choice, not an
idempotent enrollment redesign.

A3/A4 were not verified by corrupting the real Keychain or repeatedly reopening
the installed app. Tests exercise the factored owner, request boundary,
cancellation, and session lifetime. Full actor isolation of the connection
classes (A11) is not part of this fix.

A8 remains an outer deadline, not a guarantee that every retry completes:
Virtualization callbacks and persona writes can themselves stall. The timed
test accelerates the deadline; it does not simulate a 210-second real boot.

## Deception-integrity review for the relay and startup changes

The existing production maximum of 16 connections is unchanged. Its accounting
now includes pending MainActor callbacks instead of permitting an unbounded
queue of accepted descriptors. The over-limit behavior is still connection
close, with no new authentication, lockout, rate-limit response, banner, or
protocol parsing. Saturation can close connections sooner because the existing
bound is now enforced at admission. This is the specific observable difference
reviewed here, not a claim that overload timing is byte-for-byte identical.

SSH/SMB bytes remain opaque. Relay buffers, guest services, persona files,
credentials, service ports, VM containment, and payloads are unchanged. The
telemetry schema remains unchanged, including evidence for rejected accepts.
Startup timing changes happen before listeners are published.

Normal real SSH/SFTP/SMB behavior was rechecked against the newly compiled
runtime in a disposable loopback-only guest. A large-scale LAN saturation test
and post-install protocol acceptance were not performed.

## Verification

The focused regressions were observed failing before their corresponding
changes. Evidence is under `build/test-artifacts/`:

- `review-a1-a2-red.log`: five expected failures for MAC inventory handling and
  concurrent pairing completion.
- `review-pairing-cancel-red.log`: consumed-key protection fails on cancellation
  after commit without the early-consumption change.
- `review-app-red.log`, `review-app-cancel-red.log`, and
  `review-app-session-red.log`: duplicate connection, missing-client,
  cancellation, and session-lifetime regressions.
- `review-relay-red.log`: four assertion failures across queued admission and
  the leaking compound guard; early receiver cleanup already passes with the
  new lease. Production wiring is checked separately.
- `review-guest-budget-red.log`: the old 20-second host deadline fails the
  minimum 210-second budget assertion.

Final result records are listed here; run commands are below:

| Check | Result | Log |
| --- | --- | --- |
| Full sensor unit/integration/functional suite | 2,267 passed, one opt-in live-guest test skipped, 85.25 seconds; skipped case passed separately below | `review-verified-sensor.log`, `review-verified-sensor.xml` |
| Full app suite | 389 tests in 37 suites passed | `review-absolute-SquirrelOpsHomeTests.log` |
| Full helper suite | 114 tests in 7 suites passed, including opt-in read-only LAN observation | `review-absolute-SquirrelOpsHelperTests.log` |
| Guest containment and admission suites | 10 tests in 2 suites passed | `review-final-guest-runtime.log` |
| Live disposable guest | 1 passed, 23.49 seconds | `review-live-guest.log` |
| Guest process-boundary suite | 10 passed; included in the full sensor total | `review-guest-budget-green.log` |
| Release-mode compilation | Passed; initial full compilation 45.62 seconds, final guest rebuild 3.08 seconds | `review-release-build.log`, `review-final-release-build.log` |
| Ruff | `ruff check .` passed | Terminal output |
| Whitespace | `git diff --check` passed | Terminal output |
| Source identity | All 416 entries match | `review-source-verification.log` |
| Accepted pull gesture source | Both recorded source/test hashes still match | `pull-calibration-source-sha256.txt` |

The live test used an ad-hoc-signed debug runtime copied to
`/private/tmp/squirrelops-review-guest.tG0wmz/SquirrelOpsDeceptionGuest`, with only
the existing virtualization entitlement. It covered OpenSSH authentication and
persona commands, SFTP read/upload/download/removal, SMB2 negotiation and Samba
list/read/write/removal, host-canary isolation, guest loopback-only networking,
and SSH/SMB connection telemetry. The controller stopped the guest in its
cleanup path; a subsequent process check found no remaining runtime at that
path. No installed guest was restarted. Intel execution and release-signed,
root-owned installed acceptance remain separate gates.

Two final-run invocation mistakes are retained, not hidden: the sandboxed
sensor run could not bind local sockets (`review-complete-sensor.log`), and
native runs with relative test-bundle paths could not find font resources
(`review-complete-SquirrelOpsHomeTests.log` and
`review-verified-SquirrelOpsHomeTests.log`). Changing only the native working
directory did not fix lookup. The verified native command supplies an absolute
bundle path, which FontRegistration explicitly searches. The sensor rerun used
approved local socket access. No product changes were made to suppress these
test failures. Earlier test-compilation syntax errors were corrected before
the final native run.

Warnings remain for CLT linker search paths/arclite, the existing app capture
diagnostic, and Python framework deprecations. Dependencies were not updated.

### Reproduction commands

Run from the candidate checkout. The native runner requires an **absolute**
test-bundle path so its resource lookup works under this CLT test harness.

```bash
cd /Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/sensor
env -u SQUIRRELOPS_DECEPTION_RUNTIME -u SQUIRRELOPS_GUEST_BUNDLE \
  .venv/bin/python -m pytest -q --tb=short -ra
.venv/bin/ruff check .

cd ../app
DEVELOPER_DIR=/Library/Developer/CommandLineTools swift build \
  --sdk /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
  --scratch-path .build/ui-refresh --build-tests \
  -Xswiftc -plugin-path \
  -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing
for test_bundle in SquirrelOpsHomeTests SquirrelOpsHelperTests SquirrelOpsDeceptionGuestTests; do
  SQUIRRELOPS_TEST_LIVE_LAN=1 \
  DYLD_FRAMEWORK_PATH=/Library/Developer/CommandLineTools/Library/Developer/Frameworks \
  DYLD_LIBRARY_PATH=/Library/Developer/CommandLineTools/Library/Developer/usr/lib \
  /Library/Developer/CommandLineTools/usr/libexec/swift/pm/swiftpm-testing-helper \
    --test-bundle-path "$(pwd)/.build/ui-refresh/out/Products/Debug/$test_bundle.xctest/Contents/MacOS/$test_bundle" \
    --testing-library swift-testing || break
done
```

The read-only LAN opt-in observes the helper's network context; it does not
publish aliases or exercise live PF replacement. Local socket/VM tests require
permission to operate outside a socket-blocking sandbox.

## Release blocker and remaining review scope

**A5 remains open.** After a live redirect load, the post-load listener-owner
check can fail; if the block-only replacement also fails, the installed redirect
remains. `quarantinePortForwardingAfterListenerRace` throws before changing its
cache in this case. Existing success-path tests do not prove safety under both
failures. This pass inspected the source path but did not reproduce it against
the machine's live packet filter.

Blind retries would improve transient recovery but would not prove fail-closed
behavior. Flushing the anchor could expose host services. Removing an alias
alone is not a demonstrated substitute for quarantine, particularly with cached
peer ARP state and existing PF state. Disabling the host network or global PF
would be an unacceptable unapproved expansion.

The next work needs a separately reviewed ownership/publication design, such
as backend ownership reservation or an independently enforced quarantine
boundary. Require fault injection for both owner-change and quarantine-write
failure, then exact-package and second-machine LAN acceptance. Do not mark A5
resolved merely because the API returns an error or a retry passes.

A9, A11, and the classic-decoy realism items require their own design/deception
review. A10, A12 through A22, and section C are not closed by this batch. In
particular, cancellation checks added for A4 do not fix A10's empty-pagination
loop. No remaining finding should be silently accepted as release-safe.

One review correction: B8's claim that real Next.js never emits
`X-Powered-By: Next.js` is false. The
[official setting](https://nextjs.org/docs/app/api-reference/config/next-config-js/poweredByHeader)
and [server implementation](https://github.com/vercel/next.js/blob/canary/packages/next/src/server/send-payload.ts)
confirm that header. No decoy header was removed. Mixed framework headers on
different routes remain a separate persona-consistency question.

Previously accepted physical pull behavior was preserved, not re-calibrated.
Fresh foreground missing-credential/window-lifecycle acceptance, installed
upgrade acceptance, remaining review disposition, signing, and second-machine
LAN checks still precede any final installer/release claim.
