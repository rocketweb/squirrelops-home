# Mac mini: bounded Home 2.1 setup and protocol-test proposal

Date: 2026-09-28. Status: Matt approved this bounded scope with "yes proceed".
Setup files were staged and hash-verified on the mini before attended execution.

**Latest checkpoint, 2026-09-29:** the attended exact-state recovery installed
the pinned package successfully, but live SSH/SMB and HTTP protocol acceptance
failed. The initial automatic cleanup halted prematurely; the exact-session
attended continuation completed at 14:38:18 UTC, preserving the installation
and data while withdrawing the test services/addresses and its PF reference.
See the [live acceptance report](2026-09-29-mini-live-acceptance.md) for
evidence and verification limits, and the
[recovery record](2026-09-29-mini-install-recovery.md) for the prior harness
permission defect. Do not rerun fresh-install or failed-install recovery mode
against the now-installed machine.

This proposal covers the current package's installation and ordinary protocol
acceptance. It does **not** authorize older-package installation or disruptive
A5 fault injection. Those require a reviewed containment harness after this
installed baseline is established. Nothing here closes the A5 release gate.

## Exact target and artifact

- Server: `matt@100.108.203.27`, Matt's Mac mini, macOS 27.0 ARM64.
- Client: existing authorized `root@192.168.1.7`, interface `wlp0s20f3`.
- Mini ingress: `en0`, currently `192.168.1.115/24`.
- Secondary ingress observation: `en1`, currently `192.168.1.254/24`.
- Selected virtual IPs: `192.168.1.240` and `192.168.1.241`, confirmed available
  by Matt. Repeat conflict checks before allocation.
- Installer: `build/test-artifacts/SquirrelOpsHome-2.1.0-ai-setup-20260928-local-test.pkg`.
- SHA-256: `3e8c0fc78befad3365fdbff5583d9f85c6b6fe01816b5863edbebeceaa4b8f5f`.
- Unsigned local-test installer with ad-hoc executable signing. This is not a
  public release, and no Gatekeeper, SIP, TCC, or sudo-policy bypass is allowed.

## Expected changes and blast radius

| Target | Before | Proposed effect |
| --- | --- | --- |
| `/Applications/SquirrelOps Home.app` | Absent in preflight | Install one app bundle |
| `/Library/SquirrelOps/sensor` | Absent in preflight | Install sensor, bundled Python, bounded configuration and new test data |
| Privileged helper and launchd | Product jobs absent | Install helper and two product LaunchDaemons |
| Directory service | Product identity absent | Installer creates one `_squirrelops` user/group pair; discover and record actual UID/GID |
| Virtual IPs | Neither assigned by this task | At most two loopback /32 aliases with proxy ARP on `en0` |
| PF | Disabled in Matt's snapshot | Enable under a test-owned reference after loaded-rule inspection; product owns `com.apple/squirrelops` only |
| Management API | Absent in preflight | TLS API on port 8443; protected routes require pairing |
| Classic decoys | None from SquirrelOps | Up to three additional listeners on the concrete mini LAN address, using OS-assigned ports |
| Discovery | No SquirrelOps scanning | Normal ARP, TCP and Scout discovery on `192.168.1.0/24` |
| Deep decoy | Absent | One disposable guest with real SSH/SMB and synthetic persona data |

The physical host already listens on 22, 445, 5900 and other ports. Do not stop
or replace those listeners. Do not alter Ollama, the loopback inference server,
Tailscale, routing, Wi-Fi, Screen Sharing, unrelated PF anchors or VM networks.
Unrelated devices may receive ordinary sensor discovery probes, but login and
file-operation tests target only the mini's verified decoy endpoints.

Normal product-generated backend ports must be discovered from the installed
state; the earlier proposed 49222/49445 ports are for a later isolated harness,
not a claim that the installed orchestrator uses those ports.

## Preconditions, backup and authorization execution

After approval, run one reviewed, bounded setup script in **Terminal on the
mini** with `sudo`. The remote AppleScript administrator prompt did not work.
Do not collect a password in chat, grant persistent root access, or install a
general-purpose privileged command runner. Script bytes and package digest must
be available for review before that Terminal command is issued.

Before the script may install or enable PF:

1. Recheck mini identity, product absence, free disk, routes, IP conflicts,
   root-owned listener inventory, service UID availability and package digest.
   Abort on unaccounted-for drift or conflicting product artifacts.
2. Save a root-only, uniquely named baseline directory outside the package's
   snapshot-pruning path, under `/Library/SquirrelOps/acceptance-backups/`.
   Record the original absence/presence and metadata of each affected path,
   receipts, launchd state, aliases/proxy ARP, PF status, recursive filter/NAT
   rules and PF reference owners. Keep raw evidence and credentials private.
3. Inspect recursive PF rules, not just top-level Apple hooks. If enabling PF
   could activate an unrelated policy whose effects are not understood, stop
   before installing or enabling it and revise the proposal with Matt.
4. Preinstall the bounded configuration below as a regular, root-owned file
   through a validated path. Preserve any unexpected existing configuration and
   stop instead of overwriting it. Verify package scripts preserve it.
5. Acquire and record a test-owned PF enable reference using `pfctl -E`, then
   verify PF is enabled. The current helper's enable function returns without
   `-e` when status is already enabled. Never use global `-d`, `-F all`, or a
   main-ruleset reload for preparation or cleanup.
6. Create the package's one-use root-owned local-test opt-in and install the
   digest-pinned package. Record installer exit status and exact installed app,
   helper, runtime and source identities. On failure, stop and retain evidence.

The setup script, root-only backup and runtime inverse are **not yet created on
the mini**. This is an approval proposal, not an assertion that execution or
rollback has already passed.

## Bounded startup configuration

Use the locally prepared `fixtures/mini-a5-config.yaml`. The current packaged
configuration model accepts it. Its real allocator returns only `.240` and
`.241`, then reports exhaustion. Standard profile capacity canonicalization
does not enlarge that candidate range; it does retain normal LAN scans and up
to three classic host listeners. No AI endpoint or provider credential is set,
so setup does not request inference from the mini's existing AI services.

## Ordinary acceptance to perform

1. Confirm service health, actual published VIPs, the helper's UID-guarded
   redirects, and unchanged existing service endpoints. Abort if any product
   alias falls outside the two selected addresses.
2. From the laptop, exercise the verified guest SSH and SMB endpoints with
   synthetic credentials only. Confirm protocol banners, failed and successful
   authentication, SFTP/SMB listings and reads. Write/delete only uniquely named
   synthetic acceptance files in the disposable guest.
3. Verify source attribution to `192.168.1.7`, stored connection telemetry and
   expected alert grouping. An open TCP port by itself is not success.
4. Probe the discovered private backend ports directly. Observe actual ingress
   and packet delivery for secondary-interface checks; do not count targeting
   the Wi-Fi address as proof of Wi-Fi ingress.
5. Record results, exact commands, observed ports and limits in Markdown. No
   brute force, exploit payload, credential spraying or broad penetration scan.

These results establish a current installed baseline only. Different-UID and
missing/ambiguous listeners, state/retransmission/reuse, quarantine plus cleanup
faults, multi-endpoint recovery and actual old-rule package upgrade remain the
separate [A5 requirements](2026-09-26-pf-safety-development.md#live-acceptance-gate-not-executed).
Candidate 2's hash was rechecked, but that older package is **not** selected for
installation in this approval scope.

## Stop, inverse and retained data

The approved setup must include a bounded teardown path before it runs:

- Stop the test sensor through launchd and verify its processes and guest exit.
  Preserve new configuration, database, logs and enrollment material root-only.
- Withdraw only the two ledger-owned test proxy-ARP entries and aliases while
  protection remains in place. Verify actual absence before clearing the
  product anchor. If withdrawal is uncertain, keep scoped quarantine and stop.
- Stop the helper after safe network withdrawal. Use the current packaged
  `uninstall.sh --preserve-data` only after verifying its recorded targets and
  backing up the installed payload. It removes the product runtime/app while
  preserving test data and its service identity. Do not remove that retained
  account or data without separate approval.
- Release only the recorded test PF reference with `pfctl -X TOKEN`, after
  verifying its ownership and that no test alias remains. If another component
  enabled PF, preserve that component's reference. Never force global disable
  merely to match the initial disabled snapshot.
- Recheck original SSH, SMB, Screen Sharing, Ollama, loopback inference,
  Tailscale and physical routes. Distinguish restored operational behavior from
  the intentionally retained private test data/account and diagnostic backup.

If setup succeeds, stop test networking at the end of this stage and retain the
installed package/data for the subsequent reviewed A5 harness. If installation
or acceptance fails, use the backed-up current-package teardown path as far as
it is demonstrably safe; do not improvise broader cleanup.

No commit, push, tag, GitHub publication or website change is part of this scope.

## Initial execution checkpoint: staged, awaiting attended administrator command

The approved setup is staged in the mini's private mode-0700 directory:
`/Users/matt/squirrelops-mini-test.yktIwbVu` (owner `matt:staff`). It contains the
installer as `candidate.pkg`, bounded configuration, setup source and this
scope record. No product path, account, launchd job or PF state has changed.

Fresh SSH inspection still showed macOS 27.0 build `26A428`, the expected
Ethernet/Wi-Fi/Tailscale addresses, absent product paths, and the original
listeners. The laptop still routes through `wlp0s20f3`. Three new ARP probes
per selected address received no replies. Those probes supplement Matt's
address confirmation; they are not proof against future DHCP allocation.

Run in Terminal on the mini:

```sh
sudo /bin/bash /Users/matt/squirrelops-mini-test.yktIwbVu/start-mini-acceptance.sh
```

The script copies inputs into a new root-private directory, verifies pinned
digests, and uses the package's isolated Python rather than a host interpreter.
It records recursive PF policy and aborts before enable/install if it finds
unexpected loaded rules. The baseline is outside package snapshot retention.
After install, it verifies the exact app/helper/guest hashes, configuration,
stable health and original listener endpoints. It exports only non-secret
telemetry to a root-owned result directory. The install-specific **synthetic**
guest login is a separate mode-0600 file readable only by Matt and root, not in
the public JSON, command arguments or logs.

On `READY FOR TESTS`, leave Terminal open and tell Codex. Two packet captures
are limited to laptop traffic involving the approved VIPs. The script waits
for Return or 20 minutes, then stops the test services, withdraws owned aliases,
clears only the product anchor and releases only its own PF enable reference.
It retains the installation/data and a private SQLite backup. Unexpected
ownership, surviving processes, incomplete alias removal or uncertain Installer
completion stops cleanup with protection retained. It is not a generic remote
root-command service. Do not reopen the app after cleanup until the next test
stage is reviewed.

Local preparation verification, not live acceptance:

- `python -B docs/testing/fixtures/test_mini_acceptance.py`: 10 guard tests
  passed. The actual `status: ok` health fixture was observed failing before
  correcting the setup script's original `healthy` expectation.
- Ruff on both new Python fixtures: passed.
- `bash -n` on `start-mini-acceptance.sh`: passed locally and on the mini.
- Plan-only mode ran without privileged/network operations.
- Remote SHA-256 verification matched every staged executable input below.

| Input | SHA-256 |
| --- | --- |
| `start-mini-acceptance.sh` | `0ff2773f4b356de9635909f5361b89420a8225d18cdd7d0501edc55b00f0cac5` |
| `mini_acceptance.py` | `2852d7f814b66e1c75224d105e41ca11dcf860e5bbac070b10f68172c201f3cd` |
| `mini-a5-config.yaml` | `6e210567e3baae3950d91153b44090876ae6978b2a67677b1690aaf5c8f02330` |
| `candidate.pkg` | `3e8c0fc78befad3365fdbff5583d9f85c6b6fe01816b5863edbebeceaa4b8f5f` |

Remaining: the attended command, root preflight, real installation, protocol
traffic, attribution, cleanup and live parity. None are marked passed by the
guard tests or file transfer. The laptop has neither `sshpass` nor the Paramiko
module; use its existing OpenSSH/SFTP and SMB clients with a bounded PTY-based
driver rather than assuming either dependency is installed.

## PF inventory failure and corrected retry

The first attended attempt stopped during preflight, before PF enable or
installation. It retained the root-private baseline
`/Library/SquirrelOps/acceptance-backups/mini-20260928.o9xofp7p` and sanitized
status `/private/var/tmp/squirrelops-mini-results.0u2mtgr2/status.json`.
The status is `needs_review`, not an installation failure. A subsequent SSH
check still found neither product launchd service.

Matt supplied this output from the read-only `sudo /sbin/pfctl -a '*' -sr`:

```text
No ALTQ support in kernel
ALTQ related functions disabled
scrub-anchor "com.apple/*" all fragment reassemble
anchor "*" all {
pfctl: DIOCGETRULES: Invalid argument
}
```

This is an incomplete recursive read. It neither establishes conflicting
policy nor proves the Apple child rulesets empty. The harness originally
classified the unexpected `anchor "*"` display as policy needing review.
It also checked exit status but not diagnostic stderr, which could accept a
different incomplete read that produced empty stdout. Neither error is now
treated as permission to enable PF.

The corrected harness uses the installed macOS `pfctl(8)` manual's explicit
`-s Anchors` enumeration. It walks concrete anchor paths and reads `-sr` and
`-sn` separately at the root and each child, never passing `*` as an anchor
argument. It bounds the tree, rejects unrecognized namespaces and active
rules, checks stderr as well as exit status, rechecks child membership, and
compares a second inventory immediately before enabling PF. The two observed
ALTQ diagnostic lines are allowed; other diagnostics stop setup. This is a
bounded observation, not an atomic lock against other privileged PF writers.
Cleanup uses the same named-anchor inventory before releasing its own token.

The retry also recognizes retained preflight-only backups without deleting or
overwriting them. The one legacy attempt must match its exact directory name,
original setup-script digest, expected file set, and three read-only command
records. New attempts write a root-owned phase marker; an installation-phase
marker, unknown content, unsafe ownership or symlinks prevents reuse. Product
paths, accounts, receipts, services and test networking are still required to
be absent. A new attempt creates a new private baseline.

Verification of this correction:

- Observed three regression failures against the original behavior: the exact
  wildcard-query output, a zero-exit PF diagnostic with empty stdout, and
  retained preflight evidence incorrectly blocking a retry.
- `sensor/.venv/bin/python -B docs/testing/fixtures/test_mini_acceptance.py`:
  **23 tests passed** after the fix. Includes concrete child enumeration,
  filter/NAT conflict rejection, failed child reads, changing inventory,
  pre-install drift, original-backup validation and evidence preservation.
- Ruff passed on both Python fixtures; no-argument plan mode passed.
- Product source and candidate installer are unchanged. No commit, push,
  installation or live PF acceptance is claimed by these local tests.

The initial hash table above is historical. Updated bootstrap/source digests
and remote staging verification are recorded below before requesting a retry.

| Corrected input | SHA-256 |
| --- | --- |
| `start-mini-acceptance.sh` | `70a921a4b8c4a6a45f98c2a8c8c614c0070f293cc0a47718ce038ff9481d7417` |
| `mini_acceptance.py` | `365ec06fb20f018ac1acd2ca3b73544a5813fb633a06c652a580a56b254090b0` |

The test suite also passed all 23 tests using the exact extracted candidate's
isolated Python interpreter. Shell syntax validation passed locally. Before
staging the correction, the mini's original script and bootstrap were copied
to `mini_acceptance.initial.py` and `start-mini-acceptance.initial.sh` in the
same private staging directory, and both copies matched their original hashes.
Three fresh laptop ARP probes for each selected VIP again received no replies.
That is a current conflict check, not a guarantee against later allocation.

Staging completed: the remote bootstrap and Python SHA-256 values match the
corrected table; the configuration and package still match the original table.
`bash -n` also passed on the mini. No setup command was executed remotely and
no privileged state was changed by staging. The next action is the same
attended `sudo /bin/bash .../start-mini-acceptance.sh` command shown above.
Actual named-anchor reads and safe installation remain unverified until that
command runs. If it stops again, retain the new baseline and review the
reported failure; do not bypass the check or reset PF.
