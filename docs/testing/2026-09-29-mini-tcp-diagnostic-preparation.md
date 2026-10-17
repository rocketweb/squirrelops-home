# Mini TCP diagnostic preparation

Date: 2026-09-29. Historical preparation and clock correction record. See the
[account-control results](2026-09-29-mini-tcp-account-control.md) for completed v2
runs and [changed-script preparation](2026-09-29-mini-tcp-changed-script.md) for
the currently staged v3 experiment. Do not treat the old commands below as the
current operator handoff.
Scope: [approved account-control diagnostic](2026-09-29-mini-tcp-diagnostic-proposal.md).

## What changed

Added standalone diagnostic fixtures only. No installed product code, installer,
service, PF configuration, filter configuration or network interface was changed.
No commit, push, merge or release was performed in this preparation step.

- `fixtures/mini_tcp_diagnostic.py`: attended root preflight and two bounded,
  privilege-dropped fixed-banner children. Read-only observations are selected
  from a fixed command dictionary. The public record contains scoped socket
  rows, queue rows, content-filter counts and child events. Full host inventory
  stays in the root-private evidence directory.
- `fixtures/start-mini-tcp-diagnostic.sh`: one sudo command, no arguments,
  attended Terminal required. Copies and verifies the script and approved scope
  before executing Apple's isolated Python. It does not extract a package.
- `fixtures/mini_tcp_client.py`: three interleaved reads per port, six total;
  fixed destination and source address; route validation; no client payload,
  authentication or scanning. An exclusive result file prevents accidental replay.
- Two corresponding `test_mini_tcp*.py` files: guards, failure handling and
  disposable local loopback checks.

The engineering-constraints skill was used to establish failing tests before
implementation and require executed verification before the staging claim.

## Verification executed

From `/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current`:

```sh
sensor/.venv/bin/python -B -m unittest discover -s docs/testing/fixtures -p 'test_mini_tcp*.py' -v
/usr/bin/python3 -B -m unittest discover -s docs/testing/fixtures -p 'test_mini_tcp*.py' -v
```

Both: **26 passed**, under Python 3.12.12 and Apple's Python 3.9.6 respectively.
The loopback checks needed execution outside the filesystem/network sandbox.
No root or remote test operation was used by these tests.

Coverage includes account and runtime drift, wrong MAC/address/route, enabled PF,
existing VIP/proxy ARP, loaded/uncertain launchd status, ownership/link/write-bit
checks, exact privilege-drop arguments, readiness identity and port bounds,
partial startup cleanup, direct-child-only termination, fixed banner, unexpected
peer rejection, independent deadline and lifeline shutdown, readiness timeout,
fragmented client response, and distinct connect-versus-banner failure outcomes.

Ruff on the four Python files: passed. `bash -n` on the wrapper: passed locally
and on the mini. Invoking the wrapper locally without root/TTY was rejected
before any staging or listener operation. Plan-only execution passed on both
remote machines. No remote root preflight has been claimed or attempted yet.

## Staged artifacts and verified hashes

Mini, private directory owned by matt, mode 0700:
`/Users/matt/squirrelops-tcp-test.TYYG7te5`

| File | SHA-256 |
| --- | --- |
| `mini_tcp_diagnostic.py` | `7004915175c83375e963f1499d06b8e9ea170c4de069dcf42472fba0d747bb26` |
| `approved-scope.md` | `fa7de1677d4ad8be0e28acf8d77f4c2d18b7386287971ab1455caa890581539e` |
| `start-mini-tcp-diagnostic.sh` | `b2dc7e67fda56625fb7919c2481f38662075a230d91ef051ea09c0c6f7193d40` |

Laptop, root-owned directory mode 0700:
`/root/squirrelops-tcp-client.50pnQQdV`

Client SHA-256: `9811f0c95b9d08f3080eaf7f5468b5ba94c6138107b91694fe6943674d8b1336`.
Read-only route check still selects `wlp0s20f3`, source `192.168.1.7`, for `.115`.

## Operator step and continuation

In an attended Terminal **on Matts-Mini-2, not the Mac Studio**:

```sh
sudo /bin/bash /Users/matt/squirrelops-tcp-test.TYYG7te5/start-mini-tcp-diagnostic.sh
```

Leave the app closed and the Terminal open. Tell Codex immediately when it says
`READY FOR SIX CLIENT PROBES`. The listeners self-expire within 180 seconds;
post-test read-only verification can take a few additional seconds. Return or
Ctrl-C stops early. Do not accept a filter-rule prompt during this baseline.
Report the prompt or any `STOPPED` message instead. Do not rerun after a failure
without reviewing retained evidence.

Next, Codex must read the newly printed root-owned sanitized `status.json`,
verify a live ready/observing phase, peer/address, UID 309/501 port mapping and
remaining time, and then invoke the staged laptop client once with those two
ports. Read the final mini status, collect scoped results and independently
verify the probes disappeared. Do not use the old VIP acceptance commands.

These results will diagnose ordinary real-address inbound TCP only. They do
not satisfy virtual-IP/PF, launchd, guest, installed-package or A5 acceptance.

## First-run failure and clock correction

Matt ran the original wrapper. The root preflight completed, then the first
child exited with status 1 before readiness. There was no second child and no
laptop client run. Preserved evidence:

- Private original directory: `/private/var/root/squirrelops-tcp-diag.XdfzenCb`.
- Sanitized status: `/private/var/tmp/squirrelops-tcp-results.115m8xzq/status.json`.
- [Copied status](evidence/2026-09-29-mini/tcp-diagnostic-initial-status.json).
- [Read-only runtime clock comparison](evidence/2026-09-29-mini/tcp-diagnostic-clocks.json).

Live read-only SSH confirmed the product sensor/helper jobs were still absent
and no matching product/Python processes remained. The initial status reported
`baseline_verified: false` because the code incorrectly coupled that field to
*all* diagnostic errors. It recorded no additional teardown/verification error.
The corrected field independently reports whether post-cleanup baseline checks
completed, even if startup failed.

The clock comparison proved the mixed-runtime defect: Apple's Python 3.9
`time.monotonic()` read about 0.05 seconds, while the installed Python 3.12 read
about 182,964 seconds. Passing the parent's absolute monotonic deadline to the
child therefore caused the child's pre-bind `invalid deadline` exit. Both
runtimes' explicit `clock_gettime(CLOCK_MONOTONIC)` readings agreed within about
15 milliseconds. No listener or filter change was used to obtain this evidence.

Reproduced locally with an Apple 3.9 parent and the extracted package's exact
sensor Python executable (SHA-256 matches the mini's `d2555cd2...f4147`). The four
real-child cases failed with `invalid deadline` before the fix. The added status
assertion also failed before separating baseline verification from startup error.
The original tests used same-version parent/child pairs and missed this case.

Correction: shared deadlines now use the explicit OS clock in both parent and
child. The local-only readiness timeout may still use `time.monotonic()` because
that value never crosses a process boundary. Tests verify actual expiry timing,
parent lifeline closure, banner behavior, and an explicit OS-clock invariant.

After correction: **27 tests passed with the mixed 3.9/3.12 pair**, and **27 passed
with the 3.12/3.12 pair**. Ruff passed. These are local checks, not a successful
mini network diagnostic.

Mixed-runtime verification command:

```sh
env SQUIRRELOPS_DIAGNOSTIC_CHILD_PYTHON=/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/build/test-artifacts/shutdown-fix-extracted-20260929/sensor.pkg/Payload/Library/SquirrelOps/sensor/python/bin/python3.12 /usr/bin/python3 -B -m unittest discover -s docs/testing/fixtures -p 'test_mini_tcp*.py' -v
```

Corrected script SHA-256:
`b91bc0623c0cdb81b042fbb8f636d9a578c0ad2e9e2dc4d6635ae473149fd91d`.
The wrapper's pin was updated. Approved scope and laptop client are unchanged;
all original mini staging and run evidence are retained. New mini staging:
`/Users/matt/squirrelops-tcp-test-v2.CTfRMK5n`.

Remote SHA-256 verification matched the corrected script, unchanged scope and
wrapper (`3e51c62d6167ca5945ccc52f59bf7461689a44d8b62f4606a9f0662d46712d2c`).
Remote `bash -n` and plan-only startup passed. The new directory is matt-owned
mode 0700. The laptop result file is still absent and its plan-only command
passed: none of its six attempts has been consumed.

Corrected attended command, **on the mini**:

```sh
sudo /bin/bash /Users/matt/squirrelops-tcp-test-v2.CTfRMK5n/start-mini-tcp-diagnostic.sh
```

Use the same 180-second, six-client-probe scope and stop conditions. Do not use
the old command. No product changes, installer, PF changes or release action
are part of this correction.
