# Diagnostic installer and restart pass; protocol window ended unused

The operator ran the pinned diagnostic installer on the Mini on September 30,
2026. First startup and the normal sensor restart passed the attended runner's
checks. The observation window ended before the prepared laptop client ran.
Final cleanup reported an unverified PF-reference release at
`2026-10-01T01:54:48Z` (September 30, 21:54:48 EDT).

Update: the cause was reproduced as an invalid Python superclass call in the
test harness, before any PF command. The separate attended cleanup completed
October 1 at 04:58:44 EDT, preserving all seven decoys and returning PF to its
original disabled state. See the [cleanup result](2026-09-30-mini-relay-cleanup-fix.md).
The observation results below remain unchanged: no new protocol probes ran.

## Exact run and retained evidence

- Package SHA-256: `3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea`.
- Approved target: Mini `100.108.203.27`, decoy `.240` only.
- Private execution: `/private/var/root/squirrelops-mini-relay.r2RulhrI`.
- Private backup: `/Library/SquirrelOps/acceptance-backups/mini-relay-20260930.m06dh5r3`.
- Sanitized results: `/private/var/tmp/squirrelops-mini-relay-results.b0fp2kjt`.
- Prepared, unused client: `/root/squirrelops-mini-upgrade-client.GWA3Ee6a` on `.7`.

The selected public files are retained under
[evidence/2026-09-30-mini-relay-idle](evidence/2026-09-30-mini-relay-idle).
No synthetic login, private command history or PF-reference value was copied.

| Check | Result |
| --- | --- |
| Fresh `.240` conflict check | Passed before installation |
| Diagnostic package installation | Passed the runner's pinned-payload checks |
| First startup | Passed; SSH/SMB listener activation checkpoints recorded |
| Normal sensor stop/start | Passed the runner's runtime, address, policy and saved-intent checks |
| Saved seven decoys and counters | Pre-probe and final observation snapshots are identical |
| Laptop protocol probes | Not run; client directory still contains only the two staged scripts |
| New SSH/SMB acceptance evidence | None; four activation checkpoints, no client accept or relay records |
| Product shutdown | Fresh SSH inspection: sensor/helper jobs absent and explicitly disabled; no product runtime or `.240`/`.241` alias |
| PF-reference release | Unverified; root-private command evidence needs review before any retry |

The existing AI connection counts and alert are unchanged historical evidence,
not successful probes of this diagnostic build. The final `after.json` snapshot
was taken before teardown; its aliases and rules are not current stopped state.
The remaining UID-309 `distnoted` process is not the guest or sensor runtime.

## Cleanup boundary

The sanitized reason is:

```text
Cleanup incomplete: PF reference release not verified; no retry. Review private evidence
```

The wrapper deliberately hides potentially sensitive reference values from
exceptions. This message alone does not establish whether release was attempted,
whether it succeeded, or whether a preceding check failed. The underlying
private command records and current PF state are required. Do not rerun the
installer, release a reference blindly, reset PF, or start the Studio sensor.

At follow-up inspection the Studio sensor's disabled override was still present
and its `.240` loopback alias was absent. No live networking, service, package,
database or third-party filter changes were made during this review.

## Read-only next check

`inspect_mini_relay_cleanup.py` was prepared and staged as
`/Users/matt/squirrelops-mini-relay.C5Jt9KuC/inspect-relay-cleanup.py` on the Mini.
Local and remote SHA-256 match:
`e1186cc9561ceb47d71201d3495858cc982de6e37393c9c2e12406b1d5efaf5d`.
The staged file is single-linked, mode 0600, owned by `matt`.

The inspector reads only this run's retained reference/command evidence and
executes two fixed read-only commands: `pfctl -s info` and
`pfctl -s References`. It prints derived metadata with all numeric and hexadecimal
reference values redacted. It never executes commands read from evidence, writes
files, installs, starts services, changes rules or releases a reference. Missing
completed command records are explicitly not permission to retry a timed-out
operation.

Six local selection/redaction checks passed; `git diff --check` passed. The
installed Python hash was rechecked against the pinned runtime. Privileged
execution has not occurred: `sudo -n` still requires the operator's password.

```sh
sudo /Library/SquirrelOps/sensor/python/bin/python3.12 -I -B /Users/matt/squirrelops-mini-relay.C5Jt9KuC/inspect-relay-cleanup.py
```

The engineering-constraints skill kept diagnosis separate from speculative
cleanup changes. This is partial acceptance, not release readiness. No commit,
push, release publication or new protocol attempt occurred during this review.
