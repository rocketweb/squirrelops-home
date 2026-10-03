# Mini A5 disposable PF acceptance

Approved October 2, 2026 for the Mini only. This is not an installer, normal
sensor startup, whole A5 sign-off or permission to publish a release.

## Exact boundary

- Mini `100.108.203.27`, ARM64 macOS 27.0.1 build 26A434. Ethernet `en0`
  192.168.1.115, Wi-Fi `en1` 192.168.1.254. Existing jobs must stay disabled
  and unloaded. The app and guest must remain closed.
- Temporary IPs 192.168.1.239 and .240 only, each conflict-checked using the
  production duplicate-address guard before publication. No Studio or .241.
- Public ports 22 and 445 redirect to fixed disposable backends 61322 and
  61445. Children use the checksum-pinned installed Python executable with
  `-I -S -B`, cleared supplementary groups and UID 309 or 501, never root.
  Before PF or alias writes, a loopback-only preflight checks a client-initiated
  TCP close and reuse of one ephemeral backend port by those two UIDs. It does
  not run the installed sensor or change system socket settings.
- One unique `com.apple/squirrelops-a5-<nonce>` anchor, reached through the
  existing Apple parent hooks. No global policy replacement, global state
  flush, PF disable, production anchor, installed helper RPC or alias ledger.
- PF must initially be disabled, with no references and no concrete rules in
  the recursively inspected policy. The runner acquires one reference. It
  marks both acquisition and release attempts durably before executing them.
  An uncertain result is never authorization to retry.
- Fixed-source laptop probes from 192.168.1.7, bounded private packet captures
  on en0/en1, snaplen 96, 3,000 packets maximum each. Captures and full PF
  inventory remain root-private. Payloads contain synthetic tokens only.
- Private byte copies and fingerprints of config, SQLite files, launch plists
  and alias ledger. No writes to those originals. No package installation,
  service restart, Little Snitch rule or other system preference change.

The standalone Swift entry point compiles unchanged helper sources. It uses
the production rule builder, listener ownership guard, state cache, duplicate
address check and quarantine function. Its narrow command adapter substitutes
only the test anchor and injects explicitly named load/first-IP cleanup failures.
It rejects any attempt by recovery code to globally enable PF using `-e`.

## Eight attended phases

1. Healthy exact UID-309 listeners: forwarded payload, held sessions, direct
   backend denial, and second-ingress SYN probes.
2. Inject quarantine-load plus first-IP state-kill failure. Snapshot PF state
   immediately, before more traffic. Observe established and fresh flows.
   Assert recovery reports failure and refuses alias authorization for both IPs.
3. Successful block-only recovery: observe packet behavior and cleared debt.
4. Healthy publication again, reusing the same backend ports and held sessions.
   The client then completes a FIN/EOF close of the new sessions before its
   acknowledgement. Source ports are retained for the next reconnect attempt.
5. Replace with UID-501 listeners and fail load plus first-IP state cleanup.
   Require a real closing PF state on .239 before declaring this phase ready.
   Probe new connections and a same-tuple reconnect attempt. This is closing
   state reuse, not an established TCP session reaching a replacement process.
6. Missing listeners, with a failed quarantine load.
7. UID-501 wildcard listeners, with a failed quarantine load. This tests
   wildcard rejection but is **not** simultaneous exact-plus-wildcard binding.
8. Successful recovery after failures, then scoped cleanup and parity checks.

The client records responses and errors rather than turning timeouts into
passes. Little Snitch can confound any denial result; leave new prompts
unanswered and report them. Second-ingress denial is unproven unless the
Mini's en1 capture confirms packet arrival. Same-tuple attempts may be rejected
by the client's TCP stack; those are inconclusive, not PF passes.

Still separate: deliberately retained half-open SYN state/retransmission,
established-state replacement, simultaneous ambiguous listeners, **actual previous-package upgrade with
existing states**, and exact signed/notarized installer acceptance. Normal
real SSH/SMB/SFTP acceptance is already recorded elsewhere and is not replaced
by these synthetic TCP listeners.

## Build and run

From the repository, run `bash docs/testing/fixtures/pf-acceptance/build.sh`.
This compiles a standalone binary and produces a fresh pinned staging bundle.
No root or PF write occurs during the build. Run offline safety tests with
`python -m unittest discover -s docs/testing/fixtures/pf-acceptance -p test_runner.py`.

Copy the complete generated bundle into a fresh Mini staging directory and
verify `SHA256SUMS`. The user starts `sudo /bin/bash <staging>/start-mini-a5.sh`
in an attended Mini Terminal. Keep it open. Return stops early; the first phase
allows eight minutes to notify the operator, subsequent phases allow 150
seconds each, and the entire session has a 20-minute deadline.

The runner publishes only fixed-scope progress to the printed `status.json`.
It also exports scoped state records and numeric packet metadata automatically;
raw captures, full inventories, reference tokens and product backups stay private.
The October 2 completed-run export recovered uppercase `ALL` and numeric
`FIN_WAIT_2` records omitted by the original summary parser. Future summaries
accept those observed formats. Old evidence files and run results are not rewritten.
The separate `inspect_completed.py --successful-run` plan selects the completed
eight-phase run for counter and listener-event review. Only `--run` reads its
pinned private evidence. See the
[remaining-test plan](../../2026-10-02-mini-a5-remaining-plan.md) for the verified
read-only wrapper, coverage limits and approval boundary for additional tests.
Start the staged `client.py --run` on the laptop over a persistent SSH session.
Send each exact phase as one JSON line, in order, and retain its output.
Only after the corresponding probes finish, write a small acknowledgement
as Mini user `matt` to `<inbox>/<phase>.json` containing exactly
`{"nonce":"<status nonce>","phase":"<current phase>","action":"probes_done"}`.
The inbox is not a root command interface. Old, extra or malformed fields stop
the experiment. Do not send acknowledgements before recording client results.

## Rollback

On any exception or timeout: stop only owned, unreaped children; apply the
production block-only recovery even if a child stop fails; remove only aliases whose successful creation
is recorded; verify installed-data and unrelated-policy parity; empty only the
test anchor; release only the exactly observed private token, once. Verify PF
returned to its disabled baseline. Packet capture children are stopped last.

If any safety observation is ambiguous, retain protection and evidence and
request review. There is no `pfctl -d`, root ruleset reload, global state flush,
automatic reference-release retry, installed service mutation or data downgrade.
