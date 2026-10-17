# Mini A5 failure-path test preparation

Date: October 2, 2026. Status: **historical preparation; superseded by partial live results**.

The revised run has now completed all eight phases and scoped cleanup. See the
[latest result](2026-10-02-mini-a5-eight-phase-result.md) and preceding
[partial results and fixture corrections](2026-10-02-mini-a5-partial-results.md).
The paths and 24-test count below describe the original bundle. Do not rerun it;
the corrected bundle must be separately pinned and verified before another run.

Matt approved Mini-only temporary IPs 192.168.1.239 and .240 after conflict
checks, disposable listeners, packet captures, deliberate listener/state-cleanup
failures and scoped cleanup. This does not authorize changing the installed
services/data, Little Snitch, Studio, .241, or releasing a package.

The [runner scope and rollback](fixtures/pf-acceptance/README.md) describe all
eight phases. A standalone binary compiles the unchanged production helper
sources with a test entry point. It calls the actual rule builder, listener
guard, state cache, duplicate-address guard and quarantine function. Only its
test anchor substitution and named fault injections differ. It does not open
the installed helper socket or edit its alias ledger.

## Fresh checks

- Mini: ARM64 macOS 27.0.1 build 26A434; sensor/helper disabled and unloaded;
  no product PID observed. Ethernet en0 remains .115, Wi-Fi en1 remains .254.
  Service UID/GID 309:309 and Matt UID/GID 501:20 remain unchanged.
- Installed child Python hash remains
  `d2555cd22a33506826f9eb069bb13fb0cc41303c7da41da5b761967d616f4147`.
- Laptop routes both targets through wlp0s20f3 as 192.168.1.7. The default
  interpreter has no Scapy, so the new client uses tested standard-library
  AF_PACKET frames instead. No dependency was installed.
- Root-only PF inventory, database/config fingerprints and address-conflict
  checks remain in the attended preflight immediately before mutation. Their
  current state is not inferred from historical cleanup receipts.

## Local verification

| Check | Result |
| --- | --- |
| Runner safety, injected full phase sequence and client checks | 24 passed |
| Apple Python 3.9 parent with Python 3.12 disposable loopback children | Passed within the same 24-test run, 0.577 seconds |
| Production PFListenerGuardTests | 7 passed, 0.078 seconds |
| Standalone ARM64 release build | Passed, 23.22 seconds, existing CLT linker-path warnings |
| Both generated rulesets through `pfctl -n` | Passed; no rules loaded |
| Ruff, Bash syntax and whitespace | Passed |
| Mini bundle hashes, Bash syntax and both plan-only invocations | Passed remotely |
| Laptop client hash and plan-only invocation | Passed remotely |

The child-stop-failure regression was observed failing first: quarantine was
not attempted. The runner now attempts quarantine independently and retains
protection when any child stop remains uncertain. The passing regression also
checks that neither aliases nor the PF reference are released in that case.
Production code was not changed.

Reproduction:

```sh
SQUIRRELOPS_DIAGNOSTIC_CHILD_PYTHON=/Users/matt/code/squirrelops-home/.worktrees/deception-depth-2.1-current/sensor/.venv/bin/python \
  /usr/bin/python3 -m unittest discover \
  -s docs/testing/fixtures/pf-acceptance -p test_runner.py -v
```

The earlier full release-source verification remains in the
[precommit report](2026-10-02-precommit-verification.md). This new harness does
not replace those suites or turn a local check into live PF acceptance.

## Staged artifacts

- Local generated bundle: `/private/tmp/squirrelops-a5-build.NWUKgiwu/stage`.
- Mini: `/Users/matt/squirrelops-mini-a5.WSuVNfcd`.
- Laptop client: `/root/squirrelops-a5-client.CCB2C2V6/client.py`.
- Bundle `SHA256SUMS` hash:
  `55316c1801d7688680aa3b3865ae1a0ee331ac4aceb2e9ec45d42ff7beb37c90`.
- Mini launcher hash:
  `620a739fc1f322764a2bf2af66fba88aa86688651986bf6fb567a7477abd9c3a`.
- Laptop client hash:
  `3340a6f979a732129be8486215623ffc86c6427a19f2139ad5f20cb963218789`.

The Mini launcher copies fixed inputs into a fresh root-private durable backup,
checks the pinned manifest and only then starts the attended preflight.

Run on the **Mini**, not the Studio:

```sh
sudo /bin/bash /Users/matt/squirrelops-mini-a5.WSuVNfcd/start-mini-a5.sh
```

Leave Terminal open. On `READY: healthy`, notify Codex promptly. Do not press
Return unless stopping early. Leave new Little Snitch prompts unanswered and
report them. The initial window is eight minutes, subsequent phases have 150
seconds each, and the entire session has a 20-minute deadline.

After readiness, the operator starts the staged laptop client with `--run`
over the existing persistent SSH connection. Send exactly the next phase as
one JSON line, retain the response, then acknowledge that phase using the
printed status nonce/inbox. Require healthy UID-309 payloads before accepting
later denial observations; a filter prompt or failed baseline makes those
observations inconclusive. No automatic release approval follows.

SSH control paths retained for coordination:

- `/private/tmp/squirrelops-post-reboot-staging.QwxlZTAG/mini.sock`
- `/private/tmp/squirrelops-post-reboot-staging.QwxlZTAG/laptop.sock`

## Still pending

The remaining live phases, retained half-open SYN-state/retransmission,
simultaneous exact-plus-wildcard listener ambiguity, actual upgrade from the
previous unconditional-rule package with existing states, and exact signed
installer acceptance remain open. The current run is intentionally not an
installer or product-data migration. See the canonical
[A5 matrix](2026-09-26-pf-safety-development.md#live-acceptance-gate-not-executed).

The existing app/docs and website commits remain local. This turn did not
commit the new harness, push, merge, dispatch a release, tag, publish or deploy.
