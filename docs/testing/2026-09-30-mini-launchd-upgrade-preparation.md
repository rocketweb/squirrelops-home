# Launchd-budget candidate: attended mini test preparation

Status: attended execution stopped during preflight on a real ARP conflict.
Previous orphan cleanup completed; new package installation, restart, and LAN
protocol acceptance are still pending. Do not rerun without resolving the
overlapping test pool. No product source edits, rebuild, commit, push, or
publication were performed during preparation. The candidate is the preceding
local build, rehashed before transfer.

## Verified stopped baseline

The root-produced cleanup receipt reports completion at `2026-09-30T09:15:28Z`,
with stopped guest, aliases absent, native endpoints present, only the test's PF
reference released, and PF disabled. Independent read-only SSH checks confirmed
both product launchd jobs absent, historical helper/guest/VM PIDs absent, and
only `distnoted` under service UID 309. The mini still has sensor receipt
`1790731448`. Native en0 remains `192.168.1.115`.

The new runner pins this cleanup receipt and rechecks current root-only state
in the attended preflight. It does not use a historical receipt as proof that
the current system is still stopped.

## Continuation and verification

`mini_launchd_acceptance.py` reuses the verified upgrade and ownership-restart
implementations but bypasses the five-row recovery. It requires the restored
Studio rows already active, preserves every decoy's identity and intended
status, checks installed `ExitTimeOut=60`, and uses a 70-second sensor removal
poll. It retains the prior verified backup, strict PF/native-listener checks,
single-use attempt, guarded readiness, bounded probe window and safe cleanup.
PF release exceptions cannot publish the private reference token.

The engineering-constraints skill guided the timeout check: substituting the
old 45-second removal poll reproduced a failure; the new bounded poll passes.

| Check | Result |
| --- | --- |
| Complete local mini fixture suite, `unittest discover -s docs/testing/fixtures -p 'test_mini*.py' -q` | 160 passed with loopback permission; host operations mocked |
| New runner tests using extracted candidate Python with `-I -B` | 14 passed |
| Ruff on the three new Python files | Passed |
| Bootstrap shell syntax | Passed locally and on mini |
| Mini runner and laptop client plan-only modes | Passed; no service startup or probe traffic |
| Candidate and every staged script/scope digest | Matched local inputs |

The laptop remains `192.168.1.7` through `wlp0s20f3`, verified with
`ip -j route get 192.168.1.240`. SSH, SFTP, smbclient, Python and pexpect are
available. No new tools were installed.

## Staging

- Mini: `/Users/matt/squirrelops-mini-launchd.8DCJWXsN`.
- Laptop: `/root/squirrelops-mini-upgrade-client.7gztO3lV`.
- Directories are private; staged inputs are mode 0600.
- Candidate SHA-256: `3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c`.
- Runner SHA-256: `7b2517b3c59fff71741be115267b1687e50c26c5e48c40b903bb3bfdebffa6ba`.
- Bootstrap SHA-256: `e4ae2b874517b156b14af1c6302c2afd47a5a6e2e8ea9e3793152cb4416a3295`.
- Scope SHA-256: `f9640ae37e291b11106a9561eb5427efd4d0028544fcd571218997cdeeb0f601`.
- Laptop wrapper SHA-256: `aa519cabcee8942421f596a69a9e6aa4f44402c0df1a145aa14d9e933e29af5b`.
- Unchanged laptop client SHA-256: `15b3bb270b77d3801870d2a81b64dee266a8f823ce234f6b2be2ff360b02b7f6`.

The [exact scope](2026-09-30-mini-launchd-upgrade-scope.md) covers the affected
installation, backup and inverse, consent, restart and client gates, and limits.

## Next operator step

On the mini, with SquirrelOps closed:

```sh
sudo /bin/bash /Users/matt/squirrelops-mini-launchd.8DCJWXsN/start-mini-launchd-acceptance.sh
```

Review the printed scope and type `UPGRADE AND TEST RESTART` if it matches.
At `READY FOR TESTS`, leave Terminal open, do not press Return, and notify Codex.
Leave unexpected connection prompts unanswered. Return stops early, and the
window automatically ends after 20 minutes.

After readiness, verify fresh root-owned results for this package and copy only
the operator-owned synthetic guest login privately to the new laptop directory,
along with endpoint and readiness JSON. Never print credentials. Invoke
`mini_launchd_client.py --run` with that exact laptop directory once; do not
invoke the old client's main directly, which is pinned to an earlier package.
Retain sanitized results and verify final cleanup before further installation
or app launch. This is not the A5 live PF fault/isolation matrix or release
approval.

## Attempt stopped: Studio owns the second test address

The operator ran the staged bootstrap. Root staging was
`/private/var/root/squirrelops-mini-launchd.Fpl9w3AH`; the evidence directory was
`/Library/SquirrelOps/acceptance-backups/mini-upgrade-20260929.69kvi6gi`.
The directory was created, but execution stopped before `backup_existing`,
attended confirmation, the single-use install claim, PF enable, or Installer.

Root-owned result `/private/var/tmp/squirrelops-mini-upgrade-results.be83_ffe/status.json`
reports at `2026-09-30T09:43:53Z`:

```text
RuntimeError: A proposed virtual IP answered ARP; no startup authorized
```

Receipt SHA-256: `e7b0f9a1cf68116a80205b5e6c68259c98b2d2d78d7da99434da907e76888dbe`.
The mini's installed sensor receipt remains `1790731448`, both product launchd
jobs are absent, and its interface inventory has no `.240` or `.241` alias.

Read-only checks identified the overlap:

- Mini ARP entries map `.241` to `1c:1d:d3:e0:7d:03` on en0 and en1.
- Mac Studio en0 has that exact MAC, with native address `192.168.1.18`.
- Mac Studio lo0 owns `192.168.1.241/32` and its ARP table contains a permanent
  published proxy entry for `.241` using that MAC.
- Studio's background sensor is running, PID 61581 when inspected. Closing the
  dashboard does not unload the sensor. Its current launchd exit timeout is
  still five seconds, so a blind full-sensor stop is not a safe workaround.

The preflight did not record its raw ARP reply packets, so the exact reply from
that instant is unavailable. The current alias, published proxy, matching MAC,
and remote ARP entry establish the present address conflict without needing a
broad scan or changing either host. The Scapy cryptography deprecation warning
is not the preflight stop reason.

Proposed next scope, pending approval: keep Studio unchanged and narrow only
the mini's test pool in `/Library/SquirrelOps/sensor/config.yaml`:

```diff
 scouts:
   virtual_ip_range_start: 240
-  virtual_ip_range_end: 241
-  max_virtual_ips: 2
+  virtual_ip_range_end: 240
+  max_virtual_ips: 1
```

The known synthetic fixture `fixtures/mini-a5-config.yaml` matches the
preflight-pinned configuration digest. The schema permits this one-address
pool when the maximum is also one. Fresh root-side verification, an exact
private backup/inverse, updated runner and scope hashes, and a new conflict
check are required before applying it. Do not silently ignore `.241` while it
remains in the runtime's configured allocation pool. All five services for this
normal protocol/restart test already use `.240`; separate multi-address A5
acceptance remains a later gate. No configuration, PF, alias, service, or
installer changes were made during this diagnosis.

Matt subsequently approved the narrowed pool. The prepared continuation is
recorded in `2026-09-30-mini-single-ip-preparation.md`; use its new command,
not this superseded two-address runner. Live application remains pending.
