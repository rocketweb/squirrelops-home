# Resolver acceptance: approved and staged, awaiting attended startup

**Subsequent result:** the installation/restart and one-shot client run have
now executed. All 17 client checks passed. See the
[live result](2026-10-01-mini-resolver-live-result.md) for telemetry, pending
alert/cleanup checks and consumed-attempt paths. Do not rerun this command.

Matt approved staging and installing the exact resolver build on the Mini,
one normal restart, one laptop SSH/SMB/SFTP/AI and containment run, alert/file
verification and guarded cleanup. Little Snitch changes and publication are
excluded. The unchanged [scope](2026-10-01-mini-resolver-scope.md) remains a
checksum-pinned input; it records the proposal as it stood before approval.

## Verification on October 1, 2026, Eastern time

At 9:12 p.m., read-only Mini checks still showed ARM64, build `26A434`, boot
`1790777754`, both product jobs disabled and unloaded, no product processes,
and no `.240` or `.241` aliases. The sensor receipt remains 2.1.0 with install
time `1790818368`. The old guest manifest and guest executable hashes match.
No privileged PF, database or rule inspection was attempted in this staging
step; the root-attended preflight performs those checks before installation.

The laptop route remains `wlp0s20f3`, source `192.168.1.7`. Installed Samba is
`4.19.5-Ubuntu`; its help confirms the empty-config, explicit IP/port,
anonymous-user and Kerberos-off flags. `pexpect` is available.

The 12 focused resolver acceptance tests passed again with the extracted
candidate payload supplied. Local and remote installer SHA-256 match:
`47774088cd9eadc5aaddf38949e00a8b8f6eeb56c2192a5a72830d06d84a8aec`.
All 12 Mini staged files, including the bootstrap, match their recorded pins.
The laptop client matches
`6c3c9c28a9e994ea11f856ca76de46fac58507a72cad97ee962c6df88e6676ec`.

Remote shell syntax and both remote no-traffic plan modes passed. The Mini
directory is operator-owned 0700; the bootstrap copies and hashes its inputs
into a new root-private directory before any privileged execution. Laptop
staging is root-owned 0700, with client mode 0600 and no results file.

No installer, services, guest, aliases, PF reference or client probes were
started. No login was transferred. No configuration, database, Little Snitch,
Studio, Git or release state was changed.

## Exact attended Mini command

Keep both apps closed. Confirm the existing guest-only incoming TCP allowance
from laptop `.7` is still active without editing it. Leave any new or
mismatching filter prompt unanswered and report it.

Run on the Mini, not the Studio:

```sh
sudo /bin/bash /Users/matt/squirrelops-mini-resolver.FMVfY1Ri/start-mini-resolver-acceptance.sh
```

After verified backups, confirm `INSTALL RESOLVER FIX AND TEST 240`. At
`READY FOR TESTS`, tell Codex immediately and leave Terminal open. Do not
press Return until the client run and evidence collection finish. Return
then triggers guarded cleanup; an unattended window expires after 20 minutes.

## Next-agent handoff

- Mini staging: `/Users/matt/squirrelops-mini-resolver.FMVfY1Ri`.
- Local staging: `/private/tmp/squirrelops-resolver-staging.UsnG6jAX`.
- Laptop staging: `/root/squirrelops-mini-resolver-client.yquQ1Mfr`.
- Mini sanitized results prefix: `/private/var/tmp/squirrelops-mini-resolver-results.`.
- Durable backup prefix: `/Library/SquirrelOps/acceptance-backups/mini-resolver-20261001.`.
- Exclusive server claim:
  `/Library/SquirrelOps/acceptance-backups/relay-1790777754-47774088cd9e-attempt.json`.

Reuse the serial SSH control sockets under
`/private/tmp/squirrelops-post-reboot-staging.QwxlZTAG/` (`mini.sock`,
`laptop.sock`), with strict host checking and batch mode. No noninteractive
sudo access is assumed. The operator is responsible for the attended root
bootstrap; never collect an administrator password in chat.

When ready, verify fresh status, package, scope, boot and all five mappings.
Transfer root-produced `status.json`, `endpoints.json` and the synthetic
`login.json` privately, without printing the login. The client checks file
ownership/permissions, freshness and route before a single-use results claim.
Invoke exactly once:

```sh
/usr/bin/python3 -I -B /root/squirrelops-mini-resolver-client.yquQ1Mfr/mini_resolver_client.py --run /root/squirrelops-mini-resolver-client.yquQ1Mfr
```

Do not invoke this before fresh readiness or use an older client. Collect
sanitized results and compare alert/connection snapshots against first-start
and after-restart baselines. Ask Matt to press Return promptly after testing,
then verify the final stopped receipt, disabled jobs, absent aliases and
release of only this run's PF reference. No rerun or rule modification is
authorized by an inconclusive or failed attempt.

The engineering-constraints skill informed fresh checksum and plan-only
verification. This document records staging, not installed or live acceptance.
