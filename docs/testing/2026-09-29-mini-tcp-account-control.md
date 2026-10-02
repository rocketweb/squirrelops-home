# Mini real-address TCP account-control diagnostic

Date: 2026-09-29. **First run completed with a policy change; its cleanup passed.**
**The authorized repeat passed all six client probes with no new prompt reported.**
Repeat cleanup passed and was independently checked. Neither run is full release acceptance.

## Verified scope and artifacts

The [approved diagnostic scope](2026-09-29-mini-tcp-diagnostic-proposal.md)
and [clock-corrected preparation](2026-09-29-mini-tcp-diagnostic-preparation.md)
apply. Matt started the v2 attended command on the mini. No product service,
installer, virtual IP, PF policy change, packet capture or guest was invoked.

- Mini address: `192.168.1.115`, management `100.108.203.27`.
- Laptop source: `192.168.1.7`, route `wlp0s20f3`.
- Root-private evidence: `/private/var/root/squirrelops-tcp-diag.Xxrf63pW`.
- Root-owned sanitized status: `/private/var/tmp/squirrelops-tcp-results.qx2zbq0s/status.json`.
- Script SHA-256: `b91bc0623c0cdb81b042fbb8f636d9a578c0ad2e9e2dc4d6635ae473149fd91d`.
- Client SHA-256: `9811f0c95b9d08f3080eaf7f5468b5ba94c6138107b91694fe6943674d8b1336`.
- Both children used the pinned installed Python executable, cleared supplementary
  groups, site-disabled isolated mode and the same fixed-banner code.

Before client execution, SSH verified the status directory/file were root-owned,
the phase was `observing`, its timestamp was current, and 157 seconds remained.
The pinned laptop client ran once with the verified ports `58651 58652`.

## Six client results

Three interleaved attempts per listener began between 19:03:08 and 19:03:18 UTC.
All six TCP connections completed. No authentication, application request payload,
scan or file operation was sent.

| Listener | Process | TCP connects | Correct banner within five seconds |
| --- | --- | --- | --- |
| `.115:58651`, `_squirrelops` UID/GID 309/309 | PID 33168 | 3/3 | 3/3, 28 bytes each |
| `.115:58652`, `matt` UID/GID 501/20 | PID 33169 | 3/3 | 0/3, three banner timeouts |

The root observer initially recorded three banner events only for UID 309.
For UID 501 it showed `qlen/incqlen/maxqlen` of `3/3/8` and three `CLOSE_WAIT`
socket rows with no transmitted application bytes. UID 309's queue was `0/0/8`.
The content-filter active count was 1; this alone does not attribute a verdict.

At approximately 19:03:47 UTC the root observer recorded all three UID-501
`banner_sent` events together, and its pending queue returned to `0/0/8`.
These late sends are not client successes: the laptop had already timed out.

Matt reported approving a connection prompt during the run, then said he did
not recall the named process or whether the approval was temporary/permanent.
The exact click time and resulting rule are unverified. The late queue release
is consistent with prompt-gated acceptance, but cannot prove which filter or
rule caused it. No agent-side filter changes or undo were attempted.

## Cleanup and retained evidence

At **19:05:26 UTC** the guarded root status reported `stopped`,
`baseline_verified: true`, no errors, and child exit codes `[0, 0]`. Its checks
include prior listener endpoint/UID preservation, absent probe listeners,
absent product services/VIPs, PF still disabled, and unchanged PF rule text.
Independent read-only SSH then confirmed PIDs 33168/33169 absent, neither probe
port listening, and both product launchd jobs absent. PF was not independently
re-read as root over SSH; that assertion comes from the attended root harness.

- [Six client records](evidence/2026-09-29-mini/tcp-account-client-results.jsonl).
- [Intermediate status](evidence/2026-09-29-mini/tcp-account-running-status.json).
- [Final status with 87 scoped samples](evidence/2026-09-29-mini/tcp-account-final-status.json).

## Interpretation and authorized repeat

The sensor account demonstrably accepted ordinary inbound real-address TCP
and sent the expected response in this run. This is not proof that virtual-IP
translation, launchd, ASGI or the guest work, and it does not explain or close
the prior virtual-IP failure. Account differences cannot be isolated from the
prompt approval with these results.

Matt asked to try again. A separate six-attempt repeat was prepared with the
current policy left untouched and no new rules authorized. The first client
log and single-use guard remain intact. New private laptop staging is
`/root/squirrelops-tcp-client-repeat.SGHgx9il`; its unchanged hash and plan-only
entry point were verified before its later execution recorded below.

The repeat used the same v2 attended mini command after the first session
finished. Its new status, ports and window were checked before probing. Ports
and result files from the first run were not reused.

No commit, push, package rebuild, release publication or A5 closure is claimed.

## Authorized repeat after the prompt approval

Matt started the same pinned v2 diagnostic again, with the existing filter policy
left in place. No agent-side filter adjustment, reinstall, service launch or
product-code change was made between runs.

- Private root evidence: `/private/var/root/squirrelops-tcp-diag.AXwP1glg`.
- Sanitized root-owned status: `/private/var/tmp/squirrelops-tcp-results.ja_ydqb_/status.json`.
- Client: `/root/squirrelops-tcp-client-repeat.SGHgx9il/mini_tcp_client.py`.
- Read-only pre-probe check: phase `observing`, matching address/peer and UID/GID
  mapping, fresh timestamp, 147 seconds remaining. Hash verified before client run.

At **19:08:43 UTC**, the fresh client made exactly six attempts:

| Listener | Process | TCP connects | Correct 28-byte banner |
| --- | --- | --- | --- |
| `.115:58723`, `_squirrelops` UID/GID 309/309 | PID 33563 | 3/3 | 3/3 |
| `.115:58724`, `matt` UID/GID 501/20 | PID 33564 | 3/3 | 3/3 |

All six client reads completed successfully. The root observer recorded three
banner-send events for each process, and both pending queues returned to `0/0/8`.
Matt explicitly reported **no new connection prompt appeared** during the repeat.
This is evidence of success under the current policy, not recovery of an
unchanged pre-approval baseline. The prior approval's rule scope and duration
remain unknown; no settings were inspected or changed to infer them.

- [Repeat client records](evidence/2026-09-29-mini/tcp-account-repeat-client-results.jsonl).
- [Repeat running status](evidence/2026-09-29-mini/tcp-account-repeat-running-status.json).
- [Repeat final status](evidence/2026-09-29-mini/tcp-account-repeat-final-status.json).

The repeat stopped at **19:09:22 UTC**. The guarded root report recorded
`baseline_verified: true`, no errors and both child exit codes 0, retaining 43
scoped samples. Independent SSH checks found neither PID 33563/33564 nor either
test listener. The root baseline verification covers unchanged PF rules and
PF disabled, prior listener endpoint/UID parity, absent product services and
absent test addresses. No separate root PF query was made over SSH.

The new processes and new ports worked without another prompt. This is
consistent with the earlier approval carrying over, but does not prove how a
particular filter represents that approval or how long it persists. It supports
that ordinary real-address inbound TCP and fixed-banner handling work for both
accounts in this environment. The original virtual-IP/PF/launchd/guest path is
still untested under the resulting policy and its release gate remains open.

Matt subsequently asked for a changed Python script and another run to observe
whether Little Snitch alerts. The [approved scope's v3 addendum](2026-09-29-mini-tcp-diagnostic-proposal.md)
preserves all bounds and changes only the fixed banner marker. The Python
executable and filter policy were not changed. The [v3 result record](2026-09-29-mini-tcp-changed-script.md)
now reports six of six correct edited banners and verified cleanup. Matt
explicitly confirmed that no new prompt appeared during v3.
