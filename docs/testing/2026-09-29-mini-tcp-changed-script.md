# Changed-script TCP diagnostic (v3)

Date: 2026-09-29. **All six live v3 banner checks passed; cleanup passed.**
**Matt confirmed that no new prompt appeared during the v3 run.**
Matt explicitly requested a script edit and another run to observe whether it
causes a Little Snitch alert. The prior repeat passed six of six reads with no
new prompt; [its cleanup passed](2026-09-29-mini-tcp-account-control.md).

## Exact change and limits

Only the diagnostic banner changed from `SquirrelOps TCP diagnostic\r\n` to
`SquirrelOps TCP diagnostic v3\r\n`. The listener's inline Python source actually
changes, and the laptop verifier now requires the new 31-byte banner. The
installed Python executable, isolated `-c` launch, users, privilege drop, bind
address, allowed peer, port range, three-minute ceiling and six-attempt bound
are unchanged. The [approved scope](2026-09-29-mini-tcp-diagnostic-proposal.md)
contains a v3 addendum and the wrapper pins the new script/scope hashes.

No product code, filter rule, executable identity, signature, installer, service,
route or VIP is changed. Prior remote staging directories and evidence remain.
Do not reset a rule or re-sign/copy Python to manufacture an alert.

The agent-browser skill was used to read the vendor's rule documentation.
Little Snitch documents process matching by path or code ID and optional
owner/process-pair restrictions, not a promise of an alert after every Python
source edit. Since the same Python executable is used, an existing approval
may still apply. That is an inference to test, not an assured outcome.
[Primary vendor documentation](https://help.obdev.at/littlesnitch6/concepts-rules).

## Verification and pins

Two new version-marker assertions failed against v2 first. After editing, all
**29 tests passed** both with Apple's Python 3.9 parent plus the exact extracted
sensor Python 3.12 child and with the local Python 3.12 pair. The mixed-runtime
command is recorded in the [clock correction preparation](2026-09-29-mini-tcp-diagnostic-preparation.md).
Ruff passed. Wrapper `bash -n` passed locally and remotely. Remote plan-only
entry points passed without listeners or client traffic.

| Artifact | SHA-256 |
| --- | --- |
| `mini_tcp_diagnostic.py` | `8d3330aca67038485c0b8cf9ede00c8cb1864cc60363455a39ac7f4c2001d370` |
| `mini_tcp_client.py` | `80c5fe73901aad2b40c0e0bede82ee5ebc2a48df9ae42257e9c81bb36f439719` |
| `start-mini-tcp-diagnostic.sh` | `0a3d809c6f1dc3dd7097963c46874746aed1cf8d752d61f3532dca38ba31e912` |
| `approved-scope.md` | `6f75109eb6cc4bb633411e47522638b8958cc1cc3fb7c148515fb54063471b61` |

All staged hashes matched. The mini's installed executable still hashes to
`d2555cd22a33506826f9eb069bb13fb0cc41303c7da41da5b761967d616f4147`.

Mini staging (matt-owned, 0700): `/Users/matt/squirrelops-tcp-test-v3.9UdJBWGy`.
Laptop staging (root-owned, 0700): `/root/squirrelops-tcp-client-v3.VB5EwtOz`.
The staged client's six attempts have now been consumed and its result file is
retained. Do not rerun it or remove its single-use result guard.

## Attended command used

On the mini, keeping SquirrelOps closed:

```sh
sudo /bin/bash /Users/matt/squirrelops-tcp-test-v3.9UdJBWGy/start-mini-tcp-diagnostic.sh
```

The user reported ready. No further run of this command is authorized by that
completed six-attempt scope. Record any prompt separately from protocol success.

## Live v3 results

The root-owned mode-0644 status file is
`/private/var/tmp/squirrelops-tcp-results.fczkppqu/status.json`, in a root-owned
mode-0755 directory. Before probing it was `observing`, timestamped less than
two seconds before the mini's current time, with **151 seconds remaining**.
The peer/address and UID/GID mappings matched the approved scope. The laptop
client's SHA-256 matched the v3 pin and its exclusive results file was absent.

At **19:17:13 UTC**, the laptop ran exactly three interleaved attempts per port:

| Listener | Process | TCP connects | Correct v3 banner |
| --- | --- | --- | --- |
| `.115:58794`, `_squirrelops` UID/GID 309/309 | PID 33845 | 3/3 | 3/3, 31 bytes each |
| `.115:58795`, `matt` UID/GID 501/20 | PID 33846 | 3/3 | 3/3, 31 bytes each |

Every response matched the new banner exactly, demonstrating the edited inline
Python code executed. The root observer recorded three banner-send events for
each child; both queues were `0/0/8` afterward. The client finished with exit 0.
No additional probes, credentials, client application payload or file operations
were sent. After the results were reported, Matt explicitly answered "no prompt"
for this v3 run. Prompt absence is therefore an operator observation, not an
inference from successful TCP reads.

- [Six v3 client records](evidence/2026-09-29-mini/tcp-account-v3-client-results.jsonl).
- [V3 running status](evidence/2026-09-29-mini/tcp-account-v3-running-status.json).
- [V3 final status with 87 scoped samples](evidence/2026-09-29-mini/tcp-account-v3-final-status.json).

## Cleanup verified

At **19:19:26 UTC**, the attended root harness reported `stopped`,
`baseline_verified: true`, no errors, and both child exit codes 0. This covers
prior listener endpoint/UID parity, absent test listeners and addresses,
stopped product jobs, PF still disabled and unchanged PF rule text.

Independent read-only SSH afterward confirmed no PIDs 33845/33846 (`ps` exit 1,
empty stdout/stderr), no `.115:58794` or `.115:58795` listeners (`netstat` exit 0),
and both product launchd jobs absent (exit 113 with exact missing-service errors).
PF and complete native-listener baseline parity remain assertions of the guarded
root run, not separate root SSH queries. Evidence was retained; no cleanup
reset, installer, app launch or filter-rule change was performed by the agent.

This proves the modified diagnostic's real-address TCP path works for both
accounts under the current policy. Together with Matt's observation, this
specific inline-code/banner edit did not produce another connection prompt.
That is consistent with the existing executable-based approval continuing to
apply, but the matched rule, its scope and its lifetime were not inspected.
It does not establish that every Python script edit will behave this way or
explain the original virtual-IP listener failure.

This experiment does not close the product virtual-IP/guest or A5 release gates.
No commit, push, installer build, installation or release is claimed.
