# .240-only mini continuation: prepared, not applied

Matt approved the two-field mini configuration change and revised test command.
The new runner and client are staged and locally tested. Live configuration,
installation and restart acceptance remain pending the attended command. No
test host A configuration, service, alias or filter changes were performed.

## Scope and safeguards

The [approved scope](2026-09-30-mini-single-ip-scope.md) limits the test to
`192.168.20.240` and changes only `scouts.virtual_ip_range_end` from 241 to 240
and `scouts.max_virtual_ips` from 2 to 1 in the mini's sensor YAML. The installer
is unchanged, SHA-256
`3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c`.

Fresh read-only checks found both mini product services absent and the sensor
receipt still at `1790731448`. The previous first-start inventory contains only
`.240` in `virtual_ips`; the five Studio services are on that IP and classic
row 6 remains on `.115:60556`. The failed `.241` preflight remains preserved.
No new root-only configuration or PF state is assumed from these read-only
observations; the attended runner rechecks them.

`mini_single_ip_acceptance.py` loads private copies of the previous pinned
runner modules and narrows their ledger, snapshot, login and cleanup VIP set
to `.240`. Historical scripts are unchanged. This run's expected configuration
hash switches from old to new only after verified replacement. Probe and
metadata-capture implementations explicitly target `.240`, not `.241`.

Full install/data and SQLite backups precede confirmation. The config replacement
also preserves an exact private before-file, two-field change journal and inverse
instructions. It checks a regular single-link file, owner/mode/ACLs, source hash,
stopped state and inode/content stability, then uses a flushed same-directory
temporary file and atomic replacement. A failed or partial attempt retains
evidence; there is no automatic expansion back into the conflicting pool.

The actual layered config loader must accept the proposed file and resolve to
the one-IP pool before mutation. Persisted configuration overrides stop the run
without being edited. Profile capacity canonicalization does not change the
allocator's range bounds; a test verifies even a request for 50 allocations
returns only `.240`, then no more addresses. Normal sensor discovery remains
enabled on its existing subnet. No protocol/banner/persona implementation or
installer payload changed in this continuation.

## Verification

The engineering-constraints skill required evidence before widening any claim.
With the old two-IP ledger scope substituted, the new `.241` rejection test
failed (`RuntimeError not raised`). Restoring the single-IP scope passed.

| Check | Result |
| --- | --- |
| Complete local mini fixture suite, `unittest discover -s docs/testing/fixtures -p 'test_mini*.py' -q` | 182 passed with loopback permission; remote operations mocked |
| New single-IP suite using extracted candidate Python with `-I -B` | 22 passed |
| Exact two-field YAML diff and old/new SHA pins | Passed |
| Real disposable-file atomic edit, modes, backups, concurrent edit/inode change rejection | Passed |
| Real config schema, profile and IPAllocator single-address bound | Passed |
| Persisted override, ACL, unapproved edit and wrong client scope guards | Passed |
| Mocked bounded ARP probe and reply evidence; `.240`-only capture filter | Passed |
| Ruff, shell syntax and `git diff --check` | Passed |
| Mini and laptop plan-only modes | Passed without startup or probe traffic |

Existing Scapy/WebSocket dependency deprecation warnings remain; they are not
test failures. These tests do not establish successful live configuration
replacement, installation, real-VM restart, LAN acceptance or A5 isolation.

## Staging and pins

- Mini directory: `/Users/operator/squirrelops-mini-single-ip.GhTxy3KM`.
- Laptop directory: `/root/squirrelops-mini-upgrade-client.AK8t3vyw`.
- Both are private mode-0700 directories with mode-0600 inputs.
- Runner SHA: `d2bd94df4abd88663cd07ed5df316ae667eb51c66f8fd2dacc6045225e7d4cde`.
- Bootstrap SHA: `5a85561d47b6dcf36096377f4de4b4a03b334e7ac03b40204031698ad3d0e27b`.
- Scope SHA: `f49145d774f5fbbbfa8e605bd707759ffa80abf1f3216b7d6e69f56868c747ce`.
- New config SHA: `1318489677a7143395487f4a07703cac31b77577daf276000c36ca39414c2aa5`.
- Laptop wrapper SHA: `1ef90457cbcab376dee6d6683d28947e90cd4240075f1fd1d421b0218992523e`.
- Unchanged client dependency SHA: `f10d1b894eac9c05f13e2677f790d2f398d26e750eada6be2d63fdfcd44aab63`.

All mini inputs and the unchanged candidate are checksum-verified by the root
bootstrap after copying into a fresh private directory. The staged source files
and package have also been rehashed over SSH. No new package build is needed.

## Next attended action

On the mini, keep SquirrelOps closed and run:

```sh
sudo /bin/bash /Users/operator/squirrelops-mini-single-ip.GhTxy3KM/start-mini-single-ip-acceptance.sh
```

Enter `USE 240 AND TEST RESTART` when the verified backup and scope are shown.
At `READY FOR TESTS`, leave Terminal open without pressing Return and tell Codex.
Unexpected connection prompts stay unanswered. The observation window is 20
minutes, followed by guarded teardown; Return stops early.

For client continuation, use only `mini_single_ip_client.py --run` with the new
laptop directory. First verify fresh root-owned readiness for this exact package,
`test_scope=mini-single-ip-240`, `test_vips=[192.168.20.240]`, and
`config_change_verified=true`. Transfer only the synthetic guest login and the
matching endpoint/readiness JSON privately, without displaying credentials.
The old wrapper must not be used for this scope. Retain results and verify
teardown before any further app launch or release action.

This work made no live config edit, installer invocation, service mutation,
commit, push, merge, tag, public release or website update. Root execution and
all remaining live release gates are still pending.
