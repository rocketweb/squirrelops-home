# Ownership recovery: prepared, not executed

Date: 2026-09-29.

Product source, regression tests and operator/developer/release documentation
were committed and pushed as `a50179417e8f726ceb03bb6914a42cb996d2ead6` to
`feature/ai-setup-2.1`. The remote branch SHA was verified with `git ls-remote`.
PR: https://github.com/rocketweb/squirrelops-home/pull/52.
Independent review and CI for this new commit remain pending at preparation.

The local-test installer remains SHA-256
`2d5f4d287ca3ce971fd201f539d27a9272431f160a5a5debddc8d1b0b4dc7c82`.
It was built from the same product patch before committing. Its extracted
orchestrator is byte-identical to the committed source. It is not a signed or
notarized release. The prior full product validation is recorded in
[the ownership fix report](2026-09-29-classic-decoy-ownership-fix.md).

## Current verification

- Fresh product ownership/deep lifecycle/route-snapshot/packaged-restart run:
  **54 passed**, using `.venv/bin/python -m pytest` on the four affected test
  modules from the sensor directory. Ruff on `src tests` passed.
- Local fixture suite: **121 passed** with the exact extracted candidate
  Python, using `-I -B -m unittest discover -s docs/testing/fixtures -p
  'test_mini*.py' -q`. Ruff on the changed runner/client/tests and `bash -n` on
  the new bootstrap passed.
- Regression-first checks exposed and fixed missing durable cleanup receipts,
  journal permissions depending on the caller's umask, and loss of the client
  failure exit code. Sixteen new tests cover the scoped recovery/client path.
- The initial sandboxed fixture run could not bind four disposable loopback
  listeners. Repeating with local socket permission passed; no installed
  services or filters were changed by these tests.
- Fresh mini inspection: sensor and helper absent from launchd, only OS
  `distnoted` under service UID 309, installed receipt timestamp `1790711659`.
  Protected database contents cannot be inspected as `matt`; the attended
  root preflight must still verify them before offering the five-row preview.
- Laptop route: `192.168.1.240` uses `wlp0s20f3`, source `192.168.1.7`.
  Python, pexpect, SSH/SFTP and smbclient are available.

## Staged inputs

Mini: `/Users/matt/squirrelops-mini-ownership.HWmnJKQ8`, mode 0700.

Laptop: `/root/squirrelops-mini-upgrade-client.Ud9OIx96`, mode 0700.

Files were transferred without executing the test. Remote SHA-256 values match
the local inputs:

| Input | SHA-256 |
| --- | --- |
| candidate.pkg | `2d5f4d287ca3ce971fd201f539d27a9272431f160a5a5debddc8d1b0b4dc7c82` |
| mini_acceptance.py | `47b6c6df59083230ac63f97f1b32c55fa804f71839d433bfbc9fb952bf7bd40a` |
| mini_upgrade_acceptance.py | `4c732720e89da4b4a872b56e951b1b70b121e2db603185ecb36d298c99c464d3` |
| mini_ownership_acceptance.py | `fbefdc9a86cfde776fb691802ab443b8453b8067746872d62112e83fe5de8f22` |
| approved-scope.md | `48eeb6d6e1d5aad583493f6dd7315d653767c1655247e19c26eb82d3477d5b68` |
| start-mini-ownership-acceptance.sh | `872b2f9c31c946e99a4c7a2b0ea99e056597404c4c3b99038882b41a11a31d17` |
| mini_upgrade_client.py | `15b3bb270b77d3801870d2a81b64dee266a8f823ce234f6b2be2ff360b02b7f6` |
| mini_ownership_client.py | `35749262826c5b4a0b37b7add8481146dd6fbb40641e02e3f403ef4156dead93` |

## Next attended action

With SquirrelOps closed on the mini, run there:

```bash
sudo /bin/bash /Users/matt/squirrelops-mini-ownership.HWmnJKQ8/start-mini-ownership-acceptance.sh
```

Review the printed five-row preview. Type `RESTORE FIVE AND UPGRADE` only to
approve those exact changes and the pinned installation. Leave the Terminal
open after `READY FOR TESTS`, then tell the operator running laptop probes.
Leave new filter prompts unanswered and report them. Do not rerun consumed
earlier scripts. The full [scope and inverse](2026-09-29-mini-ownership-upgrade-scope.md)
are copied into the mini's staging directory.

No recovery, installation, service start, probe, Little Snitch change, PF change,
merge, tag, release, or website update was performed in this preparation. The
separate live A5 isolation matrix remains an additional release gate.
