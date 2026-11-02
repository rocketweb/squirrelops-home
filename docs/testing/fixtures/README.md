# Historical Home 2.1 acceptance fixtures

These are the source and regression tests for the attended Mini/laptop sessions
recorded in the dated reports in the parent directory. They are not general
installation, repair, cleanup or penetration-testing commands.

The dated reports, scope documents and scripts label machines generically (test
host A, test host B or "the mini", the laptop client) and use substitute
addresses. The home LAN appears as 192.168.20.0/24, and tailnet and VPN addresses
as other 100.64.0.0/10 addresses. Each keeps its original last octet, so shorthand
such as `.240` still lines up. MAC addresses keep their vendor prefix or locally
administered bit and their zero-padding pattern. Every SHA-256 that pins one of
these files was recomputed after the substitution, so it describes the file as
it is here, not the bytes originally run. Package digests are unchanged. The
original files remain in git history.

Live runners pin a particular package, host, boot, configuration, prior receipt
and approved scope. Many of those sessions have been consumed. Do not run a
historical bootstrap or reuse a PF reference just because its file is present.
A new live run requires a fresh reviewed scope, current preflight evidence,
backups, cleanup plan and operator approval. Tests here do not authorize one.

Run the synthetic regression suite from the repository root:

```sh
sensor/.venv/bin/python -m unittest discover \
  -s docs/testing/fixtures -p 'test_*.py'
```

The normal suite uses mocks, temporary files and disposable local sockets. It
does not operate the installed Mini services or firewall. Optional tests that
inspect extracted packages require the corresponding
`SQUIRRELOPS_TEST_*PACKAGE_EXPANDED` environment variables. A separately gated
root-only launchd experiment is not part of normal verification. Do not enable
that experiment as a shortcut to live PF acceptance.

Eight historical evidence-replay checks also require privately retained Mini
captures. They skip explicitly in a clean checkout. Supplied captures still
must pass the original digest/content checks; missing files are not treated as
successful acceptance. The SMB input-validation regression uses synthetic
inputs and runs without private captures. None of these test-only skips changes
a live runner's fail-closed preflight.

Do not add runtime logins, API tokens, private backups, packet captures, PF
references, installed databases or raw command exports here. Runtime credentials
are supplied through private files, not source literals. Sanitized result
summaries belong in the dated Markdown reports; raw evidence stays in the
ignored `docs/testing/evidence/` or private host backup directories. Links to
those retained local captures are not public download links.
