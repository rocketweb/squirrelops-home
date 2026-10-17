# Historical Home 2.1 acceptance fixtures

These are the source and regression tests for the attended Mini/laptop sessions
recorded in the dated reports in the parent directory. They are not general
installation, repair, cleanup or penetration-testing commands.

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
