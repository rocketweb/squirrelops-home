# Temporary guest-rule retest: prepared, not started

**Subsequent outcome:** this prepared attempt is now consumed. The
[07:32 retest report](2026-10-01-mini-filter-retest-result.md) records passing
SSH banner and AI checks, an SMB listing timeout, and verified 07:34 cleanup.
Do not rerun the startup command below. The preparation record is retained
for provenance.

Matt reported "done continue" after approving the narrow 30-minute incoming
TCP allowance for the guest executable from laptop `.7` and one controlled
retest. The operator's rule selection is not independently verified. The
[approved scope](2026-10-01-mini-filter-retest-scope.md) requires it to remain
active at startup and forbids broadening or making it permanent.

At preparation, read-only SSH found the Mini's sensor/helper disabled and
unloaded, no matching product/guest process and no `.240`/`.241` aliases.
The previous root cleanup receipt is unchanged. The Studio's `.240` alias is
also absent. Laptop route remains `wlp0s20f3`, source `192.168.1.7`.

## Minimal runner changes

The previously tested start-only runner exposes a `claim_prefix` class constant;
its default remains `protocol`, preserving the old single-use guard. The new
`FilterRetest` subclass uses `protocol-filter-approved`, pins the exact October 1
cleanup receipt, supplies fresh result/backup directories and states the new
operator-approved scope. It inherits startup, shutdown and the corrected PF
release implementation without copying or overriding them. No consumed claim
or historical remote staging is altered.

The new preflight uses the actual shared superclass after checking the newer
receipt, retaining every existing host/payload/configuration/backup/ARP guard.
The installed package bytes and all product source remain unchanged. No app
installation, restart test, Little Snitch command or rule edit is performed.
Fresh private Python extraction still comes from the checksum-pinned package.

## Verification

New runner tests first failed because the module was absent, then passed after
implementation. The seven tests cover the real receipt hash and invalid-state
rejection, actual method inheritance, preservation of the old claim and
exclusive new claim, receipt-drift refusal before host preflight, exact scope
confirmation, every bootstrap pin and plan-only behavior.

```sh
/Library/SquirrelOps/sensor/python/bin/python3.12 -I -B -m unittest discover -s docs/testing/fixtures -p test_mini_filter_retest.py -q
sensor/.venv/bin/python -B -m unittest discover -s docs/testing/fixtures -p 'test_mini*.py' -q
```

Results: **7 new tests passed** with the installed pinned Python; **342 total,
339 passed, 3 skipped** in the full harness suite, 4.190 seconds. The existing
opt-in root/artifact checks remain skipped. Loopback permission was used for
synthetic local tests only. Mocked service/cleanup messages are not remote
activity. Shell syntax, remote plan-only execution and `git diff --check` passed.

Remote input hashes match local values:

| Input | SHA-256 |
| --- | --- |
| New retest runner | `f5e26d68e523c4dfd4d1f8fe51dc8d468ddc87504284f37e42fbab86f27b277a` |
| Shared start-only runner with default-preserving claim prefix | `01a5091fb201aed0ad3eb498cd4b3a8a38155a57030256c3b52b2ffc58d96c0a` |
| New bootstrap | `6b65d80eb0f346b8ebd4ef58eebe85a0b4b72e777f20012f045d033e742140a4` |
| Approved scope | `4cd55fe800701962d972c88b6c929ef15c0154e9959da5e37f1b2c8fb434ed0c` |
| Unchanged package | `3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea` |

The old local bootstrap's shared-runner hash was updated to preserve its local
pin test. Its consumed Mini copy and claim remain untouched and must not be
rerun. This preparation does not authorize replaying an old window.

## Fresh staging and next command

Mini: `/Users/matt/squirrelops-mini-filter-retest.1moGrUKm`.
New public result prefix: `/private/var/tmp/squirrelops-mini-filter-retest-results.`
Laptop: `/root/squirrelops-mini-upgrade-client.ROWFDZto`.

The laptop contains only the same two checksum-verified scripts, no credentials,
readiness or results yet. Diagnostic wrapper SHA-256:
`bc36f73427a1a2f9b15260b922e72636b138d13330ad8329d32212ab0ab91c03`.
Shared client SHA-256:
`15b3bb270b77d3801870d2a81b64dee266a8f823ce234f6b2be2ff360b02b7f6`.
Its plan-only mode passed. The existing readiness scope remains
`mini-relay-diagnostics-240`; fresh timestamp, current phase, exact mappings,
boot, package and remaining-time gates still apply.

On the Mini, with both apps closed and the approved temporary rule still active:

```sh
sudo /bin/bash /Users/matt/squirrelops-mini-filter-retest.1moGrUKm/start-mini-filter-retest.sh
```

Confirmation: `START APPROVED FILTER RETEST`.
Send `READY FOR TESTS` immediately; keep Terminal open and do not press Return
until the client finishes. New/mismatching filter prompts remain unanswered.

The engineering-constraints skill informed the pin, claim-preservation and
regression checks. No services, guest, aliases, PF references or laptop probes
were started by this preparation; no installer, product-source edit, commit,
push or release occurred.
