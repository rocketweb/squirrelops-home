# SMB-only diagnostic: prepared and verified, not started

**Subsequent result:** this attempt is now consumed. The
[19:14 diagnostic report](2026-10-01-mini-smb-diagnostic-result.md) records all
four expected shares returned, exit 0, and a 20.841-second duration. Do not
rerun the commands below. Follow the result report for cleanup status.

Matt approved the next SMB-only window with "keep going" and reported that
the narrow guest incoming rule from laptop `.7` is still active. Its rule
configuration and lifetime were not independently inspected. No rule changes
are included. See the [exact approved scope](2026-10-01-mini-smb-diagnostic-scope.md).

The Mini's current public cleanup receipt still matches the completed filter
retest, and both product jobs remain disabled. The laptop's current route to
`.240` remains `wlp0s20f3`, source `.7`. The installed laptop SMB client is
Samba `4.19.5-Ubuntu`; its own `--help` confirms the selected diagnostic,
explicit-address/port and credential-isolation flags.

## Prepared behavior

The new window inherits the existing startup, observation, stop and PF
reference-release methods unchanged. It resolves the previous private backup
from the exact root-owned claim, pins its successful cleanup receipt, uses a
new exclusive claim and adds an SMB-only scope marker to readiness.
All original host, package, backup, ownership, database, listener, ARP and
cleanup checks remain. No product source, installer or live configuration
was changed.

The separate laptop client reads only endpoint and readiness metadata. It
does not read or transfer a login file. One explicit anonymous `smbclient`
share-listing invocation uses `.240:445`, empty client config and disabled
Kerberos. It has a 45-second deadline and a 256-KiB raw-output budget. No
credentials, file commands, SSH/AI probes or retry path are included.

Monotonic arrival times are recorded for debug output. Public output contains
only fixed stages, bounded status codes/dialect identifiers, known share names,
timings, exit/deadline outcomes and the private trace hash. Raw debug text
remains in a root-private file on the laptop. This does not equate stdout
arrival times with exact packet timing or automatically identify every SMB
substage. An unknown line is retained privately, not invented as a milestone.

The anonymous identity and clean client configuration differ from the previous
acceptance client defaults. This experiment is diagnostic, not permission to
weaken an acceptance gate or call a response after 20 seconds a timing fix.

## Verification this turn

New tests first failed because the modules were absent. An added process-exit
regression then failed with exit `-15`: stdout EOF could race client termination.
The capture now waits briefly for normal exit within the existing deadline
before cleanup. That regression and all focused tests pass.

```sh
sensor/.venv/bin/python -B -m unittest discover -s docs/testing/fixtures -p test_mini_smb_diagnostic.py -q
/Library/SquirrelOps/sensor/python/bin/python3.12 -I -B -m unittest discover -s docs/testing/fixtures -p test_mini_smb_diagnostic.py -q
sensor/.venv/bin/python -B -m unittest discover -s docs/testing/fixtures -p 'test_mini*.py' -q
```

Results: **15 focused tests pass on both interpreters**. Full harness suite:
**357 total, 354 passed, 3 existing optional skips**, 4.588 seconds. These tests
use mock host operations and disposable subprocesses/loopback fixtures, not
the live Mini guest. Printed mock install/cleanup messages are not live actions.
`git diff --check`, shell syntax, all remote input checksum checks, and both
remote plan-only modes passed. The fresh laptop result guard is unused.

| New input | SHA-256 |
| --- | --- |
| Mini window | `874b3db55ce6e096b2c78f60497027a746021dc4e0a2c156432b49b221ef2db3` |
| Mini bootstrap | `bc05eabf5e5f7dc9b5b46a9f96e7cbe7b352cf8591bb303bd0f28de74fa4b4d2` |
| Approved scope | `c435a3458ff5bd47a38c35e4de445591e14f049ab1cccbbc84f968cd91538a17` |
| Laptop client | `2bc07a0a4ec0ac624a7fb0d8bc197e15e97799d8772007b59857773a1528b892` |

Every unchanged bootstrap dependency and the existing package were also
checksum-verified on the Mini. The package was copied from the prior private
staging directory, not rebuilt, downloaded or installed.

## Attended command and one-shot handoff

Mini staging: `/Users/operator/squirrelops-mini-smb.HvkPvRep`.
Laptop staging: `/root/squirrelops-mini-smb-client.7xhb0h1T` (root-owned 0700).
Expected public result prefix: `/private/var/tmp/squirrelops-mini-smb-results.`

With both apps closed, run on the **Mini**, not test host A:

```sh
sudo /bin/bash /Users/operator/squirrelops-mini-smb.HvkPvRep/start-mini-smb-diagnostic.sh
```

Confirmation: `START ONE SMB DIAGNOSTIC`. At `READY FOR TESTS`, immediately
tell Codex and leave Terminal open. Leave new filter prompts unanswered.

The next agent must validate the fresh root-produced status and mappings,
transfer **only** `status.json` and `endpoints.json` privately to the fresh
laptop directory, and invoke exactly once:

```sh
/usr/bin/python3 -I -B /root/squirrelops-mini-smb-client.7xhb0h1T/mini_smb_diagnostic_client.py --run /root/squirrelops-mini-smb-client.7xhb0h1T
```

Do not run the prior all-protocol client. Collect sanitized results and Mini
checkpoints, then ask Matt to press Return immediately for guarded cleanup.
Verify the final receipt and stopped/disabled state. A new or mismatching
prompt is evidence to report, not authorization to alter a filter or repeat.

The engineering-constraints skill informed regression-first verification and
the explicit distinction between diagnosis and acceptance. Preparation has
not started the sensor/helper, guest, aliases, PF reference or SMB client.
No commit, push, signing, notarization or publication occurred.
