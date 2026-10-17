# Start-only protocol window preparation

Status: the attended start-only window and one laptop attempt have now run.
The [live result](2026-10-01-mini-installed-protocol-result.md) records the failed
SSH/SMB protocol gate and passing AI endpoints. This preparation record describes
the checks performed before startup; its staging and one-shot client are consumed.

The diagnostic package is already installed and its first startup and normal
restart passed. [Cleanup is now verified](2026-09-30-mini-relay-cleanup-fix.md).
There is no reason to repeat installation or that restart gate to obtain the
missing SSH/SMB protocol evidence.

## Minimal runner change

`InstalledProtocolWindow` inherits the corrected diagnostic runner through its
actual class hierarchy. It reuses the existing backup, runtime/identity checks,
health/publication checks, sanitization, observer and guarded teardown.
The parent now exposes its confirmation text and result-directory prefixes so
the start-only runner can present the correct scope without duplicating preflight.

The subclass pins the current installed hashes and receipt time, verifies the
durable successful-cleanup receipt, acquires one new PF reference, and bootstraps
only the existing helper and sensor jobs. It never invokes the installer or the
local-test installer opt-in, and it does not repeat the restart test. Teardown is
armed before the first bootstrap so partial startup still enters guarded cleanup.

The original seven decoys remain mandatory. Expected automatic classic additions
are retained under the existing rules. No SQL/configuration edits or new protocol
behavior are introduced. The one-use claim is separate from the consumed installer
attempt; it does not overwrite or bypass that historical claim.

## Local verification

The engineering-constraints skill kept live success claims separate from local
runner tests. Exact command:

```sh
sensor/.venv/bin/python -B -m unittest discover -s docs/testing/fixtures -p 'test_mini*.py' -q
```

Result: **324 run, 321 passed, 3 skipped**, 4.313 seconds with local loopback
permission. Skips are the opt-in root launchd probe and two extracted-artifact
checks whose environment inputs were not supplied in this pass. No remote probes
ran. Mocked cleanup messages are not evidence of another live cleanup.

The 11 new tests cover the exact successful receipt, rejection of incomplete
cleanup, installed baseline, installer/opt-in prohibition, consent and backup
requirements, conflict and one-use guards, ordered helper/sensor startup, partial
startup teardown state, the actual corrected reference-release chain, plan-only
behavior and all bootstrap input pins. The existing 23 diagnostic runner tests
also passed with their one optional artifact skip. Shell syntax and
`git diff --check` passed.

## Fresh Mini staging

`/Users/matt/squirrelops-mini-protocol.WJuCiUml` is the new staging directory.
Remote hashes match local inputs, shell syntax passes, and remote plan-only
execution confirms no installation, repeat restart, SQL repair or config edits.
The package file is only a source for a pinned private Python interpreter.

| Input | SHA-256 |
| --- | --- |
| `mini_installed_protocol_window.py` | `a77017016b1f1a3da16367d3aa0210efa4c175c46757994a1c84465ca9e1ba32` |
| Corrected shared diagnostic runner | `5f1c06c48157dc617bcbbfa92c74616bdf68d9f4457c7730f1b3df410c42a95b` |
| `start-mini-installed-protocol.sh` | `9bcd89898219e09b298fc427c857306efca5b5fdfe9a815f401d4f8e39341ea8` |
| [Prepared scope](2026-10-01-mini-installed-protocol-scope.md) | `1bd6c86d12b7fc6adbe3b43f4b0d3d643e3ec968ce475d3f84075de1f4b73e8f` |

```sh
sudo /bin/bash /Users/matt/squirrelops-mini-protocol.WJuCiUml/start-mini-installed-protocol.sh
```

Confirmation: `START INSTALLED BUILD AND TEST 240`.

The operator should send `READY FOR TESTS` immediately when it appears, leave
Terminal open, and not press Return until the bounded laptop run finishes.
The window auto-stops after 20 minutes. A stale or stopped receipt never authorizes
probes. The unchanged, still-unused laptop client is staged at
`/root/squirrelops-mini-upgrade-client.GWA3Ee6a`; transfer fresh readiness,
endpoints and the private synthetic login only after verifying this new window.
Do not display the login or use it outside the generated decoy.

Both apps stay closed. The Studio sensor remains held disabled and its `.240`
alias was independently absent at preparation. Startup approval in Terminal is
still required. No package installation, sensor startup, PF mutation, LAN probe,
commit, push, publication or change to Little Snitch occurred during preparation.
