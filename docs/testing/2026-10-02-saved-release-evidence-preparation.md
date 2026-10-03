# Retained release evidence review

Date: October 2, 2026. Status: **both attended exports completed and reviewed**.
See the [result](2026-10-02-saved-release-evidence-result.md); the commands below
are the historical procedure, not a request to rerun. No additional installation, probe, service restart or firewall change
is needed for this step. This is not a new acceptance run or a release waiver.

## Purpose and exact scope

The [MacBook upgrade](2026-10-02-macbook-upgrade-result.md) passed its defined
preservation and health checks, and Matt accepted the UI. Review its archived
before/after decoy metadata, scoped PF states and old alias ledger to explain
the address-set change and determine what retained-state evidence exists.
Only the completed archive
`macbook-upgrade-20261002.jikh0k2n` is read. The running installation and live
SQLite database are not opened by this exporter.

The Mini review reads two completed archives only:

- `mini-a5-20261002.DcmC5nO5`, nonce `c21040d915eb`.
- `mini-a5-edges-20261002.ouytf6ce`, nonce `cbba59af3e2b`.

It identifies bounded numeric PF metadata and the fixture's additional
`ready`, `bind_failed` and `listener_closed` event shapes that earlier exporters
withheld. Other unknown lines remain hashed and withheld. The original strict
counter results are retained unchanged, and `automatic_gate_pass` remains
false. No PF safety qualification closes merely because this exporter runs.

## Privacy and verification

The exporter reads fixed root-owned evidence paths. Archived standalone SQLite
snapshots use read-only immutable connections and reject sidecar files. Decoy
names, configuration, credential values and arbitrary log text are excluded.
The copied manifest stays private; only the old helper alias entries are
selected. The output is a new sanitized JSON file under `/private/var/tmp`.
Original evidence and its permissions are unchanged.

Local verification:

- `test_inspect_saved_release.py`: **24 passed in 0.07 seconds**.
- Combined exporter and upgrade-fixture suite: **69 passed in 0.28 seconds**.
  The first sandboxed attempt had 68 passes and one Unix-socket bind denial;
  the same synthetic suite passed outside the sandbox without changing tests.
- Ruff passed for the exporter and tests.
- `bash -n docs/testing/fixtures/inspect-saved-release.sh` passed.
- `git diff --check` passed.
- Non-root plan mode and all three transferred checksums matched on each host.

The MacBook's `/usr/bin/python3` is blocked by an unaccepted Xcode license.
No license was accepted or toolchain changed. Its installed SquirrelOps runtime
was verified as Python 3.12.12 with SQLite 3.50.4 and is used for this export.
The Mini's existing `/usr/bin/python3` was verified as Python 3.9.6 with
SQLite 3.54.0. Neither command starts the sensor or guest.

Pinned inputs:

| File | SHA-256 |
| --- | --- |
| `inspect_saved_release.py` | `2c801297ebbcfd36e7cc2d343095cc0c0bd5bc5ded6bcdf737db72e41a1f154c` |
| `inspect_completed.py` | `aa876cc0fb1076b3f4cecce3a144bd4eee980ffa524b6cfb11fa58447c3ef739` |
| `inspect-saved-release.sh` | `6ace16588eb951eca2396f149bcb6ad4e0b75a98e098d022579c380c306e1fef` |

## Attended commands

On the MacBook, 192.168.1.97. Its working app and sensor can remain running:

```sh
sudo /bin/bash /Users/matt/squirrelops-release-review.oFmWviec/inspect-saved-release.sh macbook
```

On the Mini, 100.108.203.27. Leave its product services stopped:

```sh
sudo /bin/bash /Users/matt/squirrelops-release-review.6smlhIEz/inspect-saved-release.sh mini
```

Each wrapper checks the source hashes in a new root-private staging folder,
then reads only the pinned completed evidence. Return the printed sanitized
`diagnostic.json` path for review. Do not paste the private database, manifest,
raw PF reference token or private command logs.

## Remaining boundary

The [completed review](2026-10-02-saved-release-evidence-result.md) resolves the
counter-format and child-event omissions while retaining the actual test limits.
The current installer is still
the accepted local-test artifact, not a signed/notarized public build. The
installer fixes, updated documentation and remaining test qualifications need
review before the final publication path. No new commit, push, PR or release
was made by this preparation step.
