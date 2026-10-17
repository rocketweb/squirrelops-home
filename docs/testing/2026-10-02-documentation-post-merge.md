# Documentation follow-up after the Home 2.1 merge

Date: October 2, 2026, America/Indiana/Indianapolis.

PR [#53](https://github.com/rocketweb/squirrelops-home/pull/53) merged at
03:47:21 UTC on October 3, still October 2 locally. Read-only GitHub checks
confirmed its merge commit and current `main`:
`300569ba15c375a77201cccfe7c27dc2d0da888e`.

The documentation corrections were not in that merge. They were prepared in
`.worktrees/home-2.1-documentation`, branch `docs/home-2.1-documentation`,
based on the exact merge commit. New installer, network-map and acceptance
records were preserved. Release-note corrections retain the new upstream
entries; the release-security guide retains the newly separated Home/Sensor
verification procedures.

Production sensor and guest source are unchanged from the original
[claim audit](2026-10-02-documentation-claims.md). That audit's full-suite and
real-guest results apply to their recorded baseline, not a fresh installer
acceptance. The post-merge changes outside documentation and help are limited
to an existing documentation-test assertion: Linux ARM64/x86_64 development
targets remain documented, with publication explicitly on hold.

Fresh checks in this checkout:

| Check | Result |
| --- | --- |
| App build and `DesktopExperienceTests`, fresh scratch directory and reviewed CLT macOS 26.5 SDK | Build succeeded; 9 tests passed. Existing toolchain search-path and app capture warnings remain. |
| `sensor/tests/unit/test_supply_chain_security.py`, explicit current `sensor/src` | 47 passed, 3.81 seconds. The first run exposed an assertion requiring the overstated Linux hardware promise; that assertion was corrected. |
| README and helper diagrams | Consistent row widths and wall positions confirmed. |
| Relative documentation links | All checked targets resolve. |
| Download page and manifest | Page is byte-identical to the earlier browser-checked correction; manifest remains unchanged. |

The README now identifies the merged Home 2.1.0 source, qualifies actual decoy
depth, and fixes the build commands. Studio source setup requires an ARM64
guest bundle; a debug app can build without it, while a release app cannot.

GitHub still reported immutable Home 2.0.3 as the latest published release,
with no `home-v2.1*` tag or new Home release workflow run. The README therefore
retains the verified 2.0.3 installation example and exact source/package pins.
Publishing 2.1, verifying its assets, replacing those pins, and promoting the
website's update channel are separate states.

At the time of these October 2 checks, the corrections were local. This
verification pass did not commit, push, merge, dispatch a workflow, publish a
release, or change an installed service. A read-only release refresh on
October 3 still found Home 2.0.3 as the latest published release.
