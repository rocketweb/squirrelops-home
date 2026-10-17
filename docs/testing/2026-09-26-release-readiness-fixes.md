# Home 2.1 readiness fixes

Current installer handoff and final trackpad acceptance:
[candidate 2 test record](2026-09-26-acceptance2-installer.md). The results below
document the earlier fix pass, not the identity of the current package.

Date: 2026-09-26. Scope: approved local packaging and accessibility fixes.

Earlier follow-up: Matt accepted the refresh announcement. A new package passed
extracted-code verification, but physical short-pull acceptance failed. See
[the continued acceptance report](2026-09-26-installer-candidate-acceptance.md)
for the subsequent correction and acceptance; the results below describe the
preceding fix pass.

The Swift output-path defect is fixed. Foreground keyboard traversal, detail
activation, dismissal, and focus return pass. A reproduced unnamed decoy
lifecycle switch now identifies the host or listener it controls. No installer
was created or installed, and no commit, push, or publication was performed.

## Changes

### Toolchain-aware app packaging

`app/build-app.sh` now asks Swift for its output directory using the same
configuration, architecture, SDK, and scratch path as compilation. Invalid,
multiline, non-absolute, missing, or out-of-scratch output paths fail closed.
It does not fall back to a stale architecture-specific directory.

- Optional `SQUIRRELOPS_SWIFT_SDK` selects an installed SDK explicitly.
- Optional `SQUIRRELOPS_SWIFT_SCRATCH_PATH` selects an isolated build directory.
- `--print-bundle-path` queries an existing build without rebuilding or signing.
- `scripts/build-pkg.sh` uses that same query instead of maintaining its own
  output-layout assumptions. Existing signing, guest, architecture, and
  release-policy checks remain in place.

The regression run first recorded 11 failures. All 13 cases now pass, including
modern and legacy layouts, paths containing spaces, matching flags, failed
Swift commands, invalid paths, preservation of an old bundle, and the package
builder's actual app-location block. The package block is exercised with a
stub builder; this is not an end-to-end installer build.

The real release app bundle was subsequently assembled with CLT and the
installed macOS 26.5 SDK on macOS 27.0 (26A428). Its app, helper, and guest
runtime come from `.build/final-readiness-release/out/Products/Release`.
The guest manifest was verified before and after copying; release path-leak
checks passed. All three staged executables report ARM64, `Info.plist` passes
validation, and the app version is 2.1.0. This is an unsigned staging bundle,
not a distributable package.
The Xcode license was not accepted or bypassed; commands select the working CLT.

### Keyboard and VoiceOver

The earlier Tab failure was not reproduced after relaunch with macOS Keyboard
navigation already enabled. The synthetic app's own
`NSApplication.isFullKeyboardAccessEnabled` reported all-controls mode. No
keyboard-preference change was needed in this pass.

- At the minimum window size, Tab reached Devices search, view mode, sorting,
  area grouping, and list controls; Alerts filters, date/action controls, and
  its list; Decoys lifecycle/detail controls; and Settings selectors/toggles.
- Tab reached a decoy detail link. Space opened one sheet; Escape closed it
  and restored focus to the same link. Command-R then made one paired decoy
  list/system-status request.
- Matt confirmed hearing “View details for…” with the service and address.
  The generic System Events dump omitted that label, but an in-process dump
  confirmed it. The link implementation was retained.
- The sidebar's unread item exposes label `Alerts` and value `2`. The earlier
  generic dump showed only its value. No sidebar rewrite was warranted.
- The lifecycle checkbox genuinely had a nil label. Its label now identifies
  the whole fake host and virtual IP, or the individual listener and endpoint.
  Missing/blank hostnames fall back to the decoy name. Its checked state still
  conveys enabled/disabled. The visible switch and native interaction remain
  unchanged.

Portable label regressions recorded six failed assertions with the original
empty label before the fix. They now pass. The fixed synthetic app's native
tree shows `Enable fake host studio-mini.local at 192.168.1.240` on its checked
checkbox. Its Views and Models files were compared against the candidate.
No live sensor, enrollment, Keychain, or decoy lifecycle request was used for
these UI checks.

The CLI test runner did not expose a complete SwiftUI accessibility tree for
its temporary windows. Those experimental tree tests were removed, not counted
as passing coverage. The retained tests cover label generation; foreground
inspection provides the control-level evidence above.

## Verification

| Check | Result |
| --- | --- |
| Full sensor suite, `pytest -q --tb=short -ra` | 2,259 passed, one opt-in guest test skipped, 87.49 seconds |
| Full app suite, `swiftpm-testing-helper --testing-library swift-testing` | 379 tests in 36 suites passed, 15.690 seconds |
| New packaging regression file | 13 passed |
| Package/security/backup/LAN contract selection after final doc edits | 144 passed, 8.96 seconds; overlaps the full suite |
| Release app bundle through the fixed script | Passed; final compilation 22.21 seconds, guest and path checks passed |
| Ruff, shell syntax, whitespace | Passed |
| Foreground synthetic keyboard/detail checks | Passed as described above |

The earlier live guest SSH/SFTP/SMB and containment run remains separate evidence
in the [readiness report](2026-09-26-final-installer-readiness.md). This change
does not alter guest binaries or attacker-visible behavior. Existing compiler
and dependency deprecation warnings remain.

The 411-file source/test/build-input manifest is
`build/test-artifacts/release-fixes-source-sha256.txt`, SHA-256
`95d55417acecaa02bdc8cc732344f3df8463b8f64623299a487abe11ee955e14`.
The final staged app executable SHA-256 is
`4fd727fb113027006fa8b990f1e4dba851a1c1746abc8b6544634a65c3284dfb`.
These identify local bytes, not a signed release or exact-candidate CI result.

## Remaining acceptance and release boundaries

- Spoken acceptance of the new “Decoys updated” announcement is still awaiting
  Matt's response. Full VoiceOver reading-order/custom-action acceptance is not
  established by the narrower checks above.
- The physical short-pull and mid-list negative gesture cases are not yet
  individually accepted. Automated gesture boundaries pass; earlier physical
  positive refreshes were observed.
- Build and inspect one exact installer candidate, then obtain approval to
  install that artifact with rollback copies and a verified database snapshot.
- Verify upgrade/enrollment prompts, Settings, decoy/mimic creation and
  persistence, and second-machine LAN SSH/SMB-to-alert behavior.
- Public signing/notarization, CI, protected tags, and publication remain
  separate actions. Linux publication remains independently gated.

Evidence lives in `build/test-artifacts/release-fixes-*`, plus
`swift-build-paths-red.log` and `swift-build-paths-green.log`. Development and
operator documentation were updated. The installed app and sensor were not
changed. VoiceOver was restored to its initial off state (0); Keyboard
navigation remained at its initial enabled value (2). The synthetic Decoys
window was left open. All 411 manifest entries were rechecked successfully.
