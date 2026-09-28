# Desktop polish review

Date: 2026-09-26

Status: implemented and locally verified. Not packaged, installed, committed,
or released. The currently loaded app was not replaced.

## Scope and approach

The app uses SwiftUI and AppKit, not an embedded web page. This pass preserves
the adaptive, scrollable body, the Space Grotesk/Space Mono identity, and the
red accent. It adds no package dependencies or web/native bridge.

Worktree: `.worktrees/deception-depth-2.1-current`, branch
`feature/deception-depth-2.1.0-current`. Existing release and sensor changes were
preserved. This pass changes app presentation, tests, and documentation only;
it does not alter attacker-visible protocols or decoy content.

The UI refinement used the existing design as its authority, prioritizing
readability, responsive controls, and native interaction over a redesign.

## Findings and changes

| Finding | Change |
| --- | --- |
| Devices toolbar overflowed at minimum width; search shrank to 84 points | Separate header/search from view/sort/group controls; native sort menu; 220-point search field |
| Alerts search shrank to 82 points and action/filter labels broke across lines | Native severity/type menus, compact Dates control, Actions menu for history/export/bulk operations |
| Device columns squeezed identifiers | All rows switch together to a compact arrangement below 720 points of content width, preserving full IP/MAC text |
| Settings groups had unrelated widths and excessive reading width on large windows | Consistent groups, bounded 760-point form width, compact spacing, matching page header |
| Supporting/status text failed contrast checks in both appearances | Appearance-aware supporting/status colors and readable accent text; unchanged solid accent for filled buttons |
| Long alert titles and hostnames were difficult to inspect | Two-line alert titles, independent timestamp line, hostname wrapping and full-name hover help |
| Decoy detail navigation depended on clicking a card | Explicit native View Details link with an accessibility label; existing card action retained |
| Alert dismissal appeared only on hover | Always-available labeled dismiss button, without hover-induced row movement |
| Failed alert detail had no visible exit or retry | Try Again and Close controls, Escape shortcut, safe disconnected-client handling |
| Scouts could suggest changing profiles after a connection failure | Unavailable status is distinguished from Scouts Not Enabled |

History clearing retains its confirmation dialog. Filters and action handlers
retain their existing semantics. In particular, Dismiss All acknowledges all
active alerts, not only the rows matching current filters; the guide now says so.

The earlier Decoys change remains intact: routine Studio status is hidden,
useful startup/attention notes remain, and refresh is available through pull,
Command-R, and the context menu.

## Verification

Host: macOS 27.0, build 26A428, Apple silicon. Compiled with the installed
macOS 26.5 SDK and Command Line Tools. The full Xcode license was not accepted
or changed as part of this work.

| Coverage | Result |
| --- | --- |
| App and test-target compilation | Pass |
| Complete app test bundle | 368 tests in 34 suites passed, 15.300 seconds |
| Dashboard, Devices, Alerts, Decoys, Scouts, Settings | 800×560, 1080×720, and 1600×1000, in light and dark appearances |
| Full-screen matrix | 36 renders; native search-field bounds/width assertions pass |
| Additional states | 11 renders: empty Devices/Alerts/Decoys, offline Settings/Scouts/alert detail, long Devices/Alerts, device/alert/decoy details |
| Text contrast | Six semantic text colors against three grouped/background surfaces in each appearance meet 4.5:1 |
| Whitespace/source check | `git diff --check` passes |
| Dependencies | `app/Package.swift` unchanged |

Before changing the UI, the regression run failed with 17 contrast assertions
and eight search-width/bounds assertions. The final run passes. An intermediate
test run failed because the screenshot output folder was not created before
the edge-state suite ran; the harness now creates its own output directory.

Build warnings remain for CLT developer search paths, missing arclite support,
and an existing weak-capture warning in App.swift. The build exits successfully.

### Evidence files

All paths below are relative to this worktree:

- `build/test-artifacts/desktop-polish-build.log`
- `build/test-artifacts/desktop-polish-red.log`
- `build/test-artifacts/desktop-polish-all-tests.log`
- `build/test-artifacts/desktop-polish-before/`
- `build/test-artifacts/desktop-polish-after/`

The screenshots use synthetic fixtures. They contain no production credentials
or live sensor requests. The existing complete app suite also exercises its
pairing/Keychain test fixtures; it is not a penetration test of the loaded sensor.

### Reproduce

From the candidate worktree's `app` directory:

```sh
DEVELOPER_DIR=/Library/Developer/CommandLineTools swift build \
  --sdk /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
  --scratch-path .build/ui-refresh --target SquirrelOpsHomeTests \
  -Xswiftc -plugin-path \
  -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing
```

From the worktree root, run the built bundle using its absolute path so bundled
fonts can be found:

```sh
DYLD_FRAMEWORK_PATH=/Library/Developer/CommandLineTools/Library/Developer/Frameworks \
DYLD_LIBRARY_PATH=/Library/Developer/CommandLineTools/Library/Developer/usr/lib \
SQUIRRELOPS_DESKTOP_UI_OUTPUT="$PWD/build/test-artifacts/desktop-polish-after" \
/Library/Developer/CommandLineTools/usr/libexec/swift/pm/swiftpm-testing-helper \
  --test-bundle-path "$PWD/app/.build/ui-refresh/out/Products/Debug/SquirrelOpsHomeTests.xctest/Contents/MacOS/SquirrelOpsHomeTests" \
  --testing-library swift-testing
```

## Limits and acceptance before packaging

These are isolated native view renders and automated regressions, not a claim
that every action was clicked in the installed foreground app. Offscreen
captures do not reliably represent native sidebar selection/default foreground
colors. Those should be checked in an active window rather than treated as
visual acceptance from these images alone.

Before packaging or release, verify in the foreground candidate app:

1. Resize with sidebar expanded and collapsed. Confirm native selection colors,
   focus rings, and text in light and dark appearances.
2. Tab through search, filters, menus, View Details, and Close. Check VoiceOver
   names/order and the pull-to-refresh gesture with a physical trackpad.
3. Exercise filtering, By Port, grouping, date selection, and export. Verify
   destructive menu actions still require the existing confirmation.
4. Scroll through the entire Settings form and inspect real, long device/host
   names and runtime diagnostics. Do not change live security settings merely
   to validate layout.
5. Verify older supported macOS versions separately. This pass ran only on
   this macOS 27 host; compilation with SDK 26.5 is not older-OS acceptance.

No installer should be inferred from this report. Packaging and installation
remain separate next steps after UI review.

## Foreground acceptance follow-up

The foreground follow-up began on 2026-09-26. It is not yet accepted.

- A temporary app was compiled in
  `/private/tmp/squirrelops-ui-acceptance.SezyXX`. Its Views and Theme directories
  match the candidate source exactly. Its app entry point uses synthetic data
  instead of pairing, notification registration, or a real sensor connection.
  The production app entry point was not changed.
- The app has a separate bundle identifier,
  `com.squirrelops.home.uiacceptance.sezyxx`, and is labeled
  `SquirrelOps UI Acceptance (synthetic data)`.
- Matt confirmed a physical trackpad is connected. The test app recorded
  precise scroll begin/end events followed by decoy refresh requests. His
  screenshot also confirms that the foreground sidebar selection is visible,
  unlike the earlier offscreen captures.
- The first refresh failed because the synthetic client returned an array
  instead of `DecoyListResponse(items:)`. A new regression reproduced the
  decoding failure before the fixture was corrected. This was test-fixture
  behavior, not a response from the installed sensor. The corrected harness
  has been rebuilt; a successful physical refresh still needs to be repeated.
- The initial System Events status query returned accessibility enabled, but
  actual UI inspection/control was denied with
  `osascript is not allowed assistive access. (-25211)`. That status query
  therefore did not establish that the automation process had permission.
- Keyboard and VoiceOver acceptance are blocked until macOS grants the
  requested Accessibility permission. VoiceOver was initially not running and
  was not enabled. No accessibility protection or permission was bypassed.
- The first temporary test process was stopped after the fixture failure.
  The corrected app is ready to reopen after permission is granted. The
  installed app, sensor, and installer were not replaced.

Additional evidence:

- `build/test-artifacts/foreground-acceptance-build.log`
- `build/test-artifacts/foreground-acceptance-runtime.log`
- `build/test-artifacts/foreground-fixture-regression-tests.log`

### Resumed foreground checks

Permission correction: on this Mac's macOS 27 build, the permission is named
**Device Control and Data Access**, under System Settings → Privacy & Security.
This name was verified in Apple's installed
`SecurityPrivacyExtension.appex/Contents/Resources/Localizable.loctable`, at
`en.ACCESSIBILITY`. Matt reported enabling ChatGPT and the Codex computer-use
entry; a separate entry named Codex was not listed. Subsequent System Events
queries successfully read the foreground window and the synthetic app's
accessibility hierarchy. No additional permission entry was required for this
session. Permission settings were not changed by automation.

| Check | Observed result | Acceptance |
| --- | --- | --- |
| Candidate parity | `diff -qr` returned no differences for Views and Theme between the temporary app sources and candidate | Pass for those directories |
| Corrected physical pull | Two precise scroll begin/end sequences were each followed by one successful `/decoys` read and one `/system/status` read | Positive gesture path passed; short-pull and mid-list negative checks await Matt's result |
| Command-R | Keyboard invocation in Decoys completed both fixture reads | Pass for refresh shortcut |
| Basic Tab navigation | Devices and Alerts search fields, lists, and sidebar received focus | Pass for those targets |
| All-control Tab traversal at 800×560 | Controls still skipped in Devices, Alerts, Decoys, and Settings after Control-F7 changed `AppleKeyboardUIMode` to 2; Decoys focus remained on the sidebar | **Not passed.** Need to distinguish application adoption of the OS setting from a candidate focus defect |
| VoiceOver startup and audible output | Command-F5 enabled VoiceOver; the OS preference reported 1. Matt confirmed hearing controls announced in the synthetic window | Audible output confirmed by Matt; not full reading-order/action acceptance |
| VoiceOver transcript | Direct `last phrase` and caption-property reads returned AppleScript error -1728; caption shortcut did not produce an inspectable panel | Automated transcript and complete traversal remain unverified; scripting permission was not enabled |
| Cleanup of temporary accessibility modes | Caption shortcut was reversed; Command-F5 turned VoiceOver off (OS preference 0); Control-F7 restored text/list Tab behavior (`AppleKeyboardUIMode` 0) | Original on/off behavior restored; original global keyboard key was absent, and is now explicitly 0 |
| Focused regressions | `swiftpm-testing-helper --testing-library swift-testing --filter 'fixtureDecoyResponse\|DecoyPresentationTests'` | 9 tests passed; full bundle not rerun in this follow-up |

Control-F7's all-control/text-and-list behavior is documented in
[Apple's keyboard shortcut reference](https://support.apple.com/en-au/102650).
VoiceOver has a separate optional scripting-control setting, described in
[Apple's VoiceOver General settings](https://support.apple.com/en-ae/guide/voiceover/cpvougen/mac).
The unavailable transcript is not evidence that the app is silent, and the
user's audible confirmation is not evidence of complete screen-reader coverage.

The native audit guidance kept these observed acceptance results separate from
automated view renders. No production UI fix was made during this follow-up.
The installed app, sensor, and installer remain untouched. The temporary app
was left on Decoys at 1080×720 for the physical negative-case checks.

Additional current evidence:

- `build/test-artifacts/foreground-acceptance-resumed-runtime.log`
- `build/test-artifacts/foreground-keyboard-focus.log`
- `build/test-artifacts/foreground-decoys-accessibility.log`
- `build/test-artifacts/foreground-decoy-link-attributes.log`
- `build/test-artifacts/foreground-acceptance-resumed-tests.log`

Before calling foreground acceptance complete: resolve/retest all-control
keyboard traversal, verify VoiceOver reading order and detail/refresh actions,
and capture the requested short-pull/mid-list physical trackpad results.

### Physical trackpad feedback

Matt repeated the gestures and reported that it seemed to be working, but he
could not see anything refresh. The resumed runtime log confirms further
physical scroll sequences followed by paired decoy/status reads. The synthetic
client returns identical data immediately, so successful refresh does not
change the cards and its loading indicator can be too brief to notice. The
test-only footer counters progressed from 8/10 to 18/20 during this round;
their absolute values differ because Settings also reads system status.

**P2 usability finding:** there is no durable-enough successful-refresh feedback
when the returned data is unchanged. Consider a brief, accessible “Updated just
now” confirmation that then disappears, preserving the request to hide routine
status messages. This was a recommendation at the time of the trackpad check;
the subsequently approved implementation is recorded below.

Positive physical refresh requests are verified. Matt's qualified observation
does not establish that each requested negative case left the counters
unchanged; do not mark the entire physical gesture matrix accepted from it.

The first decoy detail link was exposed as an enabled `AXLink`, but the
attribute dump did not yield a usable text label. Its source has an explicit
accessibility label. This is another reason to finish actual VoiceOver
name/order/action checks rather than infer them from source or generic AX dumps.

## Approved refresh confirmation implementation

Implemented locally after Matt approved the brief confirmation. The existing
visual style and semantic colors were retained using the Impeccable refinement
guidance. No dependency, installer, live sensor, or attacker-visible behavior
was changed.

- Explicit pull, Command-R, context-menu, and accessibility refresh actions
  share the existing refresh path. A checkmark and **Updated just now** appear
  only after both the decoy list and system status have loaded successfully.
- The confirmation overlays the list for three seconds, then fades over 0.2
  seconds. It does not shift the cards or consume clicks. Reduce Motion skips
  the fade; it does not remove the readable three-second confirmation.
- Background refreshes remain quiet. A failed or cancelled request never
  produces success feedback. A new refresh clears the prior confirmation;
  token-scoped dismissal prevents an older timer from clearing a newer result.
- Navigation cancels the pending UI refresh and dismissal. The existing error
  banner remains the failure path.
- Success posts the native
  [accessibility announcement](https://developer.apple.com/documentation/accessibility/accessibilitynotification/announcement)
  “Decoys updated” without requesting focus. Actual spoken acceptance of this
  new announcement was not performed; VoiceOver was not enabled for this pass.

### Verification for this change

The red run failed with five assertions because successful refreshes had no
confirmation. After implementation, `swiftpm-testing-helper --testing-library
swift-testing` passed **376 tests in 35 suites**, in **15.475 seconds**. New
coverage includes success with unchanged data, second-endpoint failure,
duplicate refresh suppression, cancellation, stale dismissal tokens, clearing
on navigation, and six light/dark confirmation renders at content widths of
560, 880, and 1400 points. The existing decoy gesture tests remain passing.

The isolated synthetic app was rebuilt from the changed candidate UI files.
`diff -qr` verified matching Views directories. A foreground Command-R test
completed paired list/status reads. Window-scoped screenshots at 814×720
points show the confirmation immediately after refresh and its absence after
3.5 seconds, with the header, note, and cards staying in the same positions.
The updated synthetic app was left open for Matt to try. The installed app and
sensor were not replaced.

`git diff --check` passes and `app/Package.swift` has no changes. Existing CLT
linker/search-path and arclite warnings remain; compilation exits successfully.
The prior keyboard traversal and complete VoiceOver acceptance gaps remain
separate unresolved work, not fixed or accepted by this confirmation change.

Evidence, relative to the candidate worktree:

- `build/test-artifacts/refresh-feedback-red.log`
- `build/test-artifacts/refresh-feedback-build.log`
- `build/test-artifacts/refresh-feedback-all-tests.log`
- `build/test-artifacts/refresh-feedback-foreground-build.log`
- `build/test-artifacts/refresh-feedback-runtime.log`
- `build/test-artifacts/refresh-feedback/confirmation-560-light.png` and the
  other five width/appearance renders
- `build/test-artifacts/refresh-feedback/foreground-confirmation.png`
- `build/test-artifacts/refresh-feedback/foreground-after-dismissal.png`

The user guide and 2.1 release notes now describe this behavior. No package was
built or installed, and no commit, push, or release was performed.

## Follow-up: keyboard and spoken labels

The [approved readiness-fix pass](2026-09-26-release-readiness-fixes.md) closes
the earlier keyboard-traversal uncertainty: a relaunched synthetic app confirmed
all-controls mode and exposed the expected Tab stops. Space opens decoy details;
Escape closes the sheet and returns focus to its link. Matt confirmed the link's
spoken service/address label. Native inspection also confirmed the Alerts label
alongside its badge, which the generic dump had omitted.

The pass found and fixed an actually unnamed lifecycle switch, preserving its
appearance and behavior. Full app tests now pass at 379 tests in 36 suites.
The new refresh announcement's spoken acceptance and individually confirmed
physical negative-pull cases remain separate from those completed checks.

## Follow-up: physical short-pull failure

Matt subsequently confirmed hearing **Decoys updated**, then reported that a
short pull increased the read counters. Two captured physical gestures proved
the old implementation counted accelerated input instead of visible movement.
The native clip-view measurement fix passes 382 app tests, including a
regression first observed failing on both captured sequences. Short-pull and
mid-list replays do not refresh. Corrected physical acceptance is still pending;
the existing installer candidate predates this fix. See the
[candidate acceptance record](2026-09-26-installer-candidate-acceptance.md)
for the diagnosis, tests, replay limits, and remaining release gates.

The subsequent full-pull check failed at the retained 64-point threshold.
Physical traces reached 47–52 visible points. Calibration to 44 points now
passes the captured full-pull regression and all 383 app tests. Foreground
replays show no short-pull requests, one request pair on a full pull, and no
requests from a pull starting within the list. Physical feedback on the final
calibration was pending at that point; no installer had been rebuilt or installed.

## Final trackpad acceptance

Matt subsequently answered **“yes works”** to the explicit check that short
pulls do nothing while a normal full pull refreshes. This accepts the final
44-point calibration in the production-source synthetic window. The final
three physical gesture pairs added one paired list/status read, from 4/4 to
5/5. Mid-list negative behavior retains foreground replay coverage. Exact
package upgrade and second-machine LAN checks remain separate gates.

The [candidate 2 installer](2026-09-26-acceptance2-installer.md) now contains
this accepted UI behavior and has passed fresh source and extracted-package
verification. It has not been installed or published.
