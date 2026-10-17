# Decoy status and pull-to-refresh

September 26, 2026. Local UI changes in the 2.1 candidate worktree.
Not packaged, installed, committed, or published.

## Behavior

- Routine Studio active, stopped, and disabled states no longer occupy a banner.
- Startup progress and useful failure details remain visible, including when
  there are no decoy cards. Startup status is refreshed while preparation is
  in progress and the Decoys view is visible.
- The permanent Refresh status button is removed.
- Pull down at the top of the list and release to refresh both decoys and
  system status. Empty and short lists use the same scroll container.
- Command-R, Refresh Decoys in the context menu, and a named accessibility
  action provide alternatives. Requests are guarded against overlapping
  gestures. Failed refreshes retain existing data and show the error.

## Verification

- The stopped/disabled regression failed before the notice-policy change.
- App and test target compile using the installed Command Line Tools and
  macOS 26.5 SDK, targeting macOS 14+. Full Xcode still requests license
  acceptance; no license was accepted or toolchain setting changed globally.
- 362 app tests passed in the final nonvisual run. This includes the notice
  policy, native scroll-event handling, short-pull and mid-list protection,
  cancellation, momentum filtering, refresh requests, error preservation,
  existing app state/networking tests, and font loading.
- Three visual test functions passed separately, including six light/dark
  stopped/starting/degraded previews and the existing empty diagnostic case.
  The initial relative-path test runner could not find fonts; an absolute
  test-bundle path resolved that harness issue. Earlier layout previews used
  fallback fonts, so they are not exact release typography acceptance.
- `git diff --check` passed.

The first native scroll implementation was rejected after a test exposed
SwiftUI's zero-sized AppKit document view. The final implementation takes
top-of-list position from SwiftUI and gesture phases from local native scroll
events, scoped to this scroll view and window. It returns events unchanged;
there is no global input monitor or accessibility permission requirement.

The Impeccable skill kept this a narrow simplification of the existing visual
system, preserving diagnostic information and non-gesture access. The
engineering-constraints skill required reproduction and executable checks.

## Evidence and limits

Evidence is under `build/test-artifacts/`: `decoy-ui-red-tests.log`,
`decoy-ui-final-build.log`, `decoy-ui-final-tests.log`, and
`decoy-ui-visuals/`. The final runner uses the absolute path to
`app/.build/ui-refresh/out/Products/Debug/SquirrelOpsHomeTests.xctest/Contents/MacOS/SquirrelOpsHomeTests`
and skips only `noticeVisuals|DeepDecoyVisualSmokeTests`, already rendered in
the bounded visual passes.

Native scroll events were synthesized locally in tests. A physical trackpad
gesture, keyboard-menu behavior, and VoiceOver still need acceptance in the
next installed build. The September 25 installer does not contain these UI
changes. No sensor, decoy protocol, guest, or installed application was changed
for this UI request.
