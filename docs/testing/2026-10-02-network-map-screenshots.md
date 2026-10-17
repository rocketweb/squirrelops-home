# Network map correction and synthetic website gallery

Date: October 2, 2026. Local follow-up to merged main
`d3ec67f656f0d5a23211cfa9ea86b61d47cb87ad`.

## Defect and correction

`NetworkMapView` grouped by raw `device_type`, then selected only seven old
category names. Current types such as `smartphone`, `nas` and
`network_equipment` were silently omitted. The sensor inventory remained intact;
only the dashboard map was affected.

The view now maps current and legacy type names into its existing display
groups. Unrecognized or empty types fall back to Unknown. Device objects,
classification, API payloads, trust state and order within a group are unchanged.
No decoy, network, helper or sensor behavior was changed.

## Regression evidence

`NetworkMapTests` was run before the correction. It failed with 31 assertions:
15 current device types disappeared, and future/empty types disappeared.
After the correction, all four tests passed, including 17 current-type cases,
legacy category ordering, unknown/future values and empty inventory.

The full native test command then passed:

```bash
cd app
DEVELOPER_DIR=/Library/Developer/CommandLineTools \
SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
swift test --sdk /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
  --scratch-path .build/ui-refresh \
  -Xswiftc -plugin-path \
  -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing
```

- App: 404 tests in 39 suites passed.
- Helper: 121 tests in 8 suites passed.
- Guest runtime: 30 tests in 5 suites passed.

Local logs: `/private/tmp/squirrelops-network-map-red.log`,
`/private/tmp/squirrelops-network-map-green.log` and
`/private/tmp/squirrelops-network-map-full-native.log`.

## Screenshot provenance

The [offline fixture](fixtures/website-screenshots/README.md) captured seven
native windows from this corrected source. Checksum-based `rsync` dry runs
confirmed that the copied production Home sources (except the replaced app
entry point) and local-enrollment sources matched the working tree.

Capture output: `/private/tmp/squirrelops-website-screens.xUoXnNgP/screenshots`.
All seven images were visually inspected: correct fonts, expected synthetic
content, no error banners or unrelated desktop content. Each is 2560 by 1656
pixels. Ordinary scrolling content below the window is not stitched into the
images. The Dashboard screenshot shows the top of the map, not all its rows.

The website changes are isolated in branch
`content/macos-2.1-synthetic-screenshots`, based on `e6c80fb`. They replace the
gallery references, disclose synthetic 2.1 preview data, set the correct image
aspect ratio and expose the selected gallery button with `aria-pressed`.
The public 2.0.3 download metadata remains unchanged. Old assets are retained.

| Screenshot | SHA-256 |
| --- | --- |
| Dashboard | `d919474ea90231b30f9e623229c32abcaae031f54b11f17363727288af21f0db` |
| Devices | `39003b00d1d055c805132975357c73eb80550f4ed33dfe856d87016aa2783c29` |
| Alerts | `accada05927e44a3d2596922917fa389a216beaccb2afa86e001b30eb807cc9f` |
| Decoys | `905b7e44f9fa5fa300b92b2c36150381207daea5fe37e476d83312e27bc10d91` |
| Scouts | `03051aace5e6d40f8887af36c53bc6bdca0eab1de3fe62bfaac0c5df6db63c85` |
| Settings | `f1274206f6d1476864360ec6f5cca87e7ff77ec9bbbea43ed1eabaf6a5644584` |
| Alert overlay | `d5338f912c28f4f6a67895fa435367be1e8332b8dea8a248dd5dcb98d6a7abd0` |

## Website verification

- Focused ESLint check of `app/macos/page.tsx` and
  `components/marketing/ScreenGallery.tsx`: passed.
- Production `npm run build`: passed, including static `/macos`. The first
  sandboxed attempt could not download Google Fonts; the network-enabled build
  passed without a code workaround. The final build used the corrected images.
- Served the production build only at `127.0.0.1:3211` for verification.
- All seven image selections decoded successfully at 1920 by 1080 and
  375 by 812 viewports. Exactly one button had `aria-pressed="true"` after each
  selection; neither viewport had horizontal page overflow.
- Enter on Next and Previous advanced Decoys to Scouts and back, retaining
  focus on the corresponding navigation button.
- The synthetic-preview disclosure was present and the download still pointed
  to 2.0.3. The browser reported no page errors.
- Desktop and mobile viewport screenshots were visually inspected. The narrow
  layout wraps all seven controls and scales the image without cropping. It
  does not make dense desktop screenshot text readable at phone width.

Verified browser captures: `/private/tmp/squirrelops-gallery-desktop-viewport.png`
and `/private/tmp/squirrelops-gallery-mobile-viewport.png`. Element-scoped
screenshots from the browser tool were blank, so they were rejected; the focused
viewport captures and DOM checks above are the accepted evidence.

## Release boundary

These changes are included in local follow-up commits, not pushed, merged,
packaged or published. Native tests and synthetic screenshots do not replace
the outstanding live PF safety
acceptance or signed-installer acceptance in the
[release follow-up](2026-10-02-release-gates.md).
