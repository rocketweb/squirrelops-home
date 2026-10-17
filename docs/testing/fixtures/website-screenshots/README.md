# Synthetic website screenshots

This fixture captures the real native Home views with entirely synthetic data.
It is not an installer, a running sensor, or evidence of network acceptance.

From the repository root on the reviewed development Mac:

```bash
bash docs/testing/fixtures/website-screenshots/build.sh
```

The script builds a separate app in a new `/private/tmp` directory. It copies
the production Home and local-enrollment sources, replacing only the app entry
point. The fixture entry point uses `DashboardView` and `CriticalAlertModal`
with an in-memory `SensorClientProtocol` implementation. No production startup,
pairing, Keychain read, WebSocket, notification service, sensor, helper or guest
is started. Unsupported requests and writes fail instead of contacting a sensor.

The script briefly brings seven synthetic windows to the foreground, captures
each window by its window ID, then closes them and exits. Screen recording
permission may be required. It never captures the whole desktop. No existing
application bundle, database, configuration or network setting is changed.

## Content and output

- Dashboard, Devices, Alerts, Decoys, Scouts, Settings and critical Alert overlay.
- Fixed 1280 by 800 point content area, plus the native title bar. On the
  capture Mac, each PNG is 2560 by 1656 pixels.
- Production fonts are copied and checked before capture. Nothing is painted
  over, composited, or generated to resemble an unimplemented interface.
- Static `PreviewData` is remapped to a fictional `192.168.50.*` network and
  generic names. The fixture uses current sensor device types, not the obsolete
  preview taxonomy that previously concealed the network-map grouping defect.
- One Studio host with five services, one NAS mimic, two host listeners,
  eight devices and two unread alerts. All counts, activity and times are fake.
- SSH and SMB credential-trip counts are zero: the opaque real-protocol relay
  does not observe encrypted credential contents.
- Output paths are printed by the script. Existing output images are never
  overwritten by the capture app.

The script currently selects the CLT macOS 26.5 SDK validated on this development
Mac. Change the SDK selection only after validating the replacement toolchain.
The fixture package name matches the production font resource bundle name.

## Website handoff

Inspect every PNG, then copy the seven `squirrelops-*-2.1-synthetic.png` files
into the website's `public/images/macos-screens/` directory. The macOS gallery
must disclose that its data is synthetic. Keep it labeled as a 2.1 preview until
the official release exists; screenshots alone do not authorize advancing the
download version, checksum or published release claims.

See [the capture and regression report](../../2026-10-02-network-map-screenshots.md)
for source, test and browser evidence.
