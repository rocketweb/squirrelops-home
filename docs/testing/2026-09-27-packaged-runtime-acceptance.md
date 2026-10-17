# Home 2.1 packaged-runtime acceptance

Date: 2026-09-27. Result: **passed** on macOS 27.0, build `26A428`, ARM64.

This closes the exact packaged-runtime live-test gap from the
[availability review report](2026-09-26-availability-review-fixes.md).
It does not establish installed-upgrade, LAN/PF, Intel, or notarized-release
acceptance.

## Authorization and boundaries

Matt approved making only the disposable `guest` directory and its three
copied artifacts root-owned beneath
`/private/tmp/squirrelops-availability-release.1SiEhD`.

- Exact targets: `guest`, `guest/manifest.json`, `guest/vmlinuz`, and
  `guest/studio-mini.initramfs`.
- Initial ownership: UID 501, GID 0. Test ownership: UID 0, GID 0.
- Ownership was restored to UID 501, GID 0 after acceptance. Modes remained
  `0755` for the directory and `0444` for the files.
- The runtime ran as UID 501, GID 20, not root. Its listeners bound only to
  `127.0.0.1`. The guest had no external network device or host share.
- Original artifacts and the installed app/sensor were untouched. No installer
  ran, no PF rule changed, and no merge, tag, release, commit, push, or PR update
  was performed during the September 27 acceptance run.

The restored disposable copy was retained for inspection; no material data
was deleted.

## Exact artifact

Tested checkout: `feature/deception-depth-2.1.0-current` at
`73f8b1c3987042abae1ad8eb830498457728ab07`. Product sources match
`3c2df5543aa1c343f13f5b2d699158d3bb709ca5`; the subsequent commit changes
only CI, tests, and documentation.

Installer: `build/test-artifacts/SquirrelOpsHome-2.1.0-availability-local-test.pkg`,
136,506,367 bytes. SHA-256:

```text
cc285b1c0061c1d424b602d43b1dc7e9a5573851a40e4a6a81f445eed32855e7
```

The executable used was the unmodified `Contents/Library/Helpers/com.squirrelops.deception-guest`
inside the app extracted from this installer. Runtime SHA-256:

```text
ffe268c31243004ebab5aaef12725a7e5308cbd5f81fa804edd6205a82704387
```

The extracted app passed `codesign --verify --deep --strict`. The ARM64 guest
passed `scripts/verify-guest-bundle.py`; the disposable copy matched all three
extracted guest files before and after testing. Installer and runtime hashes
also remained unchanged.

The installer is unsigned, its executables are ad-hoc signed, and it is not
notarized. These checks do not imply Developer ID signing or Gatekeeper approval.

## Live result

Command: `pytest tests/integration/test_deep_deception_live_guest.py -q --tb=short -ra`,
with `SQUIRRELOPS_DECEPTION_RUNTIME` pointing at the extracted runtime and
`SQUIRRELOPS_GUEST_BUNDLE` pointing at the approved disposable copy.
`PYTHONPATH` selected the extracted sensor site-packages. Import-path assertions
verified both `squirrelops_home_sensor` and `clownpeanuts` came from the package.
The test harness used the development virtual environment's Python, not the
installer's embedded Python.

**1 passed in 60.78 seconds.** Coverage included:

- 24 pre-authentication banner grabs and five incorrect passwords, followed by
  valid authentication.
- All 16 shared relay slots occupied, an exact capacity-rejection telemetry
  event, and recovery after the production 30-second half-close deadline while
  15 silent SMB connections remained open.
- SSH persona commands and SFTP/SMB listing, reading, writing, and deletion of
  synthetic acceptance files.
- 20 authenticated reconnect cycles and SMB negotiation after half-close.
- Host-canary absence and only the loopback network interface inside the guest.
- SSH/SMB outcome telemetry and clean runtime exit with both protocol sockets
  open. Runtime PID 64890 was observed during acceptance and was absent afterward;
  no process with the extracted-runtime path remained.

After ownership restoration, a separate invocation of the same executable
rejected the user-owned guest before boot: exit 1, `Guest file is unsafe: guest`.
This confirms the release ownership gate was not bypassed for the live run.

Raw logs remain in ignored local build artifacts:

- `build/test-artifacts/2026-09-27-availability-release-runtime-live.log`
- `build/test-artifacts/2026-09-27-availability-release-ownership-gate.log`

## Remaining release gates

Platform scope corrected September 30, 2026: Home 2.1 supports Apple Silicon
only. Intel execution is not a release gate. See
[macOS release support](../RELEASE_SECURITY.md#macos-release-support).

Installed upgrade, second-machine virtual-IP ingress, live PF acceptance,
remaining review findings, independent approval, and Developer ID
signing/notarization remain separate. No new installer build is needed for
this documentation-only follow-up; the tested bytes are unchanged. Matt
authorized committing and pushing this report with the release-candidate
documentation on September 28. That authorization does not include merging or
publishing the release.
