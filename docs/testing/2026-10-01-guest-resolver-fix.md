# Guest resolver fix: tested and rebuilt locally

The approved correction is implemented. The same local SMB client and guest
runtime took **20.073 seconds before** and **0.010 seconds after** to negotiate
and authenticate. Repeating against the guest extracted from the finished
installer took **0.011 seconds**. This confirms the resolver defect caused the
measured local stall. It does not complete Mini LAN or installed-upgrade acceptance.

No installed sensor, Mini service, firewall rule, database or configuration was
changed. Nothing was committed, pushed, installed or published.

## Change and deception review

The guest builder now stages the filesystem outside Docker's injected `/etc`
mounts, then installs the reviewed `network/hosts`, `hostname` and `resolv.conf`.
Both `studio-mini` and `studio-mini.local` resolve locally. The resolver points
only at loopback, with a bounded timeout for unknown names. There is no new
guest network adapter, DNS egress, dependency or runtime process.

The build-time verifier streams the gzip/newc archive without extraction. It
checks exact reviewed identity contents, metadata, missing/duplicate files,
path ambiguity, links, truncation, hexadecimal fields, compressed data integrity,
trailing content and a one-GiB unpacked budget. A correct manifest checksum
alone no longer authorizes builder DNS settings. Both guest build and app
packaging invoke verification.

Archive comparison found 3,788 entries in both images, no added or removed
paths, and only three changed non-directory entries: `/etc/hostname`,
`/etc/hosts` and `/etc/resolv.conf`. Twenty-eight directory link counts differ
because the rootfs is staged on a real directory tree rather than archived
directly from overlay mounts. Apart from these, content hashes, modes, owners
and link counts match. The kernel hash is unchanged.

Measured SMB identity changes are intentional and match the approved persona:

| Field | Before | After |
| --- | --- | --- |
| Dialect | SMB 3.1.1 (`0x0311`) | Same |
| NTLM NetBIOS computer | `STUDIO-MINI` | Same |
| NTLM NetBIOS domain | `STUDIO-MINI` | Same |
| NTLM DNS computer | Empty | `studio-mini.local` |
| NTLM DNS domain | Empty | `local` |

The workgroup remains `HAWTHORN`; it is not the standalone server's NTLM
NetBIOS domain field. No Samba or SSH configuration, banner, credential,
authentication policy, share, permission, protocol limit or guest containment
setting was changed. Full packet equality is not claimed: identity fields and
timing intentionally differ, and protocol nonces vary between boots.

## Verification

| Check | Result |
| --- | --- |
| Pre-fix packaging gate | Accepted a seeded builder resolver with a matching manifest hash; new regression failed |
| Pre-fix real guest | Regression failed at 20.073 seconds: negotiation 10.023, authentication 10.050 |
| Original guest identity capture | Failed latency check again at 20.091 seconds; DNS identity fields empty |
| Corrected fresh guest | 0.010 seconds, expected identity, local name resolution, SMB file roundtrip, clean exit |
| Comprehensive disposable real guest | SSH/SFTP/SMB file operations, wrong-password recovery, reconnects beyond 16 slots, half-close handling, containment and shutdown passed |
| Final full sensor suite | **2,454 passed, 3 skipped**, 3 dependency warnings, 88.20 seconds |
| Final focused packaging suite | **64 passed**, 4.72 seconds |
| Finished installer guest | Same image hashes; live identity/file test passed in 2.76 seconds, handshake 0.011 seconds |
| Packaged restart/shutdown regressions | **12 passed**, including isolated packaged-Python children, 3.78 seconds |
| App and Python signatures | Strict verification passed, ad-hoc payloads only |
| Guest executable | ARM64, unchanged from the previous diagnostic package, virtualization entitlement retained |
| Syntax/lint/whitespace | Bash syntax, full sensor Ruff check, verifier Ruff check and `git diff --check` passed |
| Cleanup | Every test called normal controller shutdown and checked exit zero; final anchored process lookup found no test runtime |

The three full-suite skips are two opt-in real-guest tests and the opt-in launchd
test. Both real-guest tests ran separately and passed. Launchd acceptance was
not repeated in this change. The complete live suite took 41.85 seconds.

The comparison used `smbprotocol` 1.17.0 with explicit synthetic `buildbot`
credentials on loopback, fresh guests and the identical ad-hoc debug runtime
(`855e7830f4493809fc3deb4ba2354c08d8ef1071d2dab049cd97dada1e5d54bb`).
This is not the Linux `smbclient` anonymous listing used in the previous LAN
diagnostic. The release executable's hash is unchanged, but its root-owned
input boundary was not bypassed to run user-owned test images.

One preliminary timing attempt reached the relay before Samba was ready and
failed without measuring latency. The final test waits for an SSH banner,
without logging in, before its first SMB connection. An initial identity
assertion incorrectly expected `HAWTHORN` for the NetBIOS domain; direct
before/after capture showed `STUDIO-MINI` in both images, and the assertion was
corrected. Two additional parser tests were watched failing for signed hex
fields and invalid deflate data before those checks were corrected.

## Installer and reproducibility

- Installer: `build/test-artifacts/SquirrelOpsHome-2.1.0-guest-resolver-20261001-local-test.pkg`
- Home/App/Sensor: **2.1.0**, ARM64 only.
- Size: **136,564,700 bytes**.
- SHA-256: `47774088cd9eadc5aaddf38949e00a8b8f6eeb56c2192a5a72830d06d84a8aec`.
- Unsigned installer, ad-hoc-signed payloads, not notarized. Local test only.
- Baseline: `a50179417e8f726ceb03bb6914a42cb996d2ead6` plus preserved earlier
  local release work and this fix. This is not a clean committed release SHA.
- Guest manifest: `cdbb8bcb53f4d3fc8c04703c7c5fce6b9903a38b263b8290a0fb7ba608b8e13f`.
- Guest initramfs: `3e30d8a0f367504cda3c8b6b9937427bf34fc31bef6cb671355cb8ce7695d4a4`.
- Guest kernel: `4c78ec153e7b8cf17011d44423ec2e11c9618933d4b931c60e63c240bf6db2f5`.
- Packaged guest executable: `762e6825939f2eecc1c4c2d704060b7cea624f9ba85801681ca83b7c411fb3f3`.

Build commands, from the release worktree:

```sh
ALPINE_IMAGE=alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b \
  bash guest/studio-mini/build-guest.sh arm64

DEVELOPER_DIR=/Library/Developer/CommandLineTools \
SQUIRRELOPS_SWIFT_SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
SQUIRRELOPS_SWIFT_SCRATCH_PATH=.build/relay-diagnostics-release \
SQUIRRELOPS_LOCAL_TEST_BUILD=1 SKIP_PKG_SIGNING=1 bash scripts/build-pkg.sh
```

The pinned package inventory passed using the reviewed cached dependency layer;
no dependency update was introduced. The guest was revalidated from the finished
installer with the final verifier, including the later malformed-stream checks.
The old image remains under `build/test-artifacts/resolver-20261001-before-arm64`.

Logs and JUnit XML are under `build/test-artifacts/resolver-20261001-*`, including
`before`, `before-identity`, `artifact-red`, `parser-red`, `unit-final`, `live`,
`final-sensor`, `packaged-guest`, `packaged-sensor`, `guest-build` and
`package-build`. Selected final source hashes are in
`build/test-artifacts/resolver-20261001-source-sha256.txt`.

Development, guest-build, release-security and release-note documentation was
updated. The engineering-constraints skill required observed failing
regressions and artifact-level verification; my-voice kept release copy factual
without broadening the local test result into a release claim.

## Remaining boundary

This closes the local resolver defect, not the full release gate. A new attended
Mini install/upgrade and bounded LAN run must verify this exact package with the
existing narrow filter policy, then verify cleanup. Do not reuse consumed test
commands, alter Little Snitch rules, restart held Mini jobs, or publish based on
this local result alone.
