# Home 2.1.1 guest build recovery

Date: 2026-10-03. Local Home review candidate, not a published installer release.

Follow-up: the separate build inputs have since been published and verified.
See [archive publication evidence](2026-10-03-guest-input-publication.md). The
local installer and runtime hashes below refer to the original local build.

## Outcome

The guest now builds from retained, hash-pinned APK files rather than resolving
dependencies from live Alpine repositories. Both architecture builds passed
without cached RUN layers, with package installation and rootfs assembly
networking disabled. The ARM64 guest passed real SSH, SFTP, SMB, identity,
isolation, and cleanup tests. A local Home 2.1.1 installer was built and its
extracted guest was compared byte-for-byte with that tested bundle.

There are **193 passing pytest cases** across the focused regression, real APK
installation, live guest, and extracted-sensor runs below. No tests in those
runs were skipped. These are local results, not remote CI or signed-release
acceptance.

Source baseline: `300569ba15c375a77201cccfe7c27dc2d0da888e`.
Branch: `fix/home-2.1.1-reproducible-guest`.
Changes remain local and uncommitted at this checkpoint.

## Why the earlier release stopped

[Home 2.1.0 run 37096783884](https://github.com/rocketweb/squirrelops-home/actions/runs/37096783884)
passed its protected-input gate, then failed the ARM64 guest inventory check.
The Alpine base image was pinned, but `apk add` still read a live repository.
Eleven dependency versions had changed since the inventory was recorded. The
inventory check correctly rejected those changes, before signing or publication.

Simply accepting new inventory text would make that build pass once without
making the next build reproducible. The recovery retains the actual dependency
files and keeps the existing signature and inventory checks.

The existing `home-v2.1.0`, `app-v2.1.0`, and `sensor-v2.1.0` tags were not changed.
Home moves to 2.1.1. Exact comparisons against the release workflow's component
path allowlists confirm that app and sensor sources still match their 2.1.0 tags.
Linux publication remains blocked; Intel Macs remain unsupported.

## Inputs and dependency review

Pinned base image:
`alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b`.

Each architecture retains 93 APKs. Together with the pinned base image, each
produces the same 109-package installed inventory. Two independent online
capture runs produced identical archive digests. Normal builds do not run that
capture path.

| Package | Previous lock | Candidate lock |
| --- | --- | --- |
| jq | 1.8.1-r0 | 1.8.2-r0 |
| libblkid | 2.42.1-r0 | 2.42.3-r1 |
| libcurl | 8.21.0-r0 | 8.22.0-r0 |
| libexpat | 2.8.4-r0 | 2.8.5-r0 |
| libldap | 2.6.14-r0 | 2.6.15-r0 |
| libuuid | 2.42.1-r0 | 2.42.3-r1 |
| linux-virt | 6.18.48-r0 | 6.18.54-r0 |
| mkinitfs | 3.14.0-r0 | 3.14.1-r0 |
| nghttp2-libs | 1.69.0-r0 | 1.70.0-r0 |
| pcre2 | 10.47-r1 | 10.49-r0 |
| xz-libs | 5.8.3-r0 | 5.8.4-r0 |

OpenSSH remains `10.3_p1-r1`; Samba remains `4.23.8-r0`. No guest persona files,
SSH/SMB configuration, authentication policy, banners, or containment settings
were edited. `packages.world` preserves the original top-level package requests,
so file-based installation does not expose every transitive dependency as an
explicit user request. Retained APK archives are not copied into the guest.

The changed dependency and kernel versions can be observed from a guest shell.
This is not a claim of indistinguishable behavior or full macOS virtualization.
The live tests below provide the local deception review evidence; independent
review must still accept this snapshot before it ships. Prior acceptance and
exceptions for the older guest do not automatically cover this kernel.

Archive metadata, with all per-package hashes in `package-inputs.lock.json`:

- `studio-mini-packages-arm64.tar`: 71,874,560 bytes,
  SHA-256 `7fab57984d555dbffdf9fe10c28f3e3016185e5470f8cf4e6adb3854fecf3ab0`.
- `studio-mini-packages-x86_64.tar`: 74,741,760 bytes,
  SHA-256 `35a54b5f9e99f6069ac60f98c83858110c2edae0f14cf4ef16e9fa30a602fe44`.

At the initial local checkpoint, these archives were retained under
`build/package-inputs-candidate-20261003/`, with intentionally null lock URLs.
The follow-up approved publication retained these exact bytes at the immutable
`guest-inputs-20261003-v1` prerelease and populated both public URLs. The archive
files remain outside Git. Public-download builds and verification are recorded
in the separate publication report; the tests and installer hashes below remain
the original local checkpoint rather than results for a different artifact.

## Verification

Host: Apple Silicon, macOS 27.0 build 26A428. The release-configuration local app
build used the installed macOS 26.5 Command Line Tools SDK.

| Check | Result |
| --- | --- |
| Focused supply-chain, APK input, package lifecycle, SQLite backup, component plist, LAN context, and guest identity regression files | 187 passed, 8.80 s |
| Real APK installation in disposable ARM64 containers | 3 passed, 8.28 s |
| Real ARM64 guest SSH/SFTP/SMB and fresh resolver/identity tests | 2 passed, 41.95 s |
| Restart-ownership test using the extracted installer Python with isolated imports | 1 passed, 1.23 s |
| Clean ARM64 and x86_64 guest builds | Both passed; bundle verification passed |
| Ruff on changed Python scripts/tests; shell syntax; whitespace | Passed |
| Local installer build and checksum | Passed |
| Extracted guest architecture, manifest, identity, hashes and containment validation | Passed |
| Extracted guest's three files compared with the live-tested ARM64 bundle | Identical |
| Extracted app's deep/strict ad-hoc signature verification | Passed |
| App and guest runtime Mach-O architecture | ARM64 |

The three actual offline APK tests cover successful installation, rejection of
an incorrect installed inventory, and rejection of signed packages when their
trusted keys are absent. They do not use a signature bypass. All container
mounts are read-only and containers are removed on normal exit.

Input validation tests exercise archive and package corruption, missing or extra
packages, duplicate entries, unsafe paths, links, wrong image/architecture,
malformed metadata, overwrite refusal, bounded downloads and HTTPS downgrade
rejection. New regression cases were observed failing before their fixes.

Supply Chain CI now builds both guests and runs the real APK tests. Its required
check uses an unconditional dependency-result guard: a failed or skipped guest
job must fail the required check, not make that check skip. Remote execution of
the changed workflow is still pending.

The real guest tests exercise repeated banner grabs, failed passwords followed
by a valid login, the 16-slot connection ceiling and slot recovery, authenticated
persona commands, SFTP and SMB read/write/delete, half-closes and reconnects,
host-canary absence, loopback-only network interfaces, and clean VM shutdown.
Fresh SMB negotiation plus authentication completed in **0.004 seconds** with
the expected `STUDIO-MINI` / `studio-mini.local` / `local` identity.

Local logs are retained under `build/`: `guest-arm64-offline.log`,
`guest-x86_64-offline.log`, `package-regression-tests.log`,
`apk-install-tests.log`, `live-guest-tests.log`, `local-installer-build.log`,
and `extracted-package-tests.log`.

## Local review installer

Artifact: `build/pkg/output/SquirrelOpsHome-2.1.1.pkg`.

SHA-256:
`0b83afe934e450643947e695c098778afa6ad4cb745bf5db45ac15d292e28514`.

Its component manifest reports Home 2.1.1, app 2.1.0, sensor 2.1.0, and sensor
API protocol 2. Embedded native code is ad-hoc signed. The installer itself is
unsigned and not notarized. Its one-time local-test opt-in remains required;
this run did not create that opt-in or install the package.

The embedded ARM64 guest contains:

- Kernel SHA-256 `e31110ab7979cee4cddcb975b36ab4f1231e98114eb8c360aeeffa00a6adbbc4`.
- Initramfs SHA-256 `049f6436c89740e8b69a441edcc79bcf9a77e8de83391641ec79863a82e8a39f`.

This establishes exact package-input retention and a tested local artifact, not
byte-for-byte reproducibility of timestamp-bearing initramfs or installer output.

## Remaining release gates

1. Archive storage, exact-byte publication, source companion, and public URL
   verification are complete. Review third-party source/notice coverage for the
   complete base image and Home installer before public Home distribution; the
   archive companion covers only the retained APKs.
2. Approve commit/push of this scope, obtain independent review of the changed
   package snapshot and workflow, merge, and verify required post-merge CI.
3. Authorize the new Home tag and protected release run. Do not rewrite 2.1.0
   tags or substitute this ad-hoc local package for the signed artifact.
4. Verify signing, notarization, and the exact new install/upgrade/runtime
   artifact. Decide the needed cross-device/PF regression scope with the reviewer
   because the guest kernel changed; this loopback test is not that acceptance.
5. Complete the independent publication gate, then verify the release assets,
   checksums/attestations, published documentation, and website download links.

No installed app, service, database, PF rule/reference, Little Snitch rule,
remote machine, GitHub source branch, or public website was changed. The initial
local checkpoint changed no GitHub tag or release; the follow-up published only
the separately approved archive tag and build-input prerelease.
