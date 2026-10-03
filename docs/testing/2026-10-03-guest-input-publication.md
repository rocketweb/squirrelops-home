# Guest build-input publication and public-download acceptance

Date: 2026-10-03. This records the approved build-input publication, not a Home
installer release, source merge, or Linux sensor publication.

## Published boundary

[guest-inputs-20261003-v1](https://github.com/rocketweb/squirrelops-home/releases/tag/guest-inputs-20261003-v1)
was published at `2026-10-03T12:32:08Z` as an immutable prerelease, with
`latest=false`. GitHub release ID: `402502813`. The latest Home installer remains
`home-v2.0.3`.

The signed annotated tag object is
`64af0e66151db6ea5f1bbb22b799fdc9ce2e5f6d`, pointing to source baseline
`300569ba15c375a77201cccfe7c27dc2d0da888e`. GitHub reports its signature valid.
The tag message binds the checksum manifest SHA-256:
`c51479f2915b786b8ff68f2ba1e063ce157d63b60cfbd73d56bc5ecd02fda188`.
No existing Home, app, or sensor tag was moved. This archive tag does not identify
the new build integration, which remains local and uncommitted on
`fix/home-2.1.1-reproducible-guest` at this checkpoint.

Eight assets were verified before and after publication:

| Asset | Bytes | SHA-256 |
| --- | ---: | --- |
| `BUILD-INPUTS.md` | 3,533 | `2cc30caa3e861ddd822db8d1a8d4c22f81be72b818b84c30f35060decb7249e7` |
| `SHA256SUMS` | 643 | `c51479f2915b786b8ff68f2ba1e063ce157d63b60cfbd73d56bc5ecd02fda188` |
| `SOURCE-INVENTORY.json` | 324,868 | `e175f6c6b8fe74dd0c46a331ac25ae54e4896a5a459e338c63b439a91135900a` |
| `THIRD-PARTY-SOURCES.md` | 10,888 | `241edcca93064ccffe1fd048dcb7ee2886d2eca0b088883d5ae82d0810498dff` |
| `package-inputs.lock.json` | 35,784 | `f0517f3aec1e5b0d181c96620d333728f82c0631512bcf01ed77030915c43069` |
| `studio-mini-package-sources.tar` | 540,569,600 | `ed83fc5c7e15b9ab66facd7c695ee99414394c79555bd8e288888e890ecb3285` |
| `studio-mini-packages-arm64.tar` | 71,874,560 | `7fab57984d555dbffdf9fe10c28f3e3016185e5470f8cf4e6adb3854fecf3ab0` |
| `studio-mini-packages-x86_64.tar` | 74,741,760 | `35a54b5f9e99f6069ac60f98c83858110c2edae0f14cf4ef16e9fa30a602fe44` |

Both APK archives are unchanged from the locally tested inputs in the
[initial build report](2026-10-03-reproducible-guest-build.md). All binary archives
remain outside Git. The lock now contains their immutable public download URLs.

## Source material and provenance limits

The source companion maps all 186 retained APKs to 66 Alpine source origins and
their exact recipe commits. It includes recipes, patches, configurations,
installation scripts, 284 checksum-listed source inputs verified against recipe
SHA-512 values, and 252 retained license/copyright/notice files. Original source
archives retain their notices. Capture and build tools are included as local
provenance records. Downloaded recipes were not executed during preparation.

These assets were prepared locally. The verified GitHub immutable-release
attestation binds the published tag and assets; it is not an Actions build or
capture provenance claim. The companion covers retained APKs only, not the
base image or the complete Home installer. Review that broader third-party
source/notice coverage before Home publication.

## Verification after publication

- `gh release verify guest-inputs-20261003-v1 --repo rocketweb/squirrelops-home`
  passed, including the immutable-release attestation.
- All eight assets were downloaded to a fresh directory. `shasum -a 256 -c
  SHA256SUMS` passed for all seven listed files. The downloaded manifest itself
  matched the hash bound by the signed tag.
- GitHub API checks confirmed exactly eight uploaded assets, their sizes and
  digests, public URLs, prerelease status, immutability, signed tag target, and
  unchanged latest Home release.
- Both guest architectures built successfully from public URLs with
  `SQUIRRELOPS_GUEST_PACKAGE_ARCHIVE` unset, `--no-cache`, and build networking
  disabled. Both bundle verifiers passed. No live APK repository fallback was used.
- Focused regression tests: **187 passed in 8.44 s**, with two existing
  WebSocket dependency deprecation warnings and no skips.
- Real APK installation tests with the public-download path: **3 passed in
  10.26 s**, no skips. Valid installation succeeded; incorrect inventory and
  missing trusted signing keys were rejected.
- Live ARM64 guest tests on the newly rebuilt bundle: **2 passed in 41.89 s**,
  no skips. Coverage includes SSH/SFTP/SMB, persona commands, connection limits,
  reconnects, identity/resolver behavior, no host canary, no virtual NIC, and
  clean shutdown. Fresh SMB negotiation and authentication took 0.005 s.
- Ruff on changed Python scripts/tests, shell syntax, and `git diff --check`
  passed.

These runs total **192 passing pytest cases**. They are local public-input
acceptance, not remote CI or signed-installer acceptance. No installed sensor,
host service, LAN alias, PF rule/reference, Little Snitch rule, or remote machine
was changed. Disposable test containers and the guest VM completed cleanup.

Public-input build output hashes:

- ARM64 kernel: `e31110ab7979cee4cddcb975b36ab4f1231e98114eb8c360aeeffa00a6adbbc4`.
- ARM64 initramfs: `c108c198d3c3ac581ea67fcd63ab46e7a1a1278ede7072ae4ef573b343a9cf7b`.
- x86_64 kernel: `c7ce829b618d4a9d2df79c58ea0fb2a392e606f6c47bb94696ea75610a568166`.
- x86_64 initramfs: `ecf5be85bba7bc711371faba30e89c240ef03da221fac8ed6b3158e78719cbea`.

The kernels match the initial local builds. Generated initramfs timestamps mean
whole-artifact byte reproducibility is not claimed. The earlier local review
installer was not rebuilt, installed, or published during this archive step;
its checksum and embedded guest hashes remain in the initial build report.

Logs and exact publication evidence are retained locally under
`build/package-inputs-publication/`: `publication-preview.json`,
`draft-verification.json`, `published-verification.json`,
`github-release-verification.log`, `regression-tests.log`,
`public-arm64-build.log`, `public-x86_64-build.log`,
`public-apk-install-tests.log`, and `public-live-guest-tests.log`.

## Remaining Home release work

Commit/push and PR creation need separate authorization. Then obtain independent
review of the package snapshot and workflow, merge, and verify required CI.
Complete the source/notice review above, the new Home tag and protected release
approval, signing/notarization, exact-artifact acceptance, and the publication
gate. The changed guest kernel's installed/LAN acceptance scope must be settled
with the reviewer. Website and Home documentation publication remain separate
from this archive publication.
