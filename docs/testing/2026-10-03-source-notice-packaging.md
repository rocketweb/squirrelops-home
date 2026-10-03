# Home 2.1.1 source and notice packaging verification

Date: 2026-10-03. Baseline: merged PR #55,
`f969048552523bf238db3b5d30a6d6b14d988c28`.

Result: local packaging and regression checks pass. This is a technical
distribution review, not a legal opinion or a final signed-release acceptance.

## Changes and boundaries

- Source coverage now checks all 109 installed guest packages. The existing
  immutable source archive covers 93; a supplement retains the other 16 from
  10 Alpine base origins. The supplement has 148 pinned recipe/source files.
- Exact Alpine recipes and patches were retained at the commits in package
  metadata. Recipe Git blobs and literal source SHA-512 checksums were checked.
  The `alpine-base` recipe only generates release text; it has no remote input.
- The final Home source companion includes that supplement, the unchanged
  original source archive, 39 exact Python source distributions, standalone
  Python build metadata/notices, and packaging instructions.
- Scapy is excluded from macOS runtime dependencies. It remains a Linux
  dependency and a Mac development-only dependency for checking Linux code.
  No other third-party dependency version changed.
- The original PolyForm Noncommercial 1.0.0 text is copied unchanged into the
  sensor wheel, source package and installed notices. README wording now agrees
  with that license. No product relicensing was performed.
- Home is 2.1.1, app remains 2.1.0, and sensor advances to 2.1.1.
- Source/inventory/notice assets are mandatory release inputs, included in
  checksums, release metadata, uploads, attestations and the existing final gate.

No app, guest, persona, protocol, sensor runtime implementation, installed
service, customer data, PF, Little Snitch, or remote-host changes were made.
The guest image bytes are unchanged from the previously verified candidate.
No tag, workflow dispatch, public release, merge or installation is included
in this verification.

## Tests

Commands ran in the isolated `home-2.1.1-source-notices` worktree.

| Check | Result |
| --- | --- |
| `cd sensor && uv run pytest tests/ -q` | 2,502 passed, 6 skipped, 3 upstream deprecation warnings |
| Clean Mac test environment before adding development-only Scapy | Same 2,502 tests passed with Scapy absent |
| `cd sensor && uv run ruff check .` | Passed |
| Ruff on the three changed/new packaging Python scripts | Passed |
| `cd sensor && uv run pyright src/` | 0 errors, 29 type warnings |
| `git diff --check`, shell syntax checks | Passed |
| ARM64 local installer build | Passed; unsigned installer, ad-hoc signed app/native payload |
| Extracted app signature and architecture | Strict/deep signature verification passed; ARM64 |
| Extracted wheel/project terms | Original license bytes and license metadata present |
| Extracted Python runtime | 40 distributions: sensor plus 39 third-party; Scapy absent |
| Guest source coverage | 109/109 exact name/version/origin/recipe-commit/license matches |
| Installed vs adjacent release notices/inventory | Byte-identical |
| Source companion inspection | All 148 base files and 39 Python sources hash-match their locks |
| Local release-asset preparation | Nine files prepared; all seven `SHA256SUMS` subjects verified |

The six skipped integration checks remain opt-in environment-dependent tests.
This change does not claim a new installed upgrade, live LAN/PF test or final
Developer ID/notarization check. No Swift source changed; the app compiled as
part of packaging, but its full test suite was not rerun in this pass.

The Scapy regression failed before the marker change. New checks cover missing
base source inputs, cache corruption and symlinks, unsafe archive paths,
runtime Scapy detection, the guest database reader, missing/changed release
companions, and the narrow Python metadata exception below. An old source
package allowlist test initially rejected `LICENSE`; it now explicitly permits
that file and checks it against the unchanged root license.

## Python upstream metadata exception

The pinned standalone Python full archive is release 20260211, Python 3.12.12,
ARM64, SHA-256
`bf70a8ba4d44eb243af9dc3485656e0ce3757588eefe27e1801b36ff9773805a`.
Its zlib metadata names both zlib and zlib-ng notices, but only the zlib notice
exists. Its exact extension link record is `{"name":"z","system":true}`.
The installed runtime reports system zlib 1.2.12. The retained upstream source
tag is `6b6905a3fe672117cff7563e2c0a375a92fd1c5a`.

The builder records this stale zlib-ng reference in the inventory and permits
it only for that system-library link shape. A regression test changes the link
to a bundled static library and verifies rejection. Other missing Python build
notices still stop packaging. No Python binary or dependency version was changed.

## Local artifacts

Directory: `build/pkg/output/` in this worktree.

- `SquirrelOpsHome-2.1.1.pkg`, SHA-256
  `eec208ad55303cd3d2eb99ed53f6428c4543ba56c318b78d77bad507778be1d7`.
- `THIRD-PARTY-SOURCES.tar`, 623,820,800 bytes, SHA-256
  `e49a09d6be56ac8ea694dfa6849155f802330997bfd9467c3df4e1518f10074a`.
- `THIRD-PARTY-INVENTORY.json` and `THIRD-PARTY-NOTICES.txt`.
  There are 348 retained notice entries; the installed notice file is
  2,861,176 bytes. The large source archive is not installed.

Build command:

```sh
SQUIRRELOPS_LOCAL_TEST_BUILD=1 SKIP_PKG_SIGNING=1 \
SQUIRRELOPS_SWIFT_SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
SQUIRRELOPS_GUEST_BUNDLE=/path/to/verified/arm64/guest \
bash scripts/build-pkg.sh
```

Private local evidence: `build/sensor-tests.log`, `build/pyright.log`,
`build/local-package.log`, `build/artifact-verification.json`, and the extracted
payload under `build/pkg-inspection-complete/`. No generated binaries, private
logs or source archives belong in the Git commit.

## Remaining release gates

1. Independent review of this packaging change and its complete source lock.
2. Merge, green post-merge CI, and newly approved signed sensor/Home 2.1.1 tags.
   Existing 2.1.0 tags and the immutable APK input release remain unchanged.
3. Protected signed/notarized Home build, exact artifact checks, and final
   approval for immutable publication. Linux publication remains blocked.
4. Verify the published assets and documentation against the release metadata.
   Website and Homebrew publication remain separate actions.
