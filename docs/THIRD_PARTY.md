# Third-party software in the macOS installer

SquirrelOps Home remains licensed under PolyForm Noncommercial 1.0.0. That
license does not replace the licenses of the third-party components distributed
alongside it. Their original license, copyright and notice texts are retained.

The installer places `LICENSE`, `THIRD-PARTY-NOTICES.txt` and
`THIRD-PARTY-INVENTORY.json` in `/Library/SquirrelOps/sensor/third-party/`.
Python wheels also retain their original `.dist-info` license directories.
The Space Grotesk and Space Mono fonts retain their embedded copyright,
SIL Open Font License notice and license URL.

## Source access

Download `THIRD-PARTY-SOURCES.tar` from the **same Home release as the installer**.
The release also provides the inventory and consolidated notice file separately.
All three are included in `SHA256SUMS` and the release workflow's attestations.
Verify them using `RELEASE-VERIFICATION.md` before extracting the archive.
No request, account registration or separate purchase is required to obtain
these public release assets. For an unpublished local-test build, use the
companion files next to the `.pkg` in `build/pkg/output/`.

The source archive contains:

- `alpine/studio-mini-package-sources.tar`: the retained source archives,
  exact Alpine recipes, patches, configurations and build scripts for the
  guest's added packages. Extract this nested archive to inspect
  `sources/<origin>-<commit>/recipe/` and `distfiles/`.
- `alpine-base/sources/`: the same inputs for inherited base packages, including
  BusyBox and APK tools. The `alpine-base` recipe generates release text directly
  and has no remote source archive. Both sets cover the full installed ARM64
  guest inventory, including the Linux kernel and Alpine's kernel configuration.
- `python-sources/`: exact source distributions for the installed third-party
  Python packages, including Zeroconf, plus the standalone runtime's bundled pip.
  Scapy is not included in the macOS runtime; Linux retains its dependency.
- `python-build/`: the exact standalone Python build's `PYTHON.json` and the
  license texts for CPython and its compiled extensions. The inventory records
  one stale upstream metadata reference: this macOS build links system libz,
  not zlib-ng, whose notice is absent from that archive. A missing notice for
  an actually bundled library is still rejected.
- `build-instructions/`: source locks, project terms and packaging instructions.

Build Alpine components in an Alpine `abuild` environment using the retained
APKBUILD recipes and checksum-listed inputs. These recipes are source, not
trusted commands to run on the host. Python source distributions retain their
upstream build instructions. SquirrelOps' guest and packaging build steps are
in `docs/DEVELOPMENT.md` at the release's source commit. The standalone Python
full-build URL and digest are retained in `third-party/sources.lock.json`.
No exact-byte rebuild of all upstream binaries is claimed.

Python's LGPL-licensed Zeroconf distribution is a separate, replaceable package
in `python/lib/python3.12/site-packages/`. Its exact source distribution and
license are retained. Rebuilding the installer with a modified dependency is
supported through the source build; changing installed signed binaries can
invalidate signatures and requires re-signing. Third-party license rights,
including applicable modification and reverse-engineering rights for debugging
those modifications, are not restricted by SquirrelOps' project terms.

## Maintainer verification

`scripts/prepare-third-party.py` compares the guest's installed APK database
with source origin, version, recipe commit and license metadata. It selects
Python source distributions by the staged wheel inventory and committed
`sensor/uv.lock`, not by an unbounded package-index resolution. It rejects
Scapy in a macOS payload, missing wheel notices, uncovered packages, changed
source hashes and a stale standalone Python pin.

All source downloads use reviewed sizes and SHA-256 hashes, including cache
hits. Alpine source retention also verifies recipe Git blobs and literal
SHA-512 source checksums without executing APKBUILD. Review updates to
`third-party/sources.lock.json` when changing the guest base or Python runtime.
Do not modify the existing immutable APK input release. The final Home source
companion includes that archive plus the base-image supplement.

This inventory is technical distribution evidence, not a legal opinion or an
automatic declaration that any combination of licenses is compatible.
