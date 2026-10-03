# Studio Mini guest

This directory builds the architecture-specific, memory-only guest used by the
2.1 deep decoy. The guest contains real OpenSSH and Samba services and relays
only those services over Virtio sockets. It has no virtual NIC, persistent
disk, host directory share, clipboard, or outbound path.

Home 2.1 supports Apple Silicon (ARM64) Macs only. Intel Macs are not supported.

```bash
bash guest/studio-mini/build-guest.sh arm64
```

The output is written to `guest/studio-mini/build/<architecture>/`. Build
outputs are ignored by Git. The default `ALPINE_IMAGE` is pinned by digest and
must match `package-inputs.lock.json`. Release automation builds separate bundles for `arm64` and
`x86_64`. This provides guest build coverage, not Intel Mac release support.
The supported macOS package embeds the ARM64 guest. An x86_64 guest build does
not establish Intel host runtime or installer compatibility.

## Retained package inputs

The normal build never resolves packages from the live Alpine repositories.
`package-inputs.lock.json` records an architecture-specific archive and every
retained APK's name, size, and SHA-256. The preparer verifies those records and
rejects missing packages, extra files, links, path traversal, and duplicates.
Inside the pinned Alpine image, the build verifies Alpine package signatures,
installs with networking disabled, and compares the full installed inventory
to `packages.lock`. `packages.world` preserves the original top-level package
requests. Temporary APK inputs are not included in the guest filesystem.

Archive downloads use the reviewed HTTPS URL. For an unpublished candidate or
offline local test, pass an already retained archive explicitly:

```bash
SQUIRRELOPS_GUEST_PACKAGE_ARCHIVE=/absolute/path/studio-mini-packages-arm64.tar \
  bash guest/studio-mini/build-guest.sh arm64
```

The same size, digest, and content checks apply to that override. A missing
archive or a null publication URL stops the build; there is no live-repository
fallback. Docker may still need network access to obtain the pinned base image.
Both build stages run without networking and without cached RUN layers.
This fixes the package inputs, not byte-for-byte reproducibility of the entire
initramfs, which still contains generated timestamps.

The 2.1.1 candidate uses the published, immutable
[guest-inputs-20261003-v1 prerelease](https://github.com/rocketweb/squirrelops-home/releases/tag/guest-inputs-20261003-v1).
Its signed tag binds the checksum manifest for both APK archives, the lock,
source inventory, notices, and corresponding source companion. The lock points
directly to the two architecture-specific downloads; binary archives are not
tracked in Git. This is a build-input publication, not a Home installer release
or a Linux sensor release. The source companion covers the retained APKs only,
not the base image or the complete Home installer. See the
[publication evidence](../../docs/testing/2026-10-03-guest-input-publication.md).

## Refreshing a package snapshot

Only the maintainer capture path contacts live Alpine package repositories:

```bash
python3 scripts/capture-guest-package-inputs.py \
  --base-image alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b \
  --output build/new-guest-package-candidate
```

Use a new output directory. Capture produces both APK archives, candidate locks,
and raw inventory evidence without replacing the reviewed files or publishing
anything. Both architecture inventories and top-level requests must agree.
Review every package change, including attacker-visible effects, then rebuild
both guests offline and run ARM64 SSH/SMB/isolation acceptance. A changed kernel
is not covered by an older artifact's runtime results. Retain the exact archives
at an approved immutable destination, verify the downloaded bytes, and put those
URLs in the reviewed lock before requesting merge or release approval.

The required CI build also runs real offline APK installation checks: a valid
inventory succeeds, a changed inventory fails, and an empty trusted-key set
rejects the retained signed packages. To repeat locally with Docker available:

```bash
cd sensor
SQUIRRELOPS_TEST_GUEST_PACKAGE_ARCHIVE=/absolute/path/studio-mini-packages-arm64.tar \
  uv run pytest tests/integration/test_guest_package_install.py -q
```

Without an archive override, `SQUIRRELOPS_TEST_GUEST_PACKAGE_INSTALL=1` opts in
to downloading the archive from the reviewed URL. Both paths perform the same
verification before creating containers. All container mounts are read-only;
no installed sensor, host networking configuration, or host package is changed.

## Guest identity and containment

The sensor creates one install-specific persona archive in memory. The signed
runtime streams it into the guest through a one-time Virtio socket before SSH
or SMB becomes reachable. Fake credentials do not need to be written to the
host filesystem.

Guest hostname and resolver files come from `network/`, not the Docker build
container. The builder copies the root filesystem into a separate staging
directory before replacing those three files, so BuildKit's injected `/etc`
files cannot override them. `studio-mini` and `studio-mini.local` resolve to
loopback; DNS is loopback-only and does not add a guest network device.

The bundle verifier streams the gzip/newc archive without extracting it. It
requires the reviewed hostname, hosts and resolver contents and rejects missing,
duplicate, linked or writable identity files, malformed archives and unexpected
trailing data. Both the guest builder and app packaging run this check.
