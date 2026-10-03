# Release security

The release workflow fails closed unless the repository trust controls below
remain configured exactly as reviewed. The workflow does not create tags, bump
versions, publish from a branch, update `main`, update the website, or update a
Homebrew tap.

Do not prepare or dispatch a Home or Sensor release until the applicable
security review and remote controls are complete.

Home 2.1 is a **macOS-only distribution release**. It includes the native
sensor inside the Apple Silicon installer. It does not publish a Linux
installer or container. Building the embedded decoy guest on Linux, or creating
a signed `sensor-v*` component tag, does not change that scope.

## Current Linux release block

Linux publication is explicitly blocked. The current tree gives the sensor a
fixed private bridge address, a fixed non-root identity, a read-only root
filesystem, `no-new-privileges`, and a drop-all capability set. Host networking
plus `NET_RAW` and `NET_ADMIN` now exist only in the `network-helper`
companion.

The helper exposes a bounded Unix-socket JSON RPC authenticated with Linux peer
credentials. It allows only ARP and multicast discovery, mDNS advertising,
owned virtual addresses, exact sensor-bound listener publication, and
SquirrelOps-owned packet-filter state. It rejects out-of-subnet addresses,
caller-selected forwarding destinations, arbitrary commands, oversized
requests, and aliases it does not own. The sensor mounts the socket volume
read-only and cannot access the Docker socket.

`.github/release-policy.json` keeps `linux_release.mode` set to `blocked`. The
`Release Sensor` workflow invokes the Linux boundary checker before publishing
Linux artifacts. The separate Home workflow does not publish Linux artifacts
or invoke that checker; it still requires the protected component tags and all
remote release controls. A component-only sensor tag is not Linux publication.
The implementation is present but has not yet received the required independent
boundary review. Do not change the policy merely to make the workflow pass.
Unblocking requires one of these independently reviewed decisions:

- review the constrained companion implementation, verify it on a real Linux
  LAN, and set `constrained-sidecar-reviewed` with the review timestamp; or
- deliberately make the release macOS-only, remove every Linux image,
  installer, OCI, and GHCR publication path from the release workflow, and set
  `macos-only-reviewed` with the review timestamp.

The boundary checker verifies the corresponding repository shape, including
the sensor's non-root/drop-all/read-only controls and the helper's exact
capability and entry-point controls. An unknown mode, missing timestamp, direct
sensor privilege, incomplete helper boundary, or lingering Linux publication
path fails closed.

## macOS release support

The macOS app and native sensor support Apple Silicon (ARM64) on macOS 14
(Sonoma) or later. Intel Macs are not supported. Home 2.1 has no supported
Intel or universal macOS installer.

Validate the final macOS installer, app, native runtime, and embedded guest as
ARM64. Installed upgrade, restart, LAN/PF, containment, and signed/notarized
artifact acceptance apply to this supported architecture. Intel execution is
not a Home 2.1 release gate. Source builders retain x86_64 options and the
workflow builds both guest architectures for build coverage; neither establishes
Intel Mac support. Linux architecture support and its publication block are
separate.

## Required GitHub settings

Keep these settings in place for every release:

The Home 2.1 package also has an indivisible guest-artifact boundary. Release
automation builds ARM64 and x86_64 Studio Mini guests from the reviewed Alpine
image digest. `guest/studio-mini/package-inputs.lock.json` additionally pins
retained APK archives and each package's size and SHA-256. Archive validation
rejects unlisted files, unsafe paths, links, duplicates, and missing inputs.
Alpine's own signature verification remains required inside the pinned image.
Package installation runs offline, then checks the complete installed inventory
against `guest/studio-mini/packages.lock`. No live-repository fallback is allowed.
Both clean guest builds are prerequisites of the required Supply Chain CI check.
The macOS job downloads the freshly built
private artifact, selects the exact package architecture, and rejects any
unexpected file, symlink, writable file, digest mismatch, architecture
mismatch, changed resource ceiling, changed containment declaration, or changed
socket/service map. The build-time verifier also streams the initramfs and
requires reviewed hostname, hosts and resolver files; matching hashes do not
authorize Docker builder DNS or hostname leakage. No external DNS access or
guest network device is added. The guest runtime is signed separately with only the
virtualization entitlement before the outer app signature is applied. Do not
substitute a locally cached guest, floating container tag, or pre-existing
release asset.

The failed Home 2.1.0 build showed why an inventory lock alone is insufficient:
the pinned base image still resolved newer dependencies from a live repository.
Its mismatch check correctly stopped publication. Home 2.1.1 adds retained
package bytes rather than bypassing that check. Existing 2.1.0 tags remain
unchanged. App and sensor versions remain 2.1.0 because their source is unchanged.

Package refresh is a separate maintainer action, never part of a normal release
build. Review inventory changes and deception behavior, run both offline builds
and current ARM64 guest acceptance, then approve archive retention/publication.
The 2.1.1 candidate now uses the approved, immutable
[guest-inputs-20261003-v1 prerelease](https://github.com/rocketweb/squirrelops-home/releases/tag/guest-inputs-20261003-v1).
The signed archive-only tag points to source baseline
`300569ba15c375a77201cccfe7c27dc2d0da888e` and binds the asset checksum manifest;
it is not a tag of the new build integration. GitHub release attestation and
freshly downloaded asset checksums were verified. No Actions capture provenance
is claimed for these locally retained inputs. Normal CI and release builds must
use the reviewed public URLs and verify the locked bytes. Local archive overrides
are useful for review, not evidence of public availability.

The source companion and notices cover the retained APKs. Complete base-image
and Home installer third-party source/notice coverage still needs review before
Home publication; this archive release does not close that broader gate. It does
not change the latest Home installer or authorize a Linux sensor publication.
See the [guest input report](testing/2026-10-03-reproducible-guest-build.md) and
[archive publication evidence](testing/2026-10-03-guest-input-publication.md).

1. Enable **release immutability**. The workflow checks the repository setting
   before building and again immediately before publication. A published
   immutable release locks its tag and assets and receives a GitHub release
   attestation. Existing releases are not made immutable retroactively.
2. Protect `main` with a ruleset that requires pull requests, required status
   checks, at least one independent approval, dismissal of stale approvals, and
   approval of the last push, plus resolution of review threads. Restrict
   deletion and block force pushes. Do not enable **restrict updates** on
   `main`: that rule permits only bypass actors to push and would also block
   compliant pull-request merges when the bypass list is empty. Do not
   configure any bypass actor, including administrators, roles, users, teams,
   integrations, or deploy keys. Include the exact check-run name
   `Verify release and package controls` as a strict required check and pin
   that check to the exact GitHub Actions App integration ID. Do not use the
   GitHub UI's composite workflow/job label as the context. A context-only
   required check is rejected because another writer could report the same
   context.
3. Add one active tag ruleset for legacy `v*` tags and the current `home-v*`,
   `app-v*`, and `sensor-v*` component tags. Enable **restrict creations**,
   **restrict updates**, and **restrict deletions** with no exclusions. Limit
   bypass to exactly one dedicated release-signer **User** with
   `bypass_mode=always`. Require hardware-backed authentication for that
   account. Team, `OrganizationAdmin`, `RepositoryRole`, integration,
   deploy-key, additional, and pull-request-only bypass actors are rejected.
   The workflow requires a GitHub-verified signed annotated tag.
4. Create a `release` environment. Add exactly one dedicated independent
   required reviewer, a release-reviewer **User**. Enable
   **prevent self-review**, disallow
   administrator bypass, and restrict deployments to protected `main`. This
   User must differ from the tag-bypass User. Move all Apple signing and
   notarization secrets into this environment. Store the Developer ID
   Application and Developer ID Installer identities as separate modern
   AES-256/PBKDF2 PKCS#12 bundles in
   `APPLE_APPLICATION_CERTIFICATE_P12` and
   `APPLE_INSTALLER_CERTIFICATE_P12`, with their shared export password in
   `APPLE_CERTIFICATE_PASSWORD`. Do not retain or upload the legacy combined
   RC2 bundle. Store notarization credentials as `APPLE_ID`, `APPLE_TEAM_ID`,
   and `APPLE_APP_PASSWORD`.
5. Require hardware-backed passkeys or security keys for maintainers. Remove
   classic and broad personal access tokens. Prefer the short-lived
   `GITHUB_TOKEN`, OIDC, or narrowly scoped fine-grained credentials.
6. Restrict Actions to reviewed actions pinned by full commit SHA. Require
   review for changes under `.github/workflows/`, release scripts, package
   scripts, `VERSION`, `APP_VERSION`, and the dependency lockfile. Keep the supply-chain
   check required so its pull-request dependency review blocks newly
   introduced moderate-or-higher vulnerabilities, and keep Dependabot enabled
   for GitHub Actions, container bases, and the `uv` lock.

Only the pinned tag-bypass User can dispatch a release. The workflow queries
its own run record and the environment review history, then requires at least
one `approved` decision for the pinned environment ID and name. Every matching
decision must come from the distinct pinned reviewer User and must be
`approved`; an approval from a different User or any rejected matching entry
fails closed. It also rejects self approval, administrator bypass, ambiguous
review history, reruns, and any actor or triggering-actor mismatch.

GitHub hides ruleset bypass actors unless the caller can write the ruleset.
Create a dedicated GitHub App installed only on this repository with
`Administration: read`, `Actions: read`, and `Contents: read`. The App
installation itself must not have Administration write permission. Store its
client ID and private key as `RELEASE_POLICY_APP_CLIENT_ID` and
`RELEASE_POLICY_APP_PRIVATE_KEY` in the protected `release` environment. The
workflow mints a repository-scoped installation token only after approval,
passes it only to the read-only policy checker, and revokes it at job end. Do
not substitute a PAT or reuse this App for general automation. Administration
write is forbidden: release-commit code must never be able to mutate the
controls it is verifying.

Review the complete ruleset with an administrator, then record its numeric
`id`, server-controlled `updated_at`, and the dedicated User's numeric actor ID
as `tag_bypass_user_id` in `.github/release-policy.json` through a reviewed pull
request. Also pin the main ruleset's `id` and `updated_at`, plus the distinct
release environment's server-controlled `updated_at` and the
environment ID, name, and release-reviewer User actor ID. Record the
non-null GitHub Actions App source ID for the required supply-chain check as
`main_ruleset.required_check_integration_id`. The live repository check source
is the GitHub-owned GitHub Actions App, integration ID `15368`; that exact ID is
pinned in policy. The current policy records nonzero control IDs and reviewed
timestamps. Those checked-in pins are not evidence that the remote controls
still match; the checker must verify them for each release. The separate Linux
review timestamp remains null while Linux publication is blocked. A reviewer
substitution or any pinned control change blocks publication.

The read-only App cannot see `bypass_actors`. That is deliberate. An
administrator independently reviews the exact bypass list, then pins the
ruleset's server-controlled `updated_at` and expected dedicated User ID through
the protected pull-request path. The release checker requires the same
ruleset ID and exact `updated_at`; any bypass change necessarily changes that
timestamp and blocks publication without giving release code write authority.

The environment endpoint requires the `Actions: read` permission. Every job
that checks it explicitly grants only `actions: read`; an API error, a missing
field, or a permission regression stops the release. Do not add a broad PAT or
an unauthenticated fallback. Fix the repository setting or token permission
instead.

## Home release procedure

After the release changes pass review, CI and the applicable live security
acceptance gates:

```bash
git fetch origin
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
DISTRIBUTION_VERSION="$(tr -d '[:space:]' < VERSION)"
APP_VERSION="$(tr -d '[:space:]' < APP_VERSION)"
SENSOR_VERSION="$(
  awk -F'"' '/^version = / { print $2; exit }' sensor/pyproject.toml
)"
git tag -s "app-v${APP_VERSION}" \
  -m "SquirrelOps Home App ${APP_VERSION}"
git tag -s "sensor-v${SENSOR_VERSION}" \
  -m "SquirrelOps Home Sensor ${SENSOR_VERSION}"
git tag -s "home-v${DISTRIBUTION_VERSION}" \
  -m "SquirrelOps Home ${DISTRIBUTION_VERSION}"
git verify-tag "app-v${APP_VERSION}"
git verify-tag "sensor-v${SENSOR_VERSION}"
git verify-tag "home-v${DISTRIBUTION_VERSION}"
git push --atomic origin \
  "app-v${APP_VERSION}" \
  "sensor-v${SENSOR_VERSION}" \
  "home-v${DISTRIBUTION_VERSION}"
```

Only the dedicated tag-ruleset bypass identity creates these signed tags. The
separate environment reviewer approves the workflow after confirming GitHub
shows every required tag signature as verified.

Do not rerun a failed release workflow. GitHub retains approvals on a rerun,
so the workflow requires `run_attempt == 1`. Preserve and inspect the failed
draft, remove only that draft after independent review, and start a fresh
manual dispatch.

Create protected, signed `app-vX.Y.Z` and `sensor-vX.Y.Z` component tags for
the exact embedded sources. When Linux publication is approved, release the
independently versioned sensor with the `Release Sensor` workflow. While Linux
publication remains blocked, do not dispatch that workflow; the signed sensor
tag is component identity only. Release the signed macOS distribution with
`Release Home Distribution` and a protected `home-vX.Y.Z` tag. Enter the full
40-character commit SHA. The Home workflow verifies that:

- the dispatched workflow, protected `main`, typed commit, and tag all resolve
  to the same commit;
- the distribution `VERSION`, `APP_VERSION`, sensor Python project, Linux
  installer, and release notes are internally consistent without forcing the
  component versions to match;
- a Home package embeds app and sensor source identical to the existing
  protected `app-vX.Y.Z` and `sensor-vX.Y.Z` component tags;
- release immutability and active rules for `home-v*`, `app-v*`, and
  `sensor-v*` tags are enabled;
- the release environment has the pinned identity and configuration, prevents
  self-review, disallows administrator bypass, and deploys only from protected
  branches;
- the fresh workflow run was dispatched by the pinned tag-bypass User and has
  at least one matching approval, with every matching decision approved by the
  distinct pinned reviewer User;
- the tag ruleset ID and server-controlled update time still match the
  independently reviewed policy pin, and the dispatcher is the separately
  pinned tag-bypass User;
- every build checks out the verified commit SHA;
- signing and notarization credentials are available only after environment
  approval;
- both architecture-specific deep-decoy guests are rebuilt from the pinned
  image digest and complete package inventory for build coverage, and the
  supported ARM64 macOS package contains the validated ARM64 guest;
- the macOS package, generated `squirrelops-home.rb`, checksums, and
  `release-metadata.json` are attested;
- canonical release notes and verification commands are rendered into
  `RELEASE-VERIFICATION.md`, included in `SHA256SUMS`, and attested with the
  other immutable assets; GitHub's editable release title and description are
  only convenience pointers to that file;
- all assets are uploaded to a draft and their GitHub-computed digests match
  immediately before the release is published;
- every draft and immutable-state check resolves the annotated tag through the
  Git ref and tag-object APIs to the exact reviewed commit; GitHub Release
  `targetCommitish` is treated only as metadata because it is non-authoritative
  when the tag already exists;
- the draft bytes and remote controls are then rechecked, and publication is
  accepted only after bounded checks confirm the exact tag, target commit,
  asset set, asset digests, `isDraft=false`, `isImmutable=true`, and a valid
  `gh release verify`.

The Home workflow has separate protected approvals for input verification,
package building, and publication. Keep the publish job awaiting approval until
required acceptance of the exact signed and notarized package is recorded.
The private `macos-pkg` Actions artifact is retained for one day. A local ad-hoc
installer is not a substitute. Home publication does not upload an OCI archive,
publish a GHCR tag, or promote a Linux installer.

## Separate Sensor release procedure (blocked)

Do not dispatch `.github/workflows/release-sensor.yml` for Home 2.1. A Linux
release needs the independently reviewed boundary decision described above
and its own release authorization.

Once that block is resolved, the Sensor workflow uses a signed `sensor-vX.Y.Z`
tag, builds a private multi-platform OCI archive, renders `install.sh` with
the attested image digest, and produces `sensor-release-metadata.json` and
`SENSOR-RELEASE-VERIFICATION.md`. Its assets and image attestations identify
`.github/workflows/release-sensor.yml`, not the Home workflow.

Only that workflow promotes the exact OCI archive to the final semver GHCR
tag immediately before Sensor publication. It verifies the digest, amd64/arm64
manifests and provenance before sealing the immutable release. It never
publishes `latest`, major/minor or mutable version tags, and refuses to
overwrite an existing release or versioned container tag. There is no public
`release-build-*` staging reference.

## Post-release website manifest

Do not update `site/public/manifest.json` to a future version before its
immutable GitHub Release exists. The existing manifest must continue to point
at the latest release that users can actually download.

After a Home release succeeds, open a separate reviewed pull request based on
the attested `release-metadata.json`, `SHA256SUMS`, and published release:

1. Verify the immutable `home-vX.Y.Z` release and download its attested metadata
   and checksums.
2. Update the distribution and app versions, `home-vX.Y.Z` package and release
   URLs, and exact package SHA-256 in `site/public/manifest.json`.
3. Do not advertise a Linux image or sensor release that was not published.
   While Linux publication remains blocked, remove stale Linux download claims
   rather than changing them to the component-only `sensor-vX.Y.Z` tag.
4. Update the site's static fallback version and download URL to the same
   published Home release.
5. Require normal CI and independent pull-request approval, merge the manifest
   PR, and verify the deployed `/manifest.json` and package URL byte-for-byte.

The release workflow intentionally cannot push this update to protected
`main`. Website state therefore remains a separately reviewed post-release
publication action.

## Independent verification

Download `RELEASE-VERIFICATION.md` first. Treat that attested asset as the
canonical notes and command source; GitHub's release title and description can
still be edited after publication. These commands apply only to an immutable
Home release. Use the exact version and independently reviewed tag commit,
not a local test package. In a fresh directory, download all six Home assets
from that pinned release and verify provenance, bytes and the macOS signature
before opening the installer:

```bash
(
set -e
RELEASE_TAG=home-vX.Y.Z
RELEASE_COMMIT=REVIEWED_40_CHARACTER_COMMIT
test "${#RELEASE_COMMIT}" -eq 40
gh release verify "$RELEASE_TAG" --repo rocketweb/squirrelops-home
gh release download "$RELEASE_TAG" --repo rocketweb/squirrelops-home \
  --pattern RELEASE-VERIFICATION.md \
  --pattern SquirrelOpsHome-X.Y.Z.pkg \
  --pattern SquirrelOpsHome-X.Y.Z.pkg.sha256 \
  --pattern squirrelops-home.rb \
  --pattern release-metadata.json \
  --pattern SHA256SUMS
for ASSET in RELEASE-VERIFICATION.md SquirrelOpsHome-X.Y.Z.pkg \
  SquirrelOpsHome-X.Y.Z.pkg.sha256 squirrelops-home.rb \
  release-metadata.json SHA256SUMS; do
  gh attestation verify "$ASSET" \
    --repo rocketweb/squirrelops-home \
    --signer-workflow rocketweb/squirrelops-home/.github/workflows/release.yml \
    --signer-digest "$RELEASE_COMMIT" \
    --source-digest "$RELEASE_COMMIT" \
    --source-ref refs/heads/main || exit 1
done
shasum -a 256 -c SHA256SUMS
pkgutil --check-signature SquirrelOpsHome-X.Y.Z.pkg
spctl --assess --type install --verbose=2 SquirrelOpsHome-X.Y.Z.pkg
)
```

Home assets contain no Linux installer or container digest. For a separately
authorized, published Sensor release, use its attested
`SENSOR-RELEASE-VERIFICATION.md`, `sensor-release-metadata.json` and
`release-sensor.yml` provenance instead. A component-only sensor tag is not
a downloadable Linux release.

The checksum catches accidental corruption. The attestation binds the artifact
to this repository, workflow, and protected source ref. Neither proves that the
reviewed source is vulnerability-free.

The workflow checks GitHub's `verification.verified` result for the signed tag,
but that does not pin an out-of-band signer key fingerprint. A compromised
GitHub account may be able to register a different signing key. Offline
verification against a hardware-backed GPG or minisign key whose fingerprint
is pinned on independent channels remains the stronger additional trust
anchor.

## Website and Homebrew promotion

`release-metadata.json`, `RELEASE-VERIFICATION.md`, and the generated
`squirrelops-home.rb` are the only promotion handoff. The metadata contains
the exact release commit, package URL and SHA-256, verification-document
SHA-256 and cask SHA-256. It contains no container digest. The cask contains the same
versioned package URL and SHA-256.

After the immutable release is published:

1. Verify the release and `release-metadata.json`.
2. Open a pull request in `mattmacrocket/squirrelops.io` that copies the exact
   package SHA-256 to the `/macos` page.
3. Copy the exact attested `squirrelops-home.rb` into a separate, reviewed tap
   or `homebrew-cask` pull request. Confirm its version, URL, and `sha256`
   against `release-metadata.json`; do not publish it directly from the release
   workflow.
4. Require CI and human review in each repository before merge. Never let the
   release workflow push directly to either default branch.
5. Test a clean `brew install --cask` and uninstall before merging the tap pull
   request.

A second repository under the same compromised account is useful against an
accidental release mutation, but it is not a fully independent trust channel.
Use a separate organization, credential, or reviewer for the website and tap
if account-compromise resistance is the goal.

Run `ruby -c`, `brew style --cask`, and `brew audit --cask --new` in the target
tap. If upstream `homebrew-cask` reports an acceptance blocker such as its
notability threshold, publish through the reviewed tap instead of bypassing the
audit.

If a post-create step fails, the workflow deliberately preserves the draft,
uploaded assets, and logs as forensic evidence. After an independent review,
delete only that draft manually before retrying the same reviewed commit.
Never request tag cleanup and never reuse or overwrite draft assets in place.

In the separate Sensor workflow, if image promotion or verification fails while
GitHub still authoritatively
reports a draft, the workflow re-resolves the final semver tag and deletes it
only when it still equals this run's expected digest. It preserves the draft
for forensic review. If GitHub state is ambiguous or published, or if the
container tag is absent or changed, the workflow refuses deletion. Review that
state manually; never delete a protected tag or recreate an immutable release.
