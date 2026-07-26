# Release security

The release workflow is intentionally blocked until the repository trust
controls below are configured. The workflow does not create tags, bump
versions, publish from a branch, update `main`, update the website, or update a
Homebrew tap.

Do not prepare or dispatch Home 2.0.0 or Sensor 2.0.0 until the applicable
security review and remote controls are complete.

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

`.github/release-policy.json` keeps `linux_release.mode` set to `blocked`, and
the remote-control checker enforces that sentinel before any release build.
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

## Required GitHub settings

Configure these settings before the next release:

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
pinned in policy. The remaining checked-in zero/null sentinels intentionally
block releases until the repository controls are reviewed and recorded. A
reviewer substitution or any pinned control change blocks publication.

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

## Release procedure

After the release changes pass review and CI:

```bash
git fetch origin
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
git tag -s vX.Y.Z -m "SquirrelOps Home X.Y.Z"
git verify-tag vX.Y.Z
git push origin vX.Y.Z
```

Only the dedicated tag-ruleset bypass identity creates this signed tag. The
separate environment reviewer approves the workflow after confirming GitHub
shows the tag signature as verified.

Do not rerun a failed release workflow. GitHub retains approvals on a rerun,
so the workflow requires `run_attempt == 1`. Preserve and inspect the failed
draft, remove only that draft after independent review, and start a fresh
manual dispatch.

Release the independently versioned sensor first with the `Release Sensor`
workflow and a protected `sensor-vX.Y.Z` tag. Create a protected
`app-vX.Y.Z` tag for the exact app component source. Release the signed macOS
distribution with `Release Home Distribution` and a protected
`home-vX.Y.Z` tag. Enter the full 40-character commit SHA. The workflows
verify that:

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
- the multi-platform container is built into a private OCI archive with no
  public staging tag;
- the Linux installer is rendered with the attested multi-platform container
  digest;
- the package, installer, generated `squirrelops-home.rb`, checksums, and
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
- immediately before publication, that archive is copied directly to the final
  semver GHCR tag and its digest, amd64/arm64 manifests, and provenance are
  verified;
- the draft bytes and remote controls are then rechecked, and publication is
  accepted only after bounded checks confirm the exact tag, target commit,
  asset set, asset digests, `isDraft=false`, `isImmutable=true`, and a valid
  `gh release verify`.

The workflow never publishes `latest`, major/minor, or mutable version container
tags. The installer and metadata use the attested image digest directly. The
workflow also refuses to overwrite an existing release or versioned container
tag. The OCI archive remains a private Actions artifact through the build and
draft phases. There is no public `release-build-*` staging reference. The final
semver image exists only in the last bounded interval before GitHub publication,
so the immutable release is never sealed before its digest-pinned dependency is
available.

## Independent verification

Download `RELEASE-VERIFICATION.md` first. Treat that attested asset as the
canonical notes and command source; GitHub's release title and description can
still be edited after publication. Then download the package, `install.sh`,
and their two matching `.sha256` files from the pinned release and verify both
provenance and bytes:

```bash
RELEASE_COMMIT="$(git rev-parse 'vX.Y.Z^{commit}')"
gh release verify vX.Y.Z --repo rocketweb/squirrelops-home
gh attestation verify RELEASE-VERIFICATION.md \
  --repo rocketweb/squirrelops-home \
  --signer-workflow rocketweb/squirrelops-home/.github/workflows/release.yml \
  --signer-digest "$RELEASE_COMMIT" \
  --source-digest "$RELEASE_COMMIT" \
  --source-ref refs/heads/main
gh attestation verify SquirrelOpsHome-X.Y.Z.pkg \
  --repo rocketweb/squirrelops-home \
  --signer-workflow rocketweb/squirrelops-home/.github/workflows/release.yml \
  --signer-digest "$RELEASE_COMMIT" \
  --source-digest "$RELEASE_COMMIT" \
  --source-ref refs/heads/main
gh attestation verify install.sh \
  --repo rocketweb/squirrelops-home \
  --signer-workflow rocketweb/squirrelops-home/.github/workflows/release.yml \
  --signer-digest "$RELEASE_COMMIT" \
  --source-digest "$RELEASE_COMMIT" \
  --source-ref refs/heads/main
gh attestation verify squirrelops-home.rb \
  --repo rocketweb/squirrelops-home \
  --signer-workflow rocketweb/squirrelops-home/.github/workflows/release.yml \
  --signer-digest "$RELEASE_COMMIT" \
  --source-digest "$RELEASE_COMMIT" \
  --source-ref refs/heads/main
gh attestation verify release-metadata.json \
  --repo rocketweb/squirrelops-home \
  --signer-workflow rocketweb/squirrelops-home/.github/workflows/release.yml \
  --signer-digest "$RELEASE_COMMIT" \
  --source-digest "$RELEASE_COMMIT" \
  --source-ref refs/heads/main
shasum -a 256 -c SquirrelOpsHome-X.Y.Z.pkg.sha256
shasum -a 256 -c install.sh.sha256
gh attestation verify \
  oci://ghcr.io/rocketweb/squirrelops-sensor@sha256:RELEASE_DIGEST \
  --repo rocketweb/squirrelops-home \
  --signer-workflow rocketweb/squirrelops-home/.github/workflows/release.yml \
  --signer-digest "$RELEASE_COMMIT" \
  --source-digest "$RELEASE_COMMIT" \
  --source-ref refs/heads/main
```

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
SHA-256, cask SHA-256, and container digest. The cask contains the same
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

If image promotion or verification fails while GitHub still authoritatively
reports a draft, the workflow re-resolves the final semver tag and deletes it
only when it still equals this run's expected digest. It preserves the draft
for forensic review. If GitHub state is ambiguous or published, or if the
container tag is absent or changed, the workflow refuses deletion. Review that
state manually; never delete a protected tag or recreate an immutable release.
