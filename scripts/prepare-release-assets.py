#!/usr/bin/env python3
"""Prepare immutable, checksummed release assets from reviewed inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tomllib
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HOMEBREW_CASK_NAME = "squirrelops-home.rb"
RELEASE_VERIFICATION_NAME = "RELEASE-VERIFICATION.md"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def render_homebrew_cask(
    *,
    version: str,
    package_sha256: str,
    repository: str,
) -> str:
    """Render the exact cask candidate promoted through a separately reviewed PR."""
    return f'''cask "squirrelops-home" do
  version "{version}"
  sha256 "{package_sha256}"

  url "https://github.com/{repository}/releases/download/home-v#{{version}}/SquirrelOpsHome-#{{version}}.pkg",
      verified: "github.com/{repository}/"
  name "SquirrelOps Home"
  desc "Local-first home network security sensor and desktop dashboard"
  homepage "https://www.squirrelops.io/"

  depends_on arch: :arm64
  depends_on macos: :sonoma

  pkg "SquirrelOpsHome-#{{version}}.pkg"

  uninstall script:  {{
              executable: "/Library/SquirrelOps/sensor/uninstall.sh",
              args:       ["--preserve-data"],
              sudo:       true,
            }},
            pkgutil: [
              "com.squirrelops.home.app",
              "com.squirrelops.home.sensor",
            ]
end
'''


def render_release_verification(
    *,
    distribution_version: str,
    app_version: str,
    sensor_version: str,
    sensor_api_protocol: int,
    repository: str,
    commit: str,
    package_name: str,
    notes: str,
) -> str:
    """Render the canonical, attested notes and verification instructions."""
    tag = f"home-v{distribution_version}"
    workflow = f"{repository}/.github/workflows/release.yml"
    return f"""# SquirrelOps Home {distribution_version}

This is the canonical release-notes and verification document for `{tag}`. It
is included in `SHA256SUMS`, attested by the release workflow, and locked as an
immutable release asset. GitHub's release title and description are editable
convenience pointers and are not authoritative.

Release commit: `{commit}`

Included components:

- macOS app: `{app_version}`
- sensor: `{sensor_version}`
- sensor API protocol: `{sensor_api_protocol}`

Verify this document before following the instructions below:

```bash
gh release verify {tag} --repo {repository}
gh attestation verify {RELEASE_VERIFICATION_NAME} \\
  --repo {repository} \\
  --signer-workflow {workflow} \\
  --signer-digest {commit} \\
  --source-digest {commit} \\
  --source-ref refs/heads/main
```

{notes.rstrip()}

## Install and verify

### macOS

Download `{package_name}` and `{package_name}.sha256`, then verify before
opening the package:

```bash
gh attestation verify {package_name} \\
  --repo {repository} \\
  --signer-workflow {workflow} \\
  --signer-digest {commit} \\
  --source-digest {commit} \\
  --source-ref refs/heads/main
shasum -a 256 -c {package_name}.sha256
pkgutil --check-signature {package_name}
spctl --assess --type install --verbose=2 {package_name}
```

Gatekeeper validates the Developer ID signature, notarization ticket, and
stapled ticket. Linux sensor releases are published independently under
`sensor-v*` tags and are not part of this Home distribution release.

### Homebrew candidate

`squirrelops-home.rb` is a checksummed and attested cask candidate. It is not
published automatically. Install it only after it lands through a separately
reviewed Homebrew tap or `homebrew-cask` pull request.

### What this proves

The checksum detects changed bytes. The attestations bind the artifacts to the
repository, protected source ref, reviewed commit, and release workflow. They
do not prove that the reviewed source is vulnerability-free.
"""


def main() -> None:
    args = parse_args()
    distribution_version = (
        REPOSITORY_ROOT / "VERSION"
    ).read_text(encoding="utf-8").strip()
    app_version = (
        REPOSITORY_ROOT / "APP_VERSION"
    ).read_text(encoding="utf-8").strip()
    pyproject = tomllib.loads(
        (REPOSITORY_ROOT / "sensor/pyproject.toml").read_text(encoding="utf-8")
    )
    sensor_version = pyproject["project"]["version"]
    compatibility_text = (
        REPOSITORY_ROOT
        / "sensor/src/squirrelops_home_sensor/compatibility.py"
    ).read_text(encoding="utf-8")
    protocol_match = re.search(
        r"^SENSOR_API_PROTOCOL_VERSION = ([0-9]+)$",
        compatibility_text,
        re.MULTILINE,
    )

    require(
        re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", distribution_version) is not None,
        "VERSION must contain a semantic version.",
    )
    require(
        re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", app_version) is not None,
        "APP_VERSION must contain a semantic version.",
    )
    require(
        isinstance(sensor_version, str)
        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", sensor_version) is not None,
        "sensor/pyproject.toml must contain a semantic version.",
    )
    require(protocol_match is not None, "Sensor API protocol version is missing.")
    sensor_api_protocol = int(protocol_match.group(1))
    require(
        args.tag == f"home-v{distribution_version}",
        f"Tag {args.tag!r} does not match home-v{distribution_version}.",
    )
    require(
        re.fullmatch(r"[0-9a-f]{40}", args.commit) is not None,
        "Release commit must be a full lowercase SHA-1.",
    )
    require(
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository)
        is not None,
        "Repository must use the owner/name form.",
    )
    require(args.package.is_file(), f"Package does not exist: {args.package}")

    expected_package_name = f"SquirrelOpsHome-{distribution_version}.pkg"
    require(
        args.package.name == expected_package_name,
        f"Expected package name {expected_package_name}, got {args.package.name}.",
    )

    release_notes_source = (
        REPOSITORY_ROOT / "docs/releases" / f"{distribution_version}.md"
    )
    require(
        release_notes_source.is_file(),
        f"Release notes do not exist: {release_notes_source}",
    )
    output = args.output
    if output.exists():
        require(output.is_dir(), f"Output path is not a directory: {output}")
        require(not any(output.iterdir()), f"Output directory is not empty: {output}")
    else:
        output.mkdir(parents=True)

    package_output = output / expected_package_name
    cask_output = output / HOMEBREW_CASK_NAME
    metadata_output = output / "release-metadata.json"
    verification_output = output / RELEASE_VERIFICATION_NAME

    shutil.copyfile(args.package, package_output)

    package_sha256 = sha256(package_output)
    release_base = (
        f"https://github.com/{args.repository}/releases/download/{args.tag}"
    )
    package_url = f"{release_base}/{expected_package_name}"
    cask_output.write_text(
        render_homebrew_cask(
            version=distribution_version,
            package_sha256=package_sha256,
            repository=args.repository,
        ),
        encoding="utf-8",
    )
    cask_sha256 = sha256(cask_output)
    verification_output.write_text(
        render_release_verification(
            distribution_version=distribution_version,
            app_version=app_version,
            sensor_version=sensor_version,
            sensor_api_protocol=sensor_api_protocol,
            repository=args.repository,
            commit=args.commit,
            package_name=expected_package_name,
            notes=release_notes_source.read_text(encoding="utf-8"),
        ),
        encoding="utf-8",
    )
    verification_sha256 = sha256(verification_output)
    metadata = {
        "schema_version": 2,
        "release": {
            "repository": args.repository,
            "tag": args.tag,
            "distribution_version": distribution_version,
            "commit": args.commit,
            "url": f"https://github.com/{args.repository}/releases/tag/{args.tag}",
            "verification_artifact": RELEASE_VERIFICATION_NAME,
            "verification_sha256": verification_sha256,
            "verification_url": f"{release_base}/{RELEASE_VERIFICATION_NAME}",
        },
        "macos": {
            "artifact": expected_package_name,
            "url": package_url,
            "sha256": package_sha256,
            "app_version": app_version,
            "sensor_version": sensor_version,
            "sensor_api_protocol": sensor_api_protocol,
        },
        "homebrew": {
            "cask_artifact": HOMEBREW_CASK_NAME,
            "cask_sha256": cask_sha256,
            "cask_url": f"{release_base}/{HOMEBREW_CASK_NAME}",
            "version": distribution_version,
            "url": package_url,
            "sha256": package_sha256,
        },
    }
    metadata_output.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    subjects = [
        package_output,
        cask_output,
        verification_output,
        metadata_output,
    ]
    checksums = "".join(f"{sha256(path)}  {path.name}\n" for path in subjects)
    (output / "SHA256SUMS").write_text(checksums, encoding="utf-8")
    (output / f"{expected_package_name}.sha256").write_text(
        f"{package_sha256}  {expected_package_name}\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
