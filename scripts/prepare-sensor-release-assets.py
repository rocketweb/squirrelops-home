#!/usr/bin/env python3
"""Prepare immutable Linux sensor release assets from reviewed inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import tarfile
import tomllib
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
IMAGE_DIGEST_PLACEHOLDER = "__RELEASE_IMAGE_DIGEST__"
VERIFICATION_NAME = "SENSOR-RELEASE-VERIFICATION.md"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oci-archive", type=Path, required=True)
    parser.add_argument("--docker-digest", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def validate_oci_archive(path: Path, expected_digest: str) -> None:
    digest_hex = expected_digest.removeprefix("sha256:")
    expected_blob = f"blobs/sha256/{digest_hex}"
    try:
        with tarfile.open(path, mode="r:*") as archive:
            members = {
                member.name.removeprefix("./"): member
                for member in archive
            }
            require("oci-layout" in members, "OCI archive is missing oci-layout.")
            require("index.json" in members, "OCI archive is missing index.json.")
            require(
                expected_blob in members,
                "OCI archive is missing the expected digest.",
            )
            layout_file = archive.extractfile(members["oci-layout"])
            index_file = archive.extractfile(members["index.json"])
            blob_file = archive.extractfile(members[expected_blob])
            require(layout_file is not None, "OCI layout metadata is unreadable.")
            require(index_file is not None, "OCI index is unreadable.")
            require(blob_file is not None, "OCI root descriptor is unreadable.")
            layout = json.load(layout_file)
            index = json.load(index_file)
            root_blob = blob_file.read()
    except (tarfile.TarError, json.JSONDecodeError, OSError) as error:
        raise SystemExit(f"OCI archive is invalid: {error}") from error

    require(
        layout == {"imageLayoutVersion": "1.0.0"},
        "OCI archive has an unsupported layout version.",
    )
    require(
        any(
            descriptor.get("digest") == expected_digest
            for descriptor in index.get("manifests", [])
        ),
        "OCI index does not reference the expected image digest.",
    )
    require(
        hashlib.sha256(root_blob).hexdigest() == digest_hex,
        "OCI root descriptor bytes do not match the expected digest.",
    )


def sensor_api_protocol() -> int:
    text = (
        REPOSITORY_ROOT
        / "sensor/src/squirrelops_home_sensor/compatibility.py"
    ).read_text(encoding="utf-8")
    match = re.search(
        r"^SENSOR_API_PROTOCOL_VERSION = ([0-9]+)$",
        text,
        re.MULTILINE,
    )
    require(match is not None, "Sensor API protocol version is missing.")
    return int(match.group(1))


def render_verification(
    *,
    version: str,
    repository: str,
    commit: str,
    digest: str,
) -> str:
    owner = repository.split("/", 1)[0]
    image = f"ghcr.io/{owner}/squirrelops-sensor"
    tag = f"sensor-v{version}"
    workflow = f"{repository}/.github/workflows/release-sensor.yml"
    return f"""# SquirrelOps Home Sensor {version}

This release contains the independently versioned Linux sensor. It does not
set the macOS app or Home distribution version.

Release commit: `{commit}`
Container: `{image}@{digest}`
Sensor API protocol: `{sensor_api_protocol()}`

```bash
gh release verify {tag} --repo {repository}
gh attestation verify {VERIFICATION_NAME} \\
  --repo {repository} \\
  --signer-workflow {workflow} \\
  --signer-digest {commit} \\
  --source-digest {commit} \\
  --source-ref refs/heads/main
gh attestation verify oci://{image}@{digest} \\
  --repo {repository} \\
  --signer-workflow {workflow} \\
  --signer-digest {commit} \\
  --source-digest {commit} \\
  --source-ref refs/heads/main
```

Download and attest `install.sh`, verify `install.sh.sha256`, review the
script, and only then run it as root.
"""


def main() -> None:
    args = parse_args()
    pyproject = tomllib.loads(
        (REPOSITORY_ROOT / "sensor/pyproject.toml").read_text(encoding="utf-8")
    )
    version = pyproject["project"]["version"]
    require(
        isinstance(version, str)
        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is not None,
        "sensor/pyproject.toml must contain a semantic version.",
    )
    require(
        args.tag == f"sensor-v{version}",
        f"Tag {args.tag!r} does not match sensor-v{version}.",
    )
    require(
        re.fullmatch(r"[0-9a-f]{40}", args.commit) is not None,
        "Release commit must be a full lowercase SHA-1.",
    )
    require(
        re.fullmatch(r"sha256:[0-9a-f]{64}", args.docker_digest) is not None,
        "Docker digest must be a full sha256 digest.",
    )
    require(
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository)
        is not None,
        "Repository must use the owner/name form.",
    )
    require(
        args.oci_archive.is_file(),
        f"OCI archive does not exist: {args.oci_archive}",
    )
    validate_oci_archive(args.oci_archive, args.docker_digest)

    install_source = REPOSITORY_ROOT / "scripts/install.sh"
    install_text = install_source.read_text(encoding="utf-8")
    require(
        install_text.count(IMAGE_DIGEST_PLACEHOLDER) == 1,
        "install.sh must contain exactly one release image digest placeholder.",
    )
    require(
        f'SQUIRRELOPS_SENSOR_VERSION="{version}"' in install_text,
        "install.sh sensor version does not match sensor/pyproject.toml.",
    )

    output = args.output
    if output.exists():
        require(output.is_dir(), f"Output path is not a directory: {output}")
        require(not any(output.iterdir()), f"Output directory is not empty: {output}")
    else:
        output.mkdir(parents=True)

    archive_name = f"squirrelops-sensor-{version}.oci.tar"
    archive_output = output / archive_name
    install_output = output / "install.sh"
    verification_output = output / VERIFICATION_NAME
    metadata_output = output / "sensor-release-metadata.json"

    archive_output.write_bytes(args.oci_archive.read_bytes())
    install_output.write_text(
        install_text.replace(IMAGE_DIGEST_PLACEHOLDER, args.docker_digest),
        encoding="utf-8",
    )
    install_output.chmod(
        install_output.stat().st_mode
        | stat.S_IXUSR
        | stat.S_IXGRP
        | stat.S_IXOTH
    )
    verification_output.write_text(
        render_verification(
            version=version,
            repository=args.repository,
            commit=args.commit,
            digest=args.docker_digest,
        ),
        encoding="utf-8",
    )

    owner = args.repository.split("/", 1)[0]
    image = f"ghcr.io/{owner}/squirrelops-sensor"
    metadata = {
        "schema_version": 1,
        "release": {
            "repository": args.repository,
            "tag": args.tag,
            "sensor_version": version,
            "commit": args.commit,
            "sensor_api_protocol": sensor_api_protocol(),
        },
        "container": {
            "image": image,
            "digest": args.docker_digest,
            "reference": f"{image}@{args.docker_digest}",
            "oci_artifact": archive_name,
            "oci_sha256": sha256(archive_output),
        },
        "installer": {
            "artifact": "install.sh",
            "sha256": sha256(install_output),
        },
    }
    metadata_output.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    subjects = [
        archive_output,
        install_output,
        verification_output,
        metadata_output,
    ]
    (output / "SHA256SUMS").write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in subjects),
        encoding="utf-8",
    )
    (output / "install.sh.sha256").write_text(
        f"{sha256(install_output)}  install.sh\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
