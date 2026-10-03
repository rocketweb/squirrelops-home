#!/usr/bin/env python3
"""Prepare review candidates, never overwrite the approved lock or publish inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path


def sha256(path):
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"alpine@sha256:[0-9a-f]{64}", args.base_image):
        parser.error("base image must be digest-pinned")
    args.output.mkdir(parents=True, exist_ok=False)
    guest = Path(__file__).resolve().parents[1] / "guest/studio-mini"
    lock = {"schema_version": 1, "base_image": args.base_image, "architectures": {}}
    inventories = []
    worlds = []
    for arch, platform, apk_arch in (
        ("arm64", "arm64", "aarch64"),
        ("x86_64", "amd64", "x86_64"),
    ):
        snapshot = args.output / arch
        subprocess.run(
            [
                "docker",
                "buildx",
                "build",
                "--no-cache",
                "--platform",
                f"linux/{platform}",
                "--build-arg",
                f"ALPINE_IMAGE={args.base_image}",
                "--file",
                str(guest / "Dockerfile.capture"),
                "--output",
                f"type=local,dest={snapshot}",
                str(guest),
            ],
            check=True,
        )
        inventories.append((snapshot / "packages.lock").read_bytes())
        worlds.append((snapshot / "packages.world").read_bytes())
        paths = sorted((snapshot / "packages").glob("*.apk"))
        if not paths:
            raise RuntimeError("APK cache was empty")
        archive = args.output / f"studio-mini-packages-{arch}.tar"
        with tarfile.open(archive, "x", format=tarfile.USTAR_FORMAT) as tar:
            for path in paths:
                if path.is_symlink() or not path.is_file():
                    raise RuntimeError("Unexpected package input")
                entry = tarfile.TarInfo(path.name)
                entry.size = path.stat().st_size
                entry.mode = 0o644
                with path.open("rb") as content:
                    tar.addfile(entry, content)
        lock["architectures"][arch] = {
            "apk_arch": apk_arch,
            "archive": {
                "name": archive.name,
                "sha256": sha256(archive),
                "size": archive.stat().st_size,
                "url": None,
            },
            "packages": [
                {"name": p.name, "sha256": sha256(p), "size": p.stat().st_size}
                for p in paths
            ],
        }
    if inventories[0] != inventories[1] or worlds[0] != worlds[1]:
        raise RuntimeError(
            "Architecture inventories differ; review separately, do not promote"
        )
    (args.output / "packages.lock").write_bytes(inventories[0])
    (args.output / "packages.world").write_bytes(worlds[0])
    (args.output / "package-inputs.lock.json").write_text(
        json.dumps(lock, indent=2) + "\n"
    )
    print(
        f"Candidate inputs retained in {args.output}. Review before promotion. Nothing published."
    )


if __name__ == "__main__":
    main()
