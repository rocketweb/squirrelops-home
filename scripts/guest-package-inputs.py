#!/usr/bin/env python3
"""Verify retained APK inputs before making them available to an offline build."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import stat
import tarfile
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

MAX_ARCHIVE = 256 * 1024 * 1024
MAX_PACKAGE = 96 * 1024 * 1024
ARCHES = {"arm64": "aarch64", "x86_64": "x86_64"}


def fail(message: str):
    raise ValueError(message)


def sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def regular(path: Path, maximum: int):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        fail(f"{path.name} must be a regular file with one link")
    if not 0 < info.st_size <= maximum:
        fail(f"{path.name} has invalid size")


def record(value, maximum: int):
    if not isinstance(value, dict):
        fail("invalid file record")
    if type(value.get("size")) is not int or not 0 < value["size"] <= maximum:
        fail("invalid file size")
    if not isinstance(value.get("sha256"), str) or not re.fullmatch(
        r"[0-9a-f]{64}", value["sha256"]
    ):
        fail("invalid file digest")


def load_lock(path: Path, architecture: str, base_image: str):
    regular(path, 1024 * 1024)
    lock = json.loads(path.read_text())
    if not isinstance(lock, dict) or set(lock) != {
        "schema_version",
        "base_image",
        "architectures",
    }:
        fail("invalid package input lock schema")
    if type(lock["schema_version"]) is not int or lock["schema_version"] != 1:
        fail("invalid package input lock version")
    if (
        not re.fullmatch(r"alpine@sha256:[0-9a-f]{64}", base_image)
        or lock["base_image"] != base_image
    ):
        fail("base image does not match reviewed package inputs")
    if (
        not isinstance(lock["architectures"], dict)
        or set(lock["architectures"]) - ARCHES.keys()
    ):
        fail("invalid architecture map")
    item = lock["architectures"].get(architecture)
    if not isinstance(item, dict) or set(item) != {"apk_arch", "archive", "packages"}:
        fail("missing or malformed architecture")
    if item["apk_arch"] != ARCHES[architecture]:
        fail("package architecture mismatch")
    archive = item["archive"]
    record(archive, MAX_ARCHIVE)
    if set(archive) != {"name", "sha256", "size", "url"} or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]*\.tar", archive.get("name", "")
    ):
        fail("invalid archive name or fields")
    if archive["url"] is not None:
        parsed = urllib.parse.urlsplit(archive["url"])
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            fail("archive URL must be HTTPS without credentials or fragment")
    packages = item["packages"]
    if not isinstance(packages, list) or not 1 <= len(packages) <= 256:
        fail("invalid package count")
    names = []
    for package in packages:
        record(package, MAX_PACKAGE)
        if set(package) != {"name", "sha256", "size"} or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._+-]*\.apk", package.get("name", "")
        ):
            fail("invalid package name or fields")
        names.append(package["name"])
    if names != sorted(set(names)):
        fail("package names must be unique and sorted")
    if sum(p["size"] for p in packages) > MAX_ARCHIVE:
        fail("package input set exceeds size budget")
    return item


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            fail("archive redirect must remain HTTPS")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(archive, destination: Path):
    if not archive["url"]:
        fail("archive is not published; supply its verified local --archive path")
    opener = urllib.request.build_opener(HTTPSRedirect())
    with (
        opener.open(archive["url"], timeout=60) as response,
        destination.open("xb") as output,
    ):
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > archive["size"]:
                fail("download exceeds reviewed archive size")
            output.write(chunk)


def prepare(
    lock_path: Path,
    architecture: str,
    base_image: str,
    archive_path: Path | None,
    output: Path,
):
    item = load_lock(lock_path, architecture, base_image)
    if output.exists() or output.is_symlink():
        fail("output already exists; refusing to overwrite")
    # Do not leave a partial directory that a later build could consume.
    with tempfile.TemporaryDirectory(
        prefix="guest-inputs-", dir=output.parent
    ) as temporary:
        staging = Path(temporary)
        if archive_path is None:
            archive_path = staging / "download.tar"
            download(item["archive"], archive_path)
        try:
            regular(archive_path, MAX_ARCHIVE)
            if (
                archive_path.stat().st_size != item["archive"]["size"]
                or sha256(archive_path) != item["archive"]["sha256"]
            ):
                fail("archive size or digest does not match reviewed inputs")
        except OSError as exc:
            fail(f"cannot read package archive: {exc}")
        packages = {p["name"]: p for p in item["packages"]}
        payload = staging / "payload"
        payload.mkdir(mode=0o755)
        seen = set()
        # No extractall: reject links, paths, duplicates and surplus files.
        with tarfile.open(archive_path, "r:") as tar:
            for member in tar:
                if member.name in seen:
                    fail("duplicate package in archive")
                if member.name not in packages:
                    fail("unexpected package in archive")
                if not member.isfile() or member.linkname or member.issparse():
                    fail("archive entry must be a regular file")
                expected = packages[member.name]
                if member.size != expected["size"]:
                    fail("package size mismatch")
                seen.add(member.name)
                path = payload / member.name
                with tar.extractfile(member) as source, path.open("xb") as target:
                    shutil.copyfileobj(source, target, 1024 * 1024)
                path.chmod(0o644)
                if sha256(path) != expected["sha256"]:
                    fail("package digest mismatch")
        if seen != packages.keys():
            fail("archive is missing reviewed packages")
        (payload / "SHA256SUMS").write_text(
            "".join(
                f"{package['sha256']}  {package['name']}\n"
                for package in item["packages"]
            )
        )
        (payload / "SHA256SUMS").chmod(0o644)
        payload.rename(output)
    print(
        f"Verified {len(packages)} retained APKs for {architecture}; no live package resolution"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare"])
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--architecture", choices=ARCHES, required=True)
    parser.add_argument("--base-image", required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare(
            args.lock, args.architecture, args.base_image, args.archive, args.output
        )
    except (ValueError, OSError, tarfile.TarError) as exc:
        parser.exit(1, f"Invalid guest package inputs: {exc}\n")


if __name__ == "__main__":
    main()
