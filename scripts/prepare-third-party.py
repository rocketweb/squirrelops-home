#!/usr/bin/env python3
"""Prepare local Home source/notice assets; never install, execute sources or publish.

The reviewed source lock supplies Alpine base recipes and Python build notices.
Other Python sdists come from uv.lock, selected by the staged wheel inventory.
All downloads (including cached inputs) are size/hash checked before use.
"""

from __future__ import annotations

import argparse
import email.parser
import gzip
import hashlib
import io
import json
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SOURCE_NAME = "THIRD-PARTY-SOURCES.tar"
INVENTORY_NAME = "THIRD-PARTY-INVENTORY.json"
NOTICE_NAME = "THIRD-PARTY-NOTICES.txt"
NOTICE_PATTERN = re.compile(r"^(COPYING|COPYRIGHT|LICEN[SC]E|NOTICE)([._-].*)?$", re.I)


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def safe_path(name: str) -> str:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "\\" in name or "\x00" in name:
        raise ValueError(f"Unsafe source path: {name!r}")
    return path.as_posix()


def fetch(item: dict, cache: Path) -> Path:
    sha, size = item["sha256"], item["size"]
    if not re.fullmatch(r"[0-9a-f]{64}", sha) or not 0 < size <= 1024**3:
        raise ValueError("Invalid source checksum/size")
    url = urllib.parse.urlsplit(item["url"])
    if url.scheme != "https" or url.username or url.password or not url.hostname:
        raise ValueError("Source URL must be HTTPS without credentials")
    target = cache / sha
    if target.exists() or target.is_symlink():
        if not stat.S_ISREG(target.lstat().st_mode):
            raise ValueError("Source cache entry must be regular")
        if target.stat().st_size != size or digest(target) != sha:
            raise ValueError("Source cache checksum mismatch")
        return target
    cache.mkdir(parents=True, exist_ok=True)
    # Download into a private, exclusive temporary file, not a predictable link.
    with tempfile.TemporaryDirectory(dir=cache) as temporary:
        download = Path(temporary) / "source"
        with urllib.request.urlopen(item["url"], timeout=60) as response, download.open("xb") as out:
            if urllib.parse.urlsplit(response.url).scheme != "https":
                raise ValueError("Non-HTTPS source redirect")
            count = 0
            while chunk := response.read(min(1024 * 1024, size + 1 - count)):
                count += len(chunk)
                if count > size:
                    raise ValueError("Source exceeds pinned size")
                out.write(chunk)
        if download.stat().st_size != size or digest(download) != sha:
            raise ValueError("Downloaded source checksum mismatch")
        download.replace(target)
    return target


def guest_packages(initramfs: Path) -> list[dict]:
    """Read just the installed APK database from bounded gzip/newc, without extraction."""
    found = None
    total = 0
    with gzip.open(initramfs, "rb") as stream:
        def read(size):
            nonlocal total
            total += size
            if size < 0 or total > 1024**3:
                raise ValueError("Guest archive exceeds budget")
            data = stream.read(size)
            if len(data) != size:
                raise ValueError("Truncated guest archive")
            return data

        for _ in range(100_000):
            header = read(110)
            if header[:6] != b"070701":
                raise ValueError("Expected newc guest archive")
            values = [int(header[i:i + 8], 16) for i in range(6, 110, 8)]
            mode, links, size, namesize = values[1], values[4], values[6], values[11]
            if not 1 <= namesize <= 4096:
                raise ValueError("Invalid guest member name")
            raw = read(namesize)
            if raw[-1:] != b"\0" or b"\0" in raw[:-1]:
                raise ValueError("Invalid guest member name")
            name = safe_path(raw[:-1].decode())
            read(-(110 + namesize) % 4)
            if name == "TRAILER!!!":
                break
            if name == "lib/apk/db/installed":
                if found is not None or not stat.S_ISREG(mode) or links != 1 or size > 2**20:
                    raise ValueError("Unsafe APK database member")
                found = read(size).decode()
            else:
                while size > 0:
                    chunk_size = min(size, 1024 * 1024)
                    read(chunk_size)
                    size -= chunk_size
            read(-values[6] % 4)
        else:
            raise ValueError("Guest member count exceeds budget")
    if found is None:
        raise ValueError("Guest APK database missing")
    packages = []
    for stanza in found.strip().split("\n\n"):
        fields = dict(line.split(":", 1) for line in stanza.splitlines() if ":" in line)
        packages.append({key: fields[field] for key, field in (
            ("name", "P"), ("version", "V"), ("origin", "o"), ("commit", "c"), ("license", "L")
        )})
    return packages


def check_guest_coverage(installed: list[dict], covered: list[dict]) -> None:
    def key(p):
        return tuple(p[k] for k in ("name", "version", "origin", "commit", "license"))
    actual, expected = [key(p) for p in installed], [key(p) for p in covered]
    if len(set(actual)) != len(actual) or len(set(expected)) != len(expected) or set(actual) != set(expected):
        raise ValueError("Guest source coverage differs from installed package inventory")


def check_base_sources(lock: dict) -> None:
    expected = {(p["origin"], p["commit"]) for p in lock["guest_base_packages"]}
    origins = {(p["origin"], p["commit"]) for p in lock["base_origins"]}
    files = [safe_path(p["path"]) for p in lock["base_files"]]
    if expected != origins or len(origins) != len(lock["base_origins"]) or len(files) != len(set(files)):
        raise ValueError("Incomplete/duplicate base source origins")
    for record in lock["base_origins"]:
        prefix = f'sources/{record["origin"]}-{record["commit"]}/'
        if prefix + "recipe/APKBUILD" not in files:
            raise ValueError("Missing base source recipe")
        for source in record["source_files"]:
            if source["path"] not in files or not source["path"].startswith(prefix):
                raise ValueError("Missing base source input")
        if not record["source_files"] and not record.get("recipe_only"):
            raise ValueError("Unreviewed recipe-only base source")


def python_packages(python_root: Path) -> list[tuple[dict, Path]]:
    paths = sorted(python_root.glob("lib/python*/site-packages/*.dist-info"))
    records = []
    for path in paths:
        metadata = email.parser.Parser().parsestr((path / "METADATA").read_text())
        name = re.sub(r"[-_.]+", "-", metadata["Name"]).lower()
        record = {"name": name, "version": metadata["Version"]}
        if any(r[0]["name"] == name for r in records):
            raise ValueError("Duplicate Python distribution")
        records.append((record, path))
    if not records or any(r[0]["name"] == "scapy" for r in records):
        raise ValueError("Missing Python inventory or unused Scapy in macOS payload")
    return records


def archive_file(output: tarfile.TarFile, path: Path, name: str):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("Only regular source files can be retained")
    entry = tarfile.TarInfo(safe_path(name))
    entry.size, entry.mode = path.stat().st_size, 0o644
    with path.open("rb") as source:
        output.addfile(entry, source)


def archive_bytes(output: tarfile.TarFile, data: bytes, name: str):
    entry = tarfile.TarInfo(safe_path(name))
    entry.size, entry.mode = len(data), 0o644
    output.addfile(entry, io.BytesIO(data))


def source_notices(path: Path, label: str) -> list[tuple[str, bytes]]:
    """Read text members only. Never extract paths, links or executables."""
    if not tarfile.is_tarfile(path):
        return []
    result = []
    with tarfile.open(path) as archive:
        for member in archive:
            if member.isfile() and NOTICE_PATTERN.match(PurePosixPath(member.name).name):
                safe_path(member.name)
                if member.size > 1024 * 1024 or len(result) > 10000:
                    raise ValueError("Source notice budget exceeded")
                result.append((f"{label}: {member.name}", archive.extractfile(member).read()))
    return result


def python_build_notices(metadata: dict, available: set[str]) -> tuple[set[str], list[str]]:
    paths, exceptions = {metadata["license_path"]}, []
    for name, extensions in metadata["build_info"]["extensions"].items():
        for extension in extensions:
            for path in extension.get("license_paths", []):
                # PBS 20260211's macOS metadata includes the Windows zlib-ng
                # notice although this extension links Apple's system libz.
                if path not in available and name == "zlib" and path == "licenses/LICENSE.zlib-ng.txt" \
                        and extension.get("links") == [{"name": "z", "system": True}]:
                    exceptions.append(path + ": zlib links system libz, not bundled zlib-ng")
                else:
                    paths.add(path)
    if not paths <= available:
        raise ValueError("Missing Python build notice")
    return paths, exceptions


def prepare(python_root: Path, guest: Path, cache: Path, output: Path, installed: Path):
    lock_path = ROOT / "third-party/sources.lock.json"
    lock = json.loads(lock_path.read_text())
    if lock["schema_version"] != 1 or lock["architecture"] != "arm64":
        raise ValueError("Only the reviewed Apple Silicon source lock is supported")
    check_base_sources(lock)
    pbs = lock["python_build"]
    runtime_script = (ROOT / "scripts/build-sensor-venv.sh").read_text()
    for text in (f'PBS_RELEASE="{pbs["release"]}"', f'PBS_PYTHON="{pbs["version"]}"',
                 f'PBS_SHA256="{pbs["install_sha256"]}"'):
        if text not in runtime_script:
            raise ValueError("Standalone Python source lock is stale")
    published = json.loads(fetch(lock["guest_inventory"], cache).read_text())
    covered = [{"name": p["pkgname"], "version": p["pkgver"],
                **{k: p[k] for k in ("origin", "commit", "license")}}
               for p in published["packages"] if p["archive_architecture"] == "arm64"]
    covered += lock["guest_base_packages"]
    packages = guest_packages(guest / "studio-mini.initramfs")
    check_guest_coverage(packages, covered)
    uv_lock = tomllib.loads((ROOT / "sensor/uv.lock").read_text())
    python_records = python_packages(python_root)
    sources = []
    for record, _ in python_records:
        if record["name"] == "squirrelops-home-sensor":
            continue
        candidates = [p for p in uv_lock["package"]
                      if p["name"] == record["name"] and p["version"] == record["version"]]
        if len(candidates) == 1 and "sdist" in candidates[0]:
            sdist = candidates[0]["sdist"]
            source = {"url": sdist["url"], "size": sdist["size"],
                      "sha256": sdist["hash"].removeprefix("sha256:")}
        else:
            extra = [s for s in lock["bootstrap_sources"]
                     if s["name"] == record["name"] and s["version"] == record["version"]]
            if len(extra) != 1:
                raise ValueError(f"Missing locked Python source: {record['name']}")
            source = extra[0]
        name = PurePosixPath(urllib.parse.urlsplit(source["url"]).path).name
        sources.append({**record, **source, "path": f"python-sources/{safe_path(name)}"})

    output.mkdir(parents=True, exist_ok=True)
    installed.mkdir(parents=True, exist_ok=True)
    archive_path = output / SOURCE_NAME
    notices = [("SquirrelOps Home (project terms, not third-party terms)", (ROOT / "LICENSE").read_bytes())]
    inventory = {"schema_version": 1, "architecture": "arm64",
                 "distribution_version": (ROOT / "VERSION").read_text().strip(),
                 "guest_packages": packages, "python_packages": [r for r, _ in python_records],
                 "python_sources": sources, "source_lock_sha256": digest(lock_path),
                 "guest_initramfs_sha256": digest(guest / "studio-mini.initramfs")}
    with tarfile.open(archive_path, "x", format=tarfile.PAX_FORMAT) as archive:
        upstream = fetch(lock["guest_sources"], cache)
        archive_file(archive, upstream, "alpine/studio-mini-package-sources.tar")
        # Notice copies in the reviewed archive have indexed hashes and provenance.
        with tarfile.open(upstream) as source_tar:
            for notice in published["notices"]:
                member = source_tar.getmember(safe_path(notice["retained_path"]))
                if not member.isfile() or member.size > 1024 * 1024:
                    raise ValueError("Unsafe retained Alpine notice")
                data = source_tar.extractfile(member).read()
                if hashlib.sha256(data).hexdigest() != notice["sha256"]:
                    raise ValueError("Retained Alpine notice checksum mismatch")
                notices.append((f'Alpine {notice["origin"]}: {notice["source_member"]}', data))
        for source in lock["base_files"]:
            file = fetch(source, cache)
            for record in lock["base_origins"]:
                for original in record["source_files"]:
                    if original["path"] == source["path"]:
                        with file.open("rb") as content:
                            if hashlib.file_digest(content, "sha512").hexdigest() != original["sha512"]:
                                raise ValueError("Alpine source recipe checksum mismatch")
            archive_file(archive, file, "alpine-base/" + safe_path(source["path"]))
            if "/distfiles/" in source["path"]:
                notices.extend(source_notices(file, source["path"]))
        for source in sources:
            file = fetch(source, cache)
            archive_file(archive, file, source["path"])
        for record, path in python_records:
            found = 0
            for file in sorted(path.rglob("*")):
                if file.is_file() and ("licenses" in file.relative_to(path).parts or NOTICE_PATTERN.match(file.name)):
                    if file.is_symlink() or file.stat().st_size > 1024 * 1024:
                        raise ValueError("Unsafe wheel notice")
                    notices.append((f'Python {record["name"]} {record["version"]}: {file.relative_to(path)}', file.read_bytes()))
                    found += 1
            if not found:
                raise ValueError(f'Missing wheel notices: {record["name"]}')
        full = fetch(pbs, cache)
        def pbs_file(name):
            return subprocess.run(["/usr/bin/tar", "-xOf", str(full), "python/" + safe_path(name)],
                                  capture_output=True, check=True, timeout=30).stdout
        metadata = json.loads(pbs_file("PYTHON.json"))
        if metadata["python_version"] != pbs["version"] or metadata["target_triple"] != "aarch64-apple-darwin":
            raise ValueError("Python full archive does not match installed runtime")
        members = subprocess.run(["/usr/bin/tar", "-tf", str(full)], capture_output=True,
                                 text=True, check=True, timeout=30).stdout.splitlines()
        available = {name.removeprefix("python/") for name in members if name.startswith("python/licenses/")}
        notice_paths, inventory["python_notice_exceptions"] = python_build_notices(metadata, available)
        archive_bytes(archive, pbs_file("PYTHON.json"), "python-build/PYTHON.json")
        for name in sorted(notice_paths):
            data = pbs_file(name)
            if not data or len(data) > 1024 * 1024:
                raise ValueError("Missing/oversized Python build notice")
            notices.append((f"Python Build Standalone {pbs['release']}: {name}", data))
            archive_bytes(archive, data, "python-build/" + name)
        # Keep the lock, recipes, instructions and original project terms with sources.
        for relative in ("third-party/sources.lock.json", "sensor/uv.lock", "LICENSE", "docs/THIRD_PARTY.md",
                         "scripts/prepare-third-party.py", "scripts/retain-alpine-sources.py",
                         "scripts/build-sensor-venv.sh", "guest/studio-mini/Dockerfile",
                         "guest/studio-mini/build-guest.sh", "guest/studio-mini/install-packages.sh",
                         "guest/studio-mini/packages.lock", "guest/studio-mini/packages.world",
                         "guest/studio-mini/package-inputs.lock.json"):
            archive_file(archive, ROOT / relative, "build-instructions/" + relative)
        archive_bytes(archive, json.dumps(inventory, indent=2).encode(), INVENTORY_NAME)
    inventory["source_archive"] = {"name": SOURCE_NAME, "size": archive_path.stat().st_size,
                                   "sha256": digest(archive_path)}
    inventory["notice_count"] = len(notices)
    release = "https://github.com/rocketweb/squirrelops-home/releases/tag/home-v" + inventory["distribution_version"]
    preface = (ROOT / "docs/THIRD_PARTY.md").read_text() + f"\n\nRelease source download: {release}\n\n"
    notice_text = preface + "\n\n".join(f"===== {name} =====\n{data.decode('utf-8', errors='replace')}" for name, data in notices)
    (output / NOTICE_NAME).write_text(notice_text)
    inventory["notices_sha256"] = digest(output / NOTICE_NAME)
    (output / INVENTORY_NAME).write_text(json.dumps(inventory, indent=2) + "\n")
    for name in (NOTICE_NAME, INVENTORY_NAME):
        shutil.copyfile(output / name, installed / name)
    shutil.copyfile(ROOT / "LICENSE", installed / "LICENSE")
    print(f"Verified sources: {len(packages)} guest packages, {len(sources)} Python distributions; {len(notices)} notices")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", choices=("arm64",), required=True)
    for name in ("python", "guest", "cache", "output", "installed-notices"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    prepare(args.python, args.guest, args.cache, args.output, args.installed_notices)


if __name__ == "__main__":
    main()
