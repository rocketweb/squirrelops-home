#!/usr/bin/env python3
"""Validate the immutable Studio Mini guest bundle before app packaging."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import stat
import subprocess
import sys
import zlib
from pathlib import Path, PurePosixPath
from typing import NoReturn

EXPECTED_FILES = {"manifest.json", "vmlinuz", "studio-mini.initramfs"}
EXPECTED_SERVICES = (
    ("ssh", 22, 10022),
    ("smb", 445, 10445),
)
MAX_KERNEL_BYTES = 128 * 1024 * 1024
MAX_INITRAMFS_BYTES = 384 * 1024 * 1024
MAX_UNPACKED_BYTES = 1024 * 1024 * 1024
NETWORK_IDENTITY = {
    "etc/hosts": b"127.0.0.1 studio-mini.local studio-mini localhost\n"
                 b"::1 localhost ip6-localhost ip6-loopback\n",
    "etc/hostname": b"studio-mini\n",
    "etc/resolv.conf": b"nameserver 127.0.0.1\noptions timeout:1 attempts:1\n",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"Invalid Studio Mini guest bundle: {message}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_file(path: Path, maximum: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        fail(f"cannot inspect {path.name}: {exc}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"{path.name} must be a regular file, not a link")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        fail(f"{path.name} has an invalid size")
    if metadata.st_mode & 0o022:
        fail(f"{path.name} must not be group- or world-writable")


def validate_network_identity(path: Path) -> None:
    """Inspect bounded gzip/newc content without extracting or following links."""
    seen: set[str] = set()
    total = 0
    try:
        with gzip.open(path, "rb") as archive:
            def read(size: int) -> bytes:
                nonlocal total
                total += size
                if total > MAX_UNPACKED_BYTES:
                    fail("network identity archive exceeds unpacked budget")
                data = archive.read(size)
                if len(data) != size:
                    fail("network identity archive is truncated")
                return data

            for _ in range(100_000):
                header = read(110)
                if header[:6] != b"070701":
                    fail("network identity archive must use newc format")
                if any(byte not in b"0123456789abcdefABCDEF" for byte in header[6:]):
                    fail("network identity archive fields must be hexadecimal")
                fields = [int(header[i:i + 8], 16) for i in range(6, 110, 8)]
                mode, uid, gid, links, size, name_size = (
                    fields[1], fields[2], fields[3], fields[4], fields[6], fields[11]
                )
                if not 1 <= name_size <= 4096 or size > MAX_UNPACKED_BYTES:
                    fail("network identity archive entry exceeds budget")
                raw_name = read(name_size)
                if raw_name[-1:] != b"\0" or b"\0" in raw_name[:-1]:
                    fail("network identity archive filename is invalid")
                name = raw_name[:-1].decode("utf-8")
                read(-(110 + name_size) % 4)
                if name == "TRAILER!!!":
                    if size or seen != NETWORK_IDENTITY.keys():
                        fail("network identity files are missing")
                    # Consume padding and the gzip trailer, checking its CRC.
                    padding = archive.read(513)
                    if len(padding) > 512 or any(padding):
                        fail("network identity archive has trailing content")
                    return
                parts = PurePosixPath(name)
                if parts.is_absolute() or ".." in parts.parts:
                    fail("network identity archive path escapes root")
                normalized = str(parts)
                if normalized == "etc" and not stat.S_ISDIR(mode):
                    fail("network identity etc must be a directory")
                if normalized in NETWORK_IDENTITY:
                    if normalized in seen or not stat.S_ISREG(mode) or links != 1:
                        fail("network identity file is duplicated or linked")
                    if uid or gid or mode & 0o022 or size > 4096:
                        fail("network identity file has unsafe metadata")
                    if read(size) != NETWORK_IDENTITY[normalized]:
                        fail(f"network identity mismatch in {normalized}")
                    seen.add(normalized)
                else:
                    remaining = size
                    while remaining:
                        chunk = min(remaining, 1024 * 1024)
                        read(chunk)
                        remaining -= chunk
                read(-size % 4)
            fail("network identity archive has too many entries")
    except (OSError, EOFError, ValueError, UnicodeError, zlib.error) as exc:
        fail(f"network identity archive is unreadable: {exc}")


def validate(bundle: Path, architecture: str) -> None:
    if bundle.is_symlink() or not bundle.is_dir():
        fail("bundle root must be a real directory")
    actual_files = {entry.name for entry in bundle.iterdir()}
    if actual_files != EXPECTED_FILES:
        fail(f"unexpected file set: {sorted(actual_files)}")

    manifest_path = bundle / "manifest.json"
    kernel_path = bundle / "vmlinuz"
    initramfs_path = bundle / "studio-mini.initramfs"
    _regular_file(manifest_path, 64 * 1024)
    _regular_file(kernel_path, MAX_KERNEL_BYTES)
    _regular_file(initramfs_path, MAX_INITRAMFS_BYTES)

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"manifest is unreadable: {exc}")
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "persona_id",
        "boot",
        "resources",
        "containment",
        "services",
    }:
        fail("manifest top-level contract does not match schema 1")
    if manifest["schema_version"] != 1 or manifest["persona_id"] != "studio-mini-v1":
        fail("manifest identity does not match Studio Mini v1")
    if manifest["resources"] != {
        "cpu_count": 2,
        "memory_bytes": 1_073_741_824,
        "max_connections": 16,
    }:
        fail("guest resource limits changed")
    if manifest["containment"] != {
        "network_devices": 0,
        "host_shares": [],
        "clipboard": False,
        "egress": "none",
        "root_filesystem": "memory-only",
    }:
        fail("guest containment contract changed")
    raw_services = manifest["services"]
    if not isinstance(raw_services, list):
        fail("guest service map is malformed")
    services: list[tuple[object, object, object]] = []
    for item in raw_services:
        if not isinstance(item, dict) or set(item) != {
            "name",
            "advertised_port",
            "guest_vsock_port",
        }:
            fail("guest service map is malformed")
        services.append(
            (item["name"], item["advertised_port"], item["guest_vsock_port"])
        )
    if tuple(services) != EXPECTED_SERVICES:
        fail("guest service map changed")

    boot = manifest.get("boot")
    if not isinstance(boot, dict) or set(boot) != {
        "kernel",
        "initial_ramdisk",
        "command_line",
    }:
        fail("boot contract is malformed")
    if boot["command_line"] != "console=hvc0 rdinit=/sbin/init":
        fail("kernel command line changed")
    expected_boot = (
        ("kernel", "vmlinuz", kernel_path),
        ("initial_ramdisk", "studio-mini.initramfs", initramfs_path),
    )
    for key, expected_name, path in expected_boot:
        entry = boot.get(key)
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            fail(f"{key} record is malformed")
        if entry["path"] != expected_name or entry["sha256"] != _sha256(path):
            fail(f"{key} digest does not match")

    validate_network_identity(initramfs_path)

    description = subprocess.run(
        ["/usr/bin/file", "-b", str(kernel_path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.casefold()
    expected_marker = "arm64" if architecture == "arm64" else "x86"
    if expected_marker not in description:
        fail(f"kernel does not match requested {architecture} architecture")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--architecture", required=True, choices=("arm64", "x86_64"))
    args = parser.parse_args()
    validate(args.bundle, args.architecture)
    print(f"Verified Studio Mini guest bundle: {args.bundle}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
