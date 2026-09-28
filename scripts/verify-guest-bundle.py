#!/usr/bin/env python3
"""Validate the immutable Studio Mini guest bundle before app packaging."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import subprocess
import sys
from pathlib import Path

EXPECTED_FILES = {"manifest.json", "vmlinuz", "studio-mini.initramfs"}
EXPECTED_SERVICES = (
    ("ssh", 22, 10022),
    ("smb", 445, 10445),
)
MAX_KERNEL_BYTES = 128 * 1024 * 1024
MAX_INITRAMFS_BYTES = 384 * 1024 * 1024


def fail(message: str) -> "NoReturn":
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
