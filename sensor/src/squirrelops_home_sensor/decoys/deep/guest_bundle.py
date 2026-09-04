"""Fail-closed validation for the signed, memory-only deception guest bundle."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_EXPECTED_SERVICES = (
    ("ssh", 22, 10022),
    ("smb", 445, 10445),
)
_MAX_KERNEL_BYTES = 128 * 1024 * 1024
_MAX_INITRAMFS_BYTES = 384 * 1024 * 1024


class GuestBundleError(RuntimeError):
    """Raised when a guest artifact cannot cross the runtime trust boundary."""


@dataclass(frozen=True)
class GuestService:
    name: str
    advertised_port: int
    guest_vsock_port: int


@dataclass(frozen=True)
class GuestBundle:
    root: Path
    persona_id: str
    kernel_path: Path
    initial_ramdisk_path: Path
    command_line: str
    cpu_count: int
    memory_bytes: int
    max_connections: int
    services: tuple[GuestService, ...]
    has_network_device: bool = False


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GuestBundleError(f"Guest manifest {name} must be an object")
    return value


def _trusted_regular_file(path: Path, trusted_uids: set[int], label: str) -> os.stat_result:
    try:
        result = path.lstat()
    except OSError as exc:
        raise GuestBundleError(f"Guest {label} is unavailable") from exc
    if not stat.S_ISREG(result.st_mode):
        raise GuestBundleError(f"Guest {label} must be a regular file")
    if result.st_uid not in trusted_uids:
        raise GuestBundleError(f"Guest {label} has an untrusted owner")
    if result.st_mode & 0o022:
        raise GuestBundleError(f"Guest {label} is writable by an untrusted account")
    return result


def _artifact_path(
    root: Path,
    descriptor: dict[str, Any],
    *,
    trusted_uids: set[int],
    label: str,
    max_size: int,
) -> Path:
    file_name = descriptor.get("path")
    if (
        not isinstance(file_name, str)
        or not file_name
        or Path(file_name).name != file_name
        or file_name in {".", ".."}
    ):
        raise GuestBundleError(f"Guest {label} path must be one file name")
    path = root / file_name
    stat_result = _trusted_regular_file(path, trusted_uids, label)
    if stat_result.st_size <= 0 or stat_result.st_size > max_size:
        raise GuestBundleError(f"Guest {label} size is outside the allowed range")

    expected_digest = descriptor.get("sha256")
    if (
        not isinstance(expected_digest, str)
        or len(expected_digest) != 64
        or any(character not in "0123456789abcdef" for character in expected_digest)
    ):
        raise GuestBundleError(f"Guest {label} digest is invalid")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as artifact:
            for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise GuestBundleError(f"Guest {label} could not be read") from exc
    if not hmac.compare_digest(digest.hexdigest(), expected_digest):
        raise GuestBundleError(f"Guest {label} digest does not match the manifest")
    return path


def load_guest_bundle(
    root: Path,
    *,
    trusted_uids: set[int] | None = None,
) -> GuestBundle:
    """Load and verify the exact 2.1 guest shape.

    Production callers accept root-owned package files only. Tests and source
    development may explicitly provide the current UID.
    """
    trusted_uids = {0} if trusted_uids is None else set(trusted_uids)
    if not trusted_uids:
        raise GuestBundleError("At least one trusted guest owner is required")
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise GuestBundleError("Guest bundle is unavailable") from exc
    if not stat.S_ISDIR(root_stat.st_mode) or root.is_symlink():
        raise GuestBundleError("Guest bundle root must be a real directory")
    if root_stat.st_uid not in trusted_uids or root_stat.st_mode & 0o022:
        raise GuestBundleError("Guest bundle root has unsafe ownership or permissions")

    manifest_path = root / "manifest.json"
    manifest_stat = _trusted_regular_file(manifest_path, trusted_uids, "manifest")
    if manifest_stat.st_size <= 0 or manifest_stat.st_size > 64 * 1024:
        raise GuestBundleError("Guest manifest size is outside the allowed range")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GuestBundleError("Guest manifest is not valid UTF-8 JSON") from exc
    manifest = _object(manifest, "root")
    if manifest.get("schema_version") != 1:
        raise GuestBundleError("Guest manifest schema version is unsupported")
    if manifest.get("persona_id") != "studio-mini-v1":
        raise GuestBundleError("Guest persona is not the reviewed studio-mini identity")

    boot = _object(manifest.get("boot"), "boot")
    command_line = boot.get("command_line")
    if command_line != "console=hvc0 rdinit=/sbin/init":
        raise GuestBundleError("Guest kernel command line is not the reviewed value")
    kernel_path = _artifact_path(
        root,
        _object(boot.get("kernel"), "boot.kernel"),
        trusted_uids=trusted_uids,
        label="kernel",
        max_size=_MAX_KERNEL_BYTES,
    )
    initial_ramdisk_path = _artifact_path(
        root,
        _object(boot.get("initial_ramdisk"), "boot.initial_ramdisk"),
        trusted_uids=trusted_uids,
        label="initial ramdisk",
        max_size=_MAX_INITRAMFS_BYTES,
    )

    resources = _object(manifest.get("resources"), "resources")
    cpu_count = resources.get("cpu_count")
    memory_bytes = resources.get("memory_bytes")
    max_connections = resources.get("max_connections")
    if cpu_count != 2:
        raise GuestBundleError("Guest CPU count must match the reviewed ceiling")
    if memory_bytes != 1_073_741_824:
        raise GuestBundleError("Guest memory must match the reviewed ceiling")
    if max_connections != 16:
        raise GuestBundleError("Guest connection ceiling must match the reviewed value")

    containment = _object(manifest.get("containment"), "containment")
    if containment.get("network_devices") != 0:
        raise GuestBundleError("Guest must not have a network device")
    if containment.get("host_shares") != []:
        raise GuestBundleError("Guest must not have host shares")
    if containment.get("clipboard") is not False:
        raise GuestBundleError("Guest clipboard sharing must be disabled")
    if containment.get("egress") != "none":
        raise GuestBundleError("Guest egress must be disabled")
    if containment.get("root_filesystem") != "memory-only":
        raise GuestBundleError("Guest root filesystem must be memory-only")

    raw_services = manifest.get("services")
    if not isinstance(raw_services, list):
        raise GuestBundleError("Guest service set must be a list")
    parsed_services: list[GuestService] = []
    for raw_service in raw_services:
        service = _object(raw_service, "service")
        name = service.get("name")
        advertised_port = service.get("advertised_port")
        guest_vsock_port = service.get("guest_vsock_port")
        if (
            not isinstance(name, str)
            or not isinstance(advertised_port, int)
            or isinstance(advertised_port, bool)
            or not isinstance(guest_vsock_port, int)
            or isinstance(guest_vsock_port, bool)
        ):
            raise GuestBundleError("Guest service descriptor has invalid field types")
        parsed_services.append(
            GuestService(
                name=name,
                advertised_port=advertised_port,
                guest_vsock_port=guest_vsock_port,
            )
        )
    actual_services = tuple(
        (service.name, service.advertised_port, service.guest_vsock_port)
        for service in parsed_services
    )
    if actual_services != _EXPECTED_SERVICES:
        raise GuestBundleError("Guest service set is not the reviewed SSH and SMB pair")

    return GuestBundle(
        root=root,
        persona_id="studio-mini-v1",
        kernel_path=kernel_path,
        initial_ramdisk_path=initial_ramdisk_path,
        command_line=command_line,
        cpu_count=cpu_count,
        memory_bytes=memory_bytes,
        max_connections=max_connections,
        services=tuple(parsed_services),
    )
