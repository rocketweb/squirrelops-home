"""Trust-boundary tests for the disposable 2.1 guest artifact."""

import hashlib
import json
import os
from pathlib import Path

import pytest

from squirrelops_home_sensor.decoys.deep.guest_bundle import (
    GuestBundleError,
    load_guest_bundle,
)


def _write_bundle(root: Path) -> None:
    kernel = b"test-linux-kernel"
    initramfs = b"test-memory-only-rootfs"
    (root / "vmlinuz").write_bytes(kernel)
    (root / "studio-mini.initramfs").write_bytes(initramfs)
    manifest = {
        "schema_version": 1,
        "persona_id": "studio-mini-v1",
        "boot": {
            "kernel": {
                "path": "vmlinuz",
                "sha256": hashlib.sha256(kernel).hexdigest(),
            },
            "initial_ramdisk": {
                "path": "studio-mini.initramfs",
                "sha256": hashlib.sha256(initramfs).hexdigest(),
            },
            "command_line": "console=hvc0 rdinit=/sbin/init",
        },
        "resources": {
            "cpu_count": 2,
            "memory_bytes": 1073741824,
            "max_connections": 16,
        },
        "containment": {
            "network_devices": 0,
            "host_shares": [],
            "clipboard": False,
            "egress": "none",
            "root_filesystem": "memory-only",
        },
        "services": [
            {
                "name": "ssh",
                "advertised_port": 22,
                "guest_vsock_port": 10022,
            },
            {
                "name": "smb",
                "advertised_port": 445,
                "guest_vsock_port": 10445,
            },
        ],
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_valid_bundle_is_loaded_with_exact_two_real_protocols(tmp_path: Path) -> None:
    _write_bundle(tmp_path)

    bundle = load_guest_bundle(tmp_path, trusted_uids={os.getuid()})

    assert bundle.persona_id == "studio-mini-v1"
    assert bundle.kernel_path == tmp_path / "vmlinuz"
    assert bundle.initial_ramdisk_path == tmp_path / "studio-mini.initramfs"
    assert [(service.name, service.advertised_port) for service in bundle.services] == [
        ("ssh", 22),
        ("smb", 445),
    ]
    assert bundle.has_network_device is False


def test_digest_mismatch_fails_closed(tmp_path: Path) -> None:
    _write_bundle(tmp_path)
    (tmp_path / "studio-mini.initramfs").write_bytes(b"tampered")

    with pytest.raises(GuestBundleError, match="digest"):
        load_guest_bundle(tmp_path, trusted_uids={os.getuid()})


def test_symlinked_boot_artifact_is_rejected(tmp_path: Path) -> None:
    _write_bundle(tmp_path)
    outside = tmp_path.parent / "outside-vmlinuz"
    outside.write_bytes(b"test-linux-kernel")
    (tmp_path / "vmlinuz").unlink()
    (tmp_path / "vmlinuz").symlink_to(outside)

    with pytest.raises(GuestBundleError, match="regular file"):
        load_guest_bundle(tmp_path, trusted_uids={os.getuid()})


def test_world_writable_artifact_is_rejected(tmp_path: Path) -> None:
    _write_bundle(tmp_path)
    (tmp_path / "vmlinuz").chmod(0o666)

    with pytest.raises(GuestBundleError, match="writable"):
        load_guest_bundle(tmp_path, trusted_uids={os.getuid()})


def test_bundle_with_a_network_device_is_rejected(tmp_path: Path) -> None:
    _write_bundle(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["containment"]["network_devices"] = 1
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(GuestBundleError, match="network device"):
        load_guest_bundle(tmp_path, trusted_uids={os.getuid()})


def test_bundle_cannot_add_visitor_selected_service(tmp_path: Path) -> None:
    _write_bundle(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["services"].append(
        {"name": "visitor", "advertised_port": 9001, "guest_vsock_port": 19001}
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(GuestBundleError, match="service set"):
        load_guest_bundle(tmp_path, trusted_uids={os.getuid()})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", None),
        ("advertised_port", "22"),
        ("advertised_port", True),
        ("guest_vsock_port", "10022"),
        ("guest_vsock_port", False),
    ],
)
def test_bundle_rejects_ambiguous_service_field_types(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    _write_bundle(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["services"][0][field] = value
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(GuestBundleError, match="field types"):
        load_guest_bundle(tmp_path, trusted_uids={os.getuid()})


def test_bundle_cannot_escape_root_with_boot_path(tmp_path: Path) -> None:
    _write_bundle(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["boot"]["kernel"]["path"] = "../outside-vmlinuz"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(GuestBundleError, match="file name"):
        load_guest_bundle(tmp_path, trusted_uids={os.getuid()})
