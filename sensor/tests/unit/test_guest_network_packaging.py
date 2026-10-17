"""Prevent build-container identity and DNS from escaping into guest artifacts."""

import gzip
import importlib.util
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.guest_archive import NETWORK_FILES, initramfs

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("guest_verifier", ROOT / "scripts/verify-guest-bundle.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def entries(files):
    return [(name, data, stat.S_IFREG | 0o644, 1) for name, data in files.items()]


def verify(tmp_path, records):
    image = tmp_path / "guest.gz"
    image.write_bytes(initramfs(records))
    verifier.validate_network_identity(image)


def test_reviewed_identity_matches_persona_and_packaging_inputs(tmp_path):
    from squirrelops_home_sensor.decoys.deep.persona import build_studio_mini_persona

    persona = build_studio_mini_persona(
        b"synthetic-network-test-key".ljust(32, b"!"), datetime(2026, 10, 1, tzinfo=UTC)
    )
    assert NETWORK_FILES["etc/hostname"].decode().strip() == persona.short_hostname
    assert persona.hostname.encode() in NETWORK_FILES["etc/hosts"]
    for name, expected in NETWORK_FILES.items():
        assert (ROOT / "guest/studio-mini/network" / Path(name).name).read_bytes() == expected
    verify(tmp_path, entries(NETWORK_FILES))


@pytest.mark.parametrize("name,bad", [
    ("etc/hosts", b"127.0.0.1 localhost buildkitsandbox\n"),
    ("etc/hostname", b"localhost\n"),
    ("etc/resolv.conf", b"nameserver 192.168.65.7\n"),
    ("etc/resolv.conf", NETWORK_FILES["etc/resolv.conf"] + b"search builder.private\n"),
])
def test_rejects_builder_identity_even_when_archive_is_well_formed(tmp_path, name, bad):
    with pytest.raises(SystemExit, match="network identity"):
        verify(tmp_path, entries(NETWORK_FILES | {name: bad}))


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "alias", "symlink", "hardlink", "writable", "traversal"])
def test_rejects_ambiguous_identity(tmp_path, mutation):
    records = entries(NETWORK_FILES)
    name, data, mode, links = records[0]
    if mutation == "missing":
        records.pop(0)
    elif mutation == "duplicate":
        records.append(records[0])
    elif mutation == "alias":
        records.append(("./etc//hosts", data, mode, links))
    elif mutation == "symlink":
        records[0] = (name, b"/tmp/hosts", stat.S_IFLNK | 0o777, links)
    elif mutation == "hardlink":
        records[0] = (name, data, mode, 2)
    elif mutation == "writable":
        records[0] = (name, data, mode | 0o022, links)
    else:
        records.append(("etc/../etc/hosts", data, mode, links))
    with pytest.raises(SystemExit):
        verify(tmp_path, records)


def test_rejects_linked_etc_directory(tmp_path):
    with pytest.raises(SystemExit):
        verify(tmp_path, [("etc", b"/tmp", stat.S_IFLNK | 0o777, 1), *entries(NETWORK_FILES)])


def test_rejects_truncated_archive(tmp_path):
    image = tmp_path / "bad.gz"
    image.write_bytes(initramfs()[:-8])
    with pytest.raises(SystemExit):
        verifier.validate_network_identity(image)


def test_rejects_signed_nonhex_archive_field(tmp_path):
    payload = bytearray(gzip.decompress(initramfs()))
    payload[6:14] = b"+0000001"
    image = tmp_path / "bad-field.gz"
    image.write_bytes(gzip.compress(payload))
    with pytest.raises(SystemExit):
        verifier.validate_network_identity(image)


def test_rejects_invalid_deflate_stream(tmp_path):
    image = tmp_path / "bad-deflate.gz"
    image.write_bytes(bytes.fromhex("1f8b0800000000000003ff000000000000000000"))
    with pytest.raises(SystemExit):
        verifier.validate_network_identity(image)


def test_unpacked_budget_is_enforced(tmp_path, monkeypatch):
    monkeypatch.setattr(verifier, "MAX_UNPACKED_BYTES", 100)
    with pytest.raises(SystemExit, match="budget"):
        verify(tmp_path, entries(NETWORK_FILES))


def test_rejects_second_archive_after_trailer(tmp_path):
    image = tmp_path / "concatenated.gz"
    image.write_bytes(initramfs() + initramfs())
    with pytest.raises(SystemExit, match="trailing content"):
        verifier.validate_network_identity(image)
