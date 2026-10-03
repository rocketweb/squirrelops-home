"""Exercise retained guest inputs, not just Dockerfile text."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "scripts/guest-package-inputs.py"
IMAGE = "alpine@sha256:" + "a" * 64


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixture(tmp_path: Path, entries=None):
    entries = entries or [("example-1.0-r0.apk", b"signed package fixture")]
    archive = tmp_path / "inputs.tar"
    with tarfile.open(archive, "w") as tar:
        for name, data in entries:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            tar.addfile(entry, io.BytesIO(data))
    lock = {
        "schema_version": 1,
        "base_image": IMAGE,
        "architectures": {
            "arm64": {
                "apk_arch": "aarch64",
                "archive": {
                    "name": archive.name,
                    "sha256": digest(archive.read_bytes()),
                    "size": archive.stat().st_size,
                    "url": None,
                },
                "packages": [
                    {"name": name, "sha256": digest(data), "size": len(data)}
                    for name, data in entries
                ],
            },
        },
    }
    lock_path = tmp_path / "inputs.lock.json"
    lock_path.write_text(json.dumps(lock))
    return lock_path, archive, lock


def run(tmp_path: Path, lock: Path, archive: Path, *extra):
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "prepare",
            "--lock",
            str(lock),
            "--architecture",
            "arm64",
            "--archive",
            str(archive),
            "--output",
            str(tmp_path / "prepared"),
            "--base-image",
            IMAGE,
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_prepares_exact_offline_files_and_checksums(tmp_path):
    lock, archive, _ = fixture(tmp_path)
    result = run(tmp_path, lock, archive)
    assert result.returncode == 0, result.stderr
    output = tmp_path / "prepared"
    assert sorted(p.name for p in output.iterdir()) == ["SHA256SUMS", "example-1.0-r0.apk"]
    assert (output / "example-1.0-r0.apk").read_bytes() == b"signed package fixture"
    assert (output / "SHA256SUMS").read_text() == (
        digest(b"signed package fixture") + "  example-1.0-r0.apk\n"
    )


def test_changed_archive_fails_before_output(tmp_path):
    lock, archive, _ = fixture(tmp_path)
    archive.write_bytes(archive.read_bytes() + b"changed")
    result = run(tmp_path, lock, archive)
    assert result.returncode != 0
    assert "archive" in result.stderr.lower()
    assert not (tmp_path / "prepared").exists()


def test_changed_package_fails_even_with_matching_archive_digest(tmp_path):
    lock_path, archive, lock = fixture(tmp_path)
    lock["architectures"]["arm64"]["packages"][0]["sha256"] = "b" * 64
    lock_path.write_text(json.dumps(lock))
    result = run(tmp_path, lock_path, archive)
    assert result.returncode != 0
    assert "package digest" in result.stderr.lower()
    assert not (tmp_path / "prepared").exists()


@pytest.mark.parametrize("name", ["../escape.apk", "/absolute.apk", "nested/a.apk", "a.apk\nother"])
def test_rejects_unsafe_package_names(tmp_path, name):
    lock, archive, _ = fixture(tmp_path, [(name, b"bad")])
    result = run(tmp_path, lock, archive)
    assert result.returncode != 0
    assert "package name" in result.stderr.lower()
    assert not (tmp_path / "prepared").exists()


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE])
def test_rejects_links_and_directories(tmp_path, kind):
    lock_path, archive, lock = fixture(tmp_path)
    with tarfile.open(archive, "w") as tar:
        entry = tarfile.TarInfo("example-1.0-r0.apk")
        entry.type = kind
        entry.linkname = "/etc/passwd"
        tar.addfile(entry)
    lock["architectures"]["arm64"]["archive"]["sha256"] = digest(archive.read_bytes())
    lock_path.write_text(json.dumps(lock))
    result = run(tmp_path, lock_path, archive)
    assert result.returncode != 0
    assert "regular file" in result.stderr.lower()
    assert not (tmp_path / "prepared").exists()


def test_rejects_duplicate_archive_entries(tmp_path):
    lock_path, archive, lock = fixture(tmp_path, [("a.apk", b"a"), ("a.apk", b"a")])
    lock["architectures"]["arm64"]["packages"] = lock["architectures"]["arm64"]["packages"][:1]
    lock_path.write_text(json.dumps(lock))
    result = run(tmp_path, lock_path, archive)
    assert result.returncode != 0
    assert "duplicate" in result.stderr.lower()


def test_rejects_unlisted_package(tmp_path):
    lock_path, archive, lock = fixture(tmp_path, [("a.apk", b"a"), ("b.apk", b"b")])
    lock["architectures"]["arm64"]["packages"] = lock["architectures"]["arm64"]["packages"][:1]
    lock_path.write_text(json.dumps(lock))
    result = run(tmp_path, lock_path, archive)
    assert result.returncode != 0
    assert "unexpected package" in result.stderr.lower()


def test_wrong_base_image_fails(tmp_path):
    lock, archive, _ = fixture(tmp_path)
    result = run(tmp_path, lock, archive, "--base-image", "alpine:latest")
    assert result.returncode != 0
    assert "base image" in result.stderr.lower()


def test_cannot_overwrite_existing_destination(tmp_path):
    lock, archive, _ = fixture(tmp_path)
    output = tmp_path / "prepared"
    output.mkdir()
    (output / "keep").write_text("user data")
    result = run(tmp_path, lock, archive)
    assert result.returncode != 0
    assert "output already exists" in result.stderr.lower()
    assert (output / "keep").read_text() == "user data"


def test_missing_archive_never_falls_back_to_live_resolution(tmp_path):
    lock, archive, _ = fixture(tmp_path)
    archive.unlink()
    result = run(tmp_path, lock, archive)
    assert result.returncode != 0
    assert "archive" in result.stderr.lower()
    assert not (tmp_path / "prepared").exists()


def test_guest_dockerfile_installs_without_network_or_signature_bypass():
    dockerfile = (REPO / "guest/studio-mini/Dockerfile").read_text()
    installer = REPO / "guest/studio-mini/install-packages.sh"
    assert "RUN --network=none" in dockerfile
    assert "from=package-inputs" in dockerfile
    assert "apk add --no-cache" not in dockerfile
    text = installer.read_text()
    assert "--no-network" in text
    assert "--repositories-file /dev/null" in text
    assert "apk verify" in text
    assert "--allow-untrusted" not in text
    assert "cp /tmp/squirrelops-packages.world /etc/apk/world" in text


def test_required_ci_check_fails_instead_of_skipping_after_guest_failure():
    workflow = (REPO / ".github/workflows/supply-chain-ci.yml").read_text()
    verify = workflow.split("  verify:\n", 1)[1].split("  guest-inputs:\n", 1)[0]
    assert "needs: guest-inputs" in verify
    assert "if: ${{ always() }}" in verify
    assert "GUEST_INPUTS_RESULT: ${{ needs.guest-inputs.result }}" in verify
    assert 'test "$GUEST_INPUTS_RESULT" = success' in verify
    assert "tests/integration/test_guest_package_install.py -q" in workflow
    assert 'SQUIRRELOPS_TEST_GUEST_PACKAGE_INSTALL: "1"' in workflow


@pytest.mark.parametrize(
    "change,expected",
    [
        (lambda lock: lock.update(schema_version=True), "version"),
        (lambda lock: lock["architectures"]["arm64"].update(apk_arch="x86_64"), "architecture"),
        (lambda lock: lock["architectures"]["arm64"]["archive"].update(size=999999999), "size"),
        (
            lambda lock: lock["architectures"]["arm64"]["archive"].update(
                url="http://example.com/a.tar"
            ),
            "HTTPS",
        ),
        (
            lambda lock: lock["architectures"]["arm64"]["archive"].update(
                url="https://secret@example.com/a.tar"
            ),
            "HTTPS",
        ),
    ],
)
def test_rejects_malformed_reviewed_lock(tmp_path, change, expected):
    lock_path, archive, lock = fixture(tmp_path)
    change(lock)
    lock_path.write_text(json.dumps(lock))
    result = run(tmp_path, lock_path, archive)
    assert result.returncode != 0
    assert expected in result.stderr
    assert not (tmp_path / "prepared").exists()


def test_archive_symlink_is_rejected(tmp_path):
    lock, archive, _ = fixture(tmp_path)
    link = tmp_path / "linked.tar"
    link.symlink_to(archive)
    result = run(tmp_path, lock, link)
    assert result.returncode != 0
    assert "regular file" in result.stderr


def test_missing_package_rejected(tmp_path):
    lock_path, archive, lock = fixture(tmp_path)
    lock["architectures"]["arm64"]["packages"].append(
        {"name": "missing.apk", "sha256": "b" * 64, "size": 20}
    )
    lock_path.write_text(json.dumps(lock))
    result = run(tmp_path, lock_path, archive)
    assert result.returncode != 0
    assert "missing reviewed packages" in result.stderr
    assert not (tmp_path / "prepared").exists()


def test_https_download_stays_bounded_and_no_live_resolution(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("guest_inputs", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    lock_path, archive, lock = fixture(tmp_path)
    lock["architectures"]["arm64"]["archive"]["url"] = "https://example.com/inputs.tar"
    lock_path.write_text(json.dumps(lock))

    class Opener:
        def open(self, url, timeout):
            assert url == "https://example.com/inputs.tar"
            assert timeout == 60
            return io.BytesIO(archive.read_bytes())

    monkeypatch.setattr(module.urllib.request, "build_opener", lambda *args: Opener())
    module.prepare(lock_path, "arm64", IMAGE, None, tmp_path / "downloaded")
    assert (tmp_path / "downloaded/example-1.0-r0.apk").exists()
    lock["architectures"]["arm64"]["archive"]["size"] = 1
    lock_path.write_text(json.dumps(lock))
    with pytest.raises(ValueError, match="exceeds reviewed archive size"):
        module.prepare(lock_path, "arm64", IMAGE, None, tmp_path / "oversized")
    assert not (tmp_path / "oversized").exists()


def test_downgrade_redirect_rejected():
    spec = importlib.util.spec_from_file_location("guest_inputs", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(ValueError, match="remain HTTPS"):
        module.HTTPSRedirect().redirect_request(None, None, 302, "", {}, "http://example.com/a")
