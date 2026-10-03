"""The installer must carry notices and sources for its actual contents."""

import importlib.util
import sys
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[3]


def test_scapy_is_linux_only_and_project_license_is_packaged():
    project = tomllib.loads((ROOT / "sensor/pyproject.toml").read_text())["project"]
    scapy = next(Requirement(d) for d in project["dependencies"] if d.startswith("scapy"))
    assert scapy.marker is not None, "Unused GPL dependency must not ship on macOS"
    assert not scapy.marker.evaluate({"sys_platform": "darwin"})
    assert scapy.marker.evaluate({"sys_platform": "linux"})
    assert project["license-files"] == ["LICENSE"]
    assert (ROOT / "sensor/LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()


@pytest.fixture
def sources():
    spec = importlib.util.spec_from_file_location(
        "third_party_sources", ROOT / "scripts/prepare-third-party.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_guest_coverage_checks_base_packages_and_recipe_commit(sources):
    package = {"name": "busybox", "version": "1.37.0-r31", "origin": "busybox",
               "commit": "a" * 40, "license": "GPL-2.0-only"}
    sources.check_guest_coverage([package], [package])
    with pytest.raises(ValueError, match="coverage"):
        sources.check_guest_coverage([package], [])
    with pytest.raises(ValueError, match="coverage"):
        sources.check_guest_coverage([package], [{**package, "commit": "b" * 40}])


def test_download_cache_is_rehashed(sources, tmp_path):
    import hashlib

    data = b"source"
    item = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
            "url": "https://example.invalid/source.tar"}
    target = tmp_path / item["sha256"]
    target.write_bytes(b"broken")
    with pytest.raises(ValueError, match="checksum"):
        sources.fetch(item, tmp_path)
    target.unlink()
    target.symlink_to(tmp_path / "other")
    with pytest.raises(ValueError, match="regular"):
        sources.fetch(item, tmp_path)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "a/../../b", "a\\b"])
def test_source_members_cannot_escape(sources, name):
    with pytest.raises(ValueError, match="path"):
        sources.safe_path(name)


def test_every_base_source_must_be_retained(sources):
    lock = {"guest_base_packages": [{"origin": "busybox", "commit": "a" * 40}],
            "base_origins": [{"origin": "busybox", "commit": "a" * 40,
                              "source_files": [{"path": "sources/busybox/recipe/patch"}]}],
            "base_files": []}
    with pytest.raises(ValueError, match="base source"):
        sources.check_base_sources(lock)


def test_mac_source_assets_are_uploaded_and_attested():
    text = (ROOT / ".github/workflows/release.yml").read_text()
    for name in ("THIRD-PARTY-SOURCES.tar", "THIRD-PARTY-INVENTORY.json", "THIRD-PARTY-NOTICES.txt"):
        assert f"build/pkg/output/{name}" in text
        assert f"release-assets/{name}" in text
    assert "--third-party release-input" in text


def test_python_inventory_rejects_scapy_unknown_notice_state(sources, tmp_path):
    metadata = tmp_path / "lib/python3.12/site-packages/scapy-2.7.0.dist-info"
    metadata.mkdir(parents=True)
    (metadata / "METADATA").write_text("Name: scapy\nVersion: 2.7.0\n")
    with pytest.raises(ValueError, match="Scapy"):
        sources.python_packages(tmp_path)


def test_guest_database_is_read_without_extracting(sources, tmp_path):
    from tests.guest_archive import initramfs

    guest = tmp_path / "initramfs"
    database = b"P:busybox\nV:1.0-r0\no:busybox\nc:abc\nL:GPL-2.0-only\n\n"
    guest.write_bytes(initramfs([("lib/apk/db/installed", database, 0o100644, 1)]))
    assert sources.guest_packages(guest) == [{
        "name": "busybox", "version": "1.0-r0", "origin": "busybox",
        "commit": "abc", "license": "GPL-2.0-only",
    }]


def test_system_zlib_stale_notice_does_not_allow_missing_bundled_notice(sources):
    extension = {"links": [{"name": "z", "system": True}],
                 "license_paths": ["licenses/LICENSE.zlib-ng.txt", "licenses/LICENSE.zlib.txt"]}
    metadata = {"license_path": "licenses/LICENSE.cpython.txt",
                "build_info": {"extensions": {"zlib": [extension]}}}
    available = {"licenses/LICENSE.cpython.txt", "licenses/LICENSE.zlib.txt"}
    paths, exceptions = sources.python_build_notices(metadata, available)
    assert paths == available
    assert exceptions == ["licenses/LICENSE.zlib-ng.txt: zlib links system libz, not bundled zlib-ng"]
    extension["links"] = [{"name": "z", "path_static": "build/libz.a"}]
    with pytest.raises(ValueError, match="Missing Python build notice"):
        sources.python_build_notices(metadata, available)
