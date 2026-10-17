"""Opt-in real APK verification and offline installation in disposable containers."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def retained_inputs(tmp_path_factory):
    archive = os.environ.get("SQUIRRELOPS_TEST_GUEST_PACKAGE_ARCHIVE")
    if not archive and os.environ.get("SQUIRRELOPS_TEST_GUEST_PACKAGE_INSTALL") != "1":
        pytest.skip("Explicit retained-package installation test opt-in is required")
    architecture = os.environ.get("SQUIRRELOPS_TEST_GUEST_ARCH", "arm64")
    platform = {"arm64": "linux/arm64", "x86_64": "linux/amd64"}[architecture]
    guest = REPO / "guest/studio-mini"
    lock = guest / "package-inputs.lock.json"
    image = json.loads(lock.read_text())["base_image"]
    root = tmp_path_factory.mktemp("retained-apks")
    packages = root / "packages"
    subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts/guest-package-inputs.py"),
            "prepare",
            "--lock",
            str(lock),
            "--architecture",
            architecture,
            "--base-image",
            image,
            "--output",
            str(packages),
            *(["--archive", archive] if archive else []),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return guest, packages, image, platform


@pytest.mark.parametrize("case", ["valid", "inventory_drift", "untrusted_signer"])
def test_actual_offline_package_install(retained_inputs, tmp_path, case):
    guest, packages, image, platform = retained_inputs
    inventory = tmp_path / "inventory"
    inventory.write_text(
        (guest / "packages.lock").read_text()
        + ("unexpected-package-1.0-r0\n" if case == "inventory_drift" else "")
    )
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--platform",
        platform,
    ]
    mounts = [
        (packages, "/package-inputs"),
        (inventory, "/tmp/squirrelops-packages.lock"),
        (guest / "packages.world", "/reviewed.world"),
        (guest / "install-packages.sh", "/tmp/install-packages.sh"),
    ]
    if case == "untrusted_signer":
        empty_keys = tmp_path / "empty-keys"
        empty_keys.mkdir()
        mounts.append((empty_keys, "/etc/apk/keys"))
    for source, destination in mounts:
        command.extend(
            [
                "--mount",
                f"type=bind,src={source},dst={destination},readonly",
            ]
        )
    command.extend(
        [
            image,
            "sh",
            "-ec",
            "cp /reviewed.world /tmp/squirrelops-packages.world; "
            "sh /tmp/install-packages.sh; "
            "diff -u /reviewed.world /etc/apk/world; "
            "test ! -e /tmp/squirrelops-packages.world; echo OFFLINE_INSTALL_VERIFIED",
        ]
    )
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    output = result.stdout + result.stderr
    if case == "valid":
        assert result.returncode == 0, output[-4000:]
        assert "OFFLINE_INSTALL_VERIFIED" in output
    else:
        assert result.returncode != 0, output[-4000:]
        assert "OFFLINE_INSTALL_VERIFIED" not in output
        if case == "inventory_drift":
            assert "unexpected-package-1.0-r0" in output
        else:
            assert "UNTRUSTED" in output.upper() or "SIGNATURE" in output.upper(), output[-4000:]
