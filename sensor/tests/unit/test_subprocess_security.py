from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from squirrelops_home_sensor.subprocess_security import trusted_executable


def test_rejects_unknown_executable_names() -> None:
    with pytest.raises(ValueError, match="not allow-listed"):
        trusted_executable("attacker-tool")


def test_returns_an_absolute_path_for_available_system_tool() -> None:
    executable = trusted_executable("scutil")
    assert Path(executable).is_absolute()
    assert Path(executable).name == "scutil"


def test_skips_an_admin_writable_allowlisted_candidate() -> None:
    from squirrelops_home_sensor import subprocess_security

    insecure = "/usr/local/bin/nmap"
    secure = "/usr/bin/nmap"

    def fake_lstat(path: Path):
        if str(path) == insecure:
            return SimpleNamespace(st_uid=501, st_mode=0o100755)
        if str(path) == secure:
            return SimpleNamespace(st_uid=0, st_mode=0o100755)
        raise FileNotFoundError

    with (
        patch.dict(
            subprocess_security._TRUSTED_EXECUTABLE_PATHS,
            {"nmap": (insecure, secure)},
        ),
        patch.object(Path, "lstat", fake_lstat),
        patch.object(Path, "is_file", return_value=True),
        patch.object(Path, "is_symlink", return_value=False),
        patch("os.access", return_value=True),
    ):
        assert trusted_executable("nmap") == secure
