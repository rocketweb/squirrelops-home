from __future__ import annotations

from pathlib import Path

import pytest

from squirrelops_home_sensor.subprocess_security import trusted_executable


def test_rejects_unknown_executable_names() -> None:
    with pytest.raises(ValueError, match="not allow-listed"):
        trusted_executable("attacker-tool")


def test_returns_an_absolute_path_for_available_system_tool() -> None:
    executable = trusted_executable("scutil")
    assert Path(executable).is_absolute()
    assert Path(executable).name == "scutil"
