"""Static package regressions for signing identity and private logs."""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_sensor_sdist_allowlists_source_and_package_metadata() -> None:
    pyproject = tomllib.loads(
        (REPO_ROOT / "sensor/pyproject.toml").read_text(encoding="utf-8")
    )
    sdist = pyproject["tool"]["hatch"]["build"]["targets"]["sdist"]

    assert set(sdist["include"]) == {"src", "pyproject.toml"}


def test_helper_is_signed_with_its_launchd_identifier() -> None:
    script = (REPO_ROOT / "scripts/sign-app.sh").read_text(encoding="utf-8")

    assert 'HELPER_BUNDLE_ID="com.squirrelops.helper"' in script
    assert '--identifier "$HELPER_BUNDLE_ID"' in script
    assert 'HELPER_SIGNATURE="$(codesign -d --verbose=4' in script
    assert '"Identifier=${HELPER_BUNDLE_ID}" <<< "$HELPER_SIGNATURE"' in script


def test_package_hardens_existing_and_new_sensor_logs() -> None:
    postinstall = (REPO_ROOT / "scripts/pkg/postinstall").read_text(
        encoding="utf-8"
    )
    preinstall = (REPO_ROOT / "scripts/pkg/preinstall").read_text(
        encoding="utf-8"
    )

    assert 'chmod 700 "$LOG_DIR"' in postinstall
    assert (
        'find "$LOG_DIR" -maxdepth 1 -type f -exec chmod 600 {} \\;'
        in postinstall
    )
    assert '-name "squirrelops-sensor.log"' in preinstall
    assert "-delete" in preinstall


def test_embedded_sensor_runtime_uses_hash_locked_dependencies() -> None:
    environment_builder = (
        REPO_ROOT / "scripts/build-sensor-venv.sh"
    ).read_text(encoding="utf-8")
    package_builder = (REPO_ROOT / "scripts/build-pkg.sh").read_text(
        encoding="utf-8"
    )

    assert 'uv export \\\n    --project "$SENSOR_DIR" \\' in environment_builder
    assert "--locked" in environment_builder
    assert "--no-dev" in environment_builder
    assert "--no-emit-project" in environment_builder
    assert "--no-header" in environment_builder
    assert "--no-annotate" in environment_builder
    assert "--require-hashes" in environment_builder
    assert 'REQUIRED_UV_VERSION="0.10.2"' in environment_builder
    assert "--only-group build" in environment_builder
    assert '--build-constraints "$LOCKED_BUILD_REQUIREMENTS"' in environment_builder
    assert '--python "$ENV_PYTHON"' in environment_builder
    assert '"$ENV_PYTHON" -m pip install \\\n    --no-index \\' in environment_builder
    assert '--no-deps \\\n    "$SENSOR_WHEEL"' in environment_builder
    assert '"$ENV_PYTHON" -m pip check' in environment_builder
    assert "Locked runtime mismatch" in environment_builder
    assert (
        'cp "$SENSOR_REQUIREMENTS_LOCK" "$SENSOR_INSTALL/requirements.lock"'
        in package_builder
    )
    assert (
        'cp "$SENSOR_BUILD_REQUIREMENTS_LOCK" \\\n'
        '    "$SENSOR_INSTALL/build-requirements.lock"'
        in package_builder
    )
