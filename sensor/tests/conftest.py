"""Shared test fixtures for SquirrelOps Home Sensor tests."""

import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SENSOR_ROOT = REPO_ROOT / "sensor"


@pytest.fixture
def repo_root() -> pathlib.Path:
    return REPO_ROOT


@pytest.fixture
def sensor_root() -> pathlib.Path:
    return SENSOR_ROOT
