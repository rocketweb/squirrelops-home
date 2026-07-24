"""Tests for bounded private daemon logging."""

from __future__ import annotations

import logging
import plistlib
import stat
from pathlib import Path

from squirrelops_home_sensor.__main__ import _PrivateRotatingFileHandler

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_private_rotating_handler_bounds_log_and_permissions(tmp_path: Path) -> None:
    log_path = tmp_path / "sensor.log"
    handler = _PrivateRotatingFileHandler(
        log_path,
        maxBytes=256,
        backupCount=2,
        encoding="utf-8",
    )
    logger = logging.getLogger("squirrelops.tests.private-rotation")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    try:
        for index in range(100):
            logger.info("bounded log message %03d %s", index, "x" * 40)
    finally:
        handler.close()
        logger.handlers = []

    files = sorted(tmp_path.glob("sensor.log*"))
    assert 1 < len(files) <= 3
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in files)


def test_packaged_daemon_routes_python_logs_through_rotating_handler() -> None:
    plist_path = REPO_ROOT / "sensor/resources/com.squirrelops.sensor.plist"
    with plist_path.open("rb") as plist_file:
        plist = plistlib.load(plist_file)

    environment = plist["EnvironmentVariables"]
    assert environment["SQUIRRELOPS_LOG_PATH"].endswith(
        "/squirrelops-sensor.log"
    )
    assert plist["StandardOutPath"].endswith("/squirrelops-bootstrap.log")
    assert plist["StandardErrorPath"].endswith("/squirrelops-bootstrap.log")
