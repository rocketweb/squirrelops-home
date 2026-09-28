"""Exercise the installer's actual snapshot function with macOS SQLite."""

from __future__ import annotations

import grp
import os
import pwd
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
pytestmark = pytest.mark.skipif(
    sys.platform != "darwin", reason="Requires the macOS package utilities"
)


def _function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{")
    return source[start:source.index("\n}\n", start) + 3]


def _snapshot(install: Path, backups: Path) -> subprocess.CompletedProcess[str]:
    source = (REPO_ROOT / "scripts/pkg/preinstall").read_text()
    functions = "\n".join(
        _function(source, name) for name in (
            "path_has_no_extended_acl", "snapshot_tree_is_private",
            "create_upgrade_snapshot",
        )
    )
    # The fixture owns its private directories. Only translate the root owner
    # assertions; execute real ditto, sqlite3, chmod, and snapshot validation.
    owner = pwd.getpwuid(os.getuid()).pw_name
    group = grp.getgrgid(os.getgid()).gr_name
    functions = functions.replace("-o root -g wheel", f"-o {os.getuid()} -g {os.getgid()}")
    functions = functions.replace("root:wheel:700", f"{owner}:{group}:700")
    harness = f"""
set -euo pipefail
INSTALL_DIR="$1"
DATA_DIR="$INSTALL_DIR/data"
SENSOR_DB="$DATA_DIR/squirrelops.db"
CONFIG_FILE="$INSTALL_DIR/config.yaml"
BACKUP_ROOT="$2"
INCOMPLETE_BACKUP_DIR=""
{functions}
if ! create_upgrade_snapshot; then
    exit 1
fi
"""
    return subprocess.run(
        ["/bin/bash", "-c", harness, "snapshot-test", str(install), str(backups)],
        capture_output=True, text=True, timeout=30, check=False,
    )


@pytest.mark.parametrize("journal", ["DELETE", "WAL"])
@pytest.mark.parametrize("writer_open", [False, True])
def test_snapshot_is_standalone_and_preserves_committed_rows(
    tmp_path: Path, journal: str, writer_open: bool,
) -> None:
    # Resolve /var -> /private/var so -nofollow tests the files, not pytest's
    # platform temporary-directory alias.
    tmp_path = tmp_path.resolve()
    install = tmp_path / "sensor"
    data = install / "data"
    data.mkdir(parents=True)
    database = data / "squirrelops.db"
    backups = tmp_path / "backups"
    connection = sqlite3.connect(database)
    try:
        connection.execute(f"PRAGMA journal_mode={journal}")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY, message TEXT)")
        connection.execute("INSERT INTO alerts VALUES (1, 'retained alert')")
        connection.commit()
        # Cover both a clean shutdown and committed data still in the WAL.
        if not writer_open:
            connection.close()
        before = database.read_bytes()
        result = _snapshot(install, backups)
        assert result.returncode == 0, result.stdout + result.stderr
        snapshots = list(backups.glob("preinstall.*"))
        assert len(snapshots) == 1
        snapshot = snapshots[0]
        copied = snapshot / "data/squirrelops.db"
        assert (snapshot / "COMPLETE").is_file()
        assert copied.is_file()
        assert not Path(f"{copied}-wal").exists()
        assert not Path(f"{copied}-shm").exists()
        check = subprocess.run(
            ["/usr/bin/sqlite3", "-bail", "-batch", "-nofollow", "-readonly",
             str(copied), "PRAGMA trusted_schema=OFF; PRAGMA quick_check(1); "
             "PRAGMA journal_mode; SELECT id, message FROM alerts;"],
            capture_output=True, text=True, check=False,
        )
        assert check.returncode == 0, check.stderr
        assert check.stdout.splitlines() == ["ok", "delete", "1|retained alert"]
        assert database.read_bytes() == before
        if writer_open:
            assert connection.execute("PRAGMA journal_mode").fetchone()[0] == journal.lower()
        assert copied.stat().st_mode & 0o777 == 0o600
    finally:
        connection.close()


@pytest.mark.parametrize("invalid", ["corrupt", "symlink"])
def test_snapshot_rejects_invalid_source_without_completing(
    tmp_path: Path, invalid: str,
) -> None:
    tmp_path = tmp_path.resolve()
    install = tmp_path / "sensor"
    data = install / "data"
    data.mkdir(parents=True)
    database = data / "squirrelops.db"
    if invalid == "corrupt":
        database.write_bytes(b"not a database")
    else:
        target = tmp_path / "elsewhere.db"
        with sqlite3.connect(target) as connection:
            connection.execute("CREATE TABLE sentinel (id INTEGER)")
        database.symlink_to(target)
    before = database.read_bytes()
    backups = tmp_path / "backups"
    result = _snapshot(install, backups)
    assert result.returncode != 0
    assert "Sensor database integrity check failed" in result.stderr
    assert not list(backups.glob("preinstall.*/COMPLETE"))
    assert database.read_bytes() == before
