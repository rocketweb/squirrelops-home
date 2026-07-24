"""Safe, explicit removal of persisted alert history."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite

logger = logging.getLogger(__name__)

_clear_lock = asyncio.Lock()
_ALERT_EVENT_TYPES = (
    "alert.new",
    "alert.updated",
    "incident.new",
    "incident.updated",
)
_SQLITE_MAX_ROW_ID = (1 << 63) - 1
_PORT_RISK_ALERT_ROWS = """
    SELECT affected_devices, detail, device_id, issue_key
    FROM home_alerts
    WHERE alert_type = 'security.port_risk'
"""
_UPSERT_CLEARED_PORT_RISK = """
    INSERT INTO security_insight_state
        (device_id, insight_key, alert_id, created_at, resolved_at)
    SELECT id, ?, NULL, ?, NULL
    FROM devices
    WHERE id = ?
    ON CONFLICT(device_id, insight_key) DO UPDATE SET
        alert_id = NULL,
        resolved_at = NULL
"""


@dataclass(frozen=True)
class AlertHistoryClearResult:
    """Counts and recovery information from an alert-history purge."""

    alerts_deleted: int
    incidents_deleted: int
    replay_events_deleted: int
    backup_file: str
    cleared_at: str
    event_seq: int


def _positive_int(value: object, *, maximum: int | None = None) -> int | None:
    """Return a strict positive integer from persisted JSON data."""
    upper_bound = maximum if maximum is not None else _SQLITE_MAX_ROW_ID
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.strip().isascii():
        normalized = value.strip()
        if (
            not normalized.isdigit()
            or len(normalized) > len(str(upper_bound))
        ):
            return None
        parsed = int(normalized)
    else:
        return None
    if parsed < 1 or parsed > upper_bound:
        return None
    return parsed


def _json_value(value: object) -> object:
    """Decode a persisted JSON value without making history clearing fragile."""
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
        return None


def _port_risk_tombstones(
    rows: Iterable[Sequence[object]],
) -> set[tuple[int, str]]:
    """Recover every affected device+port represented by grouped alerts."""
    tombstones: set[tuple[int, str]] = set()
    for row in rows:
        affected_raw, detail_raw, alert_device_raw, issue_key_raw = row
        detail = _json_value(detail_raw)
        default_port = (
            _positive_int(detail.get("port"), maximum=65535)
            if isinstance(detail, dict)
            else None
        )
        if default_port is None and isinstance(issue_key_raw, str):
            default_port = _positive_int(
                issue_key_raw.rsplit(":", 1)[-1],
                maximum=65535,
            )

        affected = _json_value(affected_raw)
        row_added = False
        if isinstance(affected, list):
            for device in affected:
                if not isinstance(device, dict):
                    continue
                device_id = _positive_int(device.get("device_id"))
                port = _positive_int(
                    device.get("port"),
                    maximum=65535,
                )
                if port is None:
                    port = default_port
                if device_id is None or port is None:
                    continue
                tombstones.add((device_id, f"risky_port:{port}"))
                row_added = True

        # Pre-grouping alerts stored their one affected device on the alert.
        if not row_added:
            device_id = _positive_int(alert_device_raw)
            if device_id is not None and default_port is not None:
                tombstones.add((device_id, f"risky_port:{default_port}"))
    return tombstones


def _backfill_port_risk_tombstones(writer: sqlite3.Connection) -> None:
    """Persist clear tombstones for legacy alerts missing analyzer state."""
    rows = writer.execute(_PORT_RISK_ALERT_ROWS).fetchall()
    created_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    for device_id, insight_key in _port_risk_tombstones(rows):
        writer.execute(
            _UPSERT_CLEARED_PORT_RISK,
            (insight_key, created_at, device_id),
        )


async def _backfill_port_risk_tombstones_async(
    db: aiosqlite.Connection,
) -> None:
    """Async equivalent for shared in-memory test databases."""
    cursor = await db.execute(_PORT_RISK_ALERT_ROWS)
    rows = await cursor.fetchall()
    created_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    for device_id, insight_key in _port_risk_tombstones(rows):
        await db.execute(
            _UPSERT_CLEARED_PORT_RISK,
            (insight_key, created_at, device_id),
        )


def _prepare_backup_path(backup_dir: Path) -> Path:
    """Create the private backup directory and return a unique target path."""
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(backup_dir, 0o700)

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return backup_dir / f"alerts-before-clear-{timestamp}.sqlite3"


def _backup_connection(
    source: sqlite3.Connection,
    backup_path: Path,
) -> None:
    """Create and integrity-check a private SQLite backup."""
    target: sqlite3.Connection | None = None

    try:
        target = sqlite3.connect(str(backup_path))
        os.chmod(backup_path, 0o600)
        source.backup(target)
        target.commit()
        check = target.execute("PRAGMA quick_check").fetchone()
        if check is None or check[0] != "ok":
            raise RuntimeError("Alert history backup failed SQLite integrity check")
    except Exception:
        if target is not None:
            target.close()
            target = None
        backup_path.unlink(missing_ok=True)
        raise
    finally:
        if target is not None:
            target.close()


def _clear_file_database(
    database_path: Path,
    backup_dir: Path,
) -> AlertHistoryClearResult:
    """Back up and clear a file database under one write-exclusion window."""
    backup_path = _prepare_backup_path(backup_dir)
    writer = sqlite3.connect(
        str(database_path),
        timeout=30,
        isolation_level=None,
    )
    writer.execute("PRAGMA busy_timeout = 30000")
    writer.execute("PRAGMA foreign_keys = ON")

    source: sqlite3.Connection | None = None
    try:
        # Wait for any producer's pending commit, then prevent new writers.
        writer.execute("BEGIN IMMEDIATE")
        counts = writer.execute(
            f"""
            SELECT
                (SELECT COUNT(*) FROM home_alerts),
                (SELECT COUNT(*) FROM incidents),
                (SELECT COUNT(*) FROM events
                 WHERE event_type IN ({", ".join("?" for _ in _ALERT_EVENT_TYPES)}))
            """,
            _ALERT_EVENT_TYPES,
        ).fetchone()
        if counts is None:
            raise RuntimeError("Could not count alert history")

        # A second read connection can take a stable backup while the writer's
        # reserved lock prevents the snapshot from changing.
        source = sqlite3.connect(str(database_path), timeout=30)
        source.execute("PRAGMA busy_timeout = 30000")
        _backup_connection(source, backup_path)
        source.close()
        source = None

        placeholders = ", ".join("?" for _ in _ALERT_EVENT_TYPES)
        event_ids = (
            f"SELECT seq FROM events WHERE event_type IN ({placeholders})"
        )
        writer.execute(
            f"UPDATE decoy_connections SET event_seq = NULL "
            f"WHERE event_seq IN ({event_ids})",
            _ALERT_EVENT_TYPES,
        )
        writer.execute(
            f"UPDATE canary_observations SET event_seq = NULL "
            f"WHERE event_seq IN ({event_ids})",
            _ALERT_EVENT_TYPES,
        )
        _backfill_port_risk_tombstones(writer)
        writer.execute(
            "UPDATE security_insight_state SET alert_id = NULL "
            "WHERE alert_id IS NOT NULL"
        )
        writer.execute("DELETE FROM home_alerts")
        writer.execute("DELETE FROM incidents")
        writer.execute(
            f"DELETE FROM events WHERE event_type IN ({placeholders})",
            _ALERT_EVENT_TYPES,
        )

        cleared_at = datetime.now(UTC).isoformat()
        marker_payload = {
            "alerts_deleted": int(counts[0]),
            "incidents_deleted": int(counts[1]),
            "replay_events_deleted": int(counts[2]),
            "backup_file": backup_path.name,
            "cleared_at": cleared_at,
        }
        marker = writer.execute(
            """INSERT INTO events (event_type, payload, created_at)
               VALUES ('alerts.history_cleared', ?, ?)""",
            (json.dumps(marker_payload), cleared_at),
        )
        if marker.lastrowid is None:
            raise RuntimeError("Alert clear marker was not persisted")
        writer.commit()

        return AlertHistoryClearResult(
            alerts_deleted=int(counts[0]),
            incidents_deleted=int(counts[1]),
            replay_events_deleted=int(counts[2]),
            backup_file=backup_path.name,
            cleared_at=cleared_at,
            event_seq=int(marker.lastrowid),
        )
    except Exception:
        try:
            writer.rollback()
        except sqlite3.Error:
            pass
        logger.exception(
            "Alert history clear failed; recovery backup remains at %s",
            backup_path,
        )
        raise
    finally:
        if source is not None:
            source.close()
        writer.close()


async def _database_file(db: aiosqlite.Connection) -> Path | None:
    """Return the main database path, or None for an in-memory test database."""
    cursor = await db.execute("PRAGMA database_list")
    for row in await cursor.fetchall():
        if row[1] == "main" and row[2]:
            return Path(row[2])
    return None


async def _clear_shared_test_database(
    db: aiosqlite.Connection,
    backup_dir: Path,
) -> AlertHistoryClearResult:
    """In-memory fallback used by isolated route tests."""
    backup_path = _prepare_backup_path(backup_dir)
    target = sqlite3.connect(str(backup_path))
    try:
        os.chmod(backup_path, 0o600)
        await db.commit()
        await db.backup(target)
        target.commit()
        if target.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise RuntimeError("Alert history backup failed SQLite integrity check")
    finally:
        target.close()

    placeholders = ", ".join("?" for _ in _ALERT_EVENT_TYPES)
    try:
        await db.execute("BEGIN IMMEDIATE")
        counts_cursor = await db.execute(
            f"""
            SELECT
                (SELECT COUNT(*) FROM home_alerts),
                (SELECT COUNT(*) FROM incidents),
                (SELECT COUNT(*) FROM events
                 WHERE event_type IN ({placeholders}))
            """,
            _ALERT_EVENT_TYPES,
        )
        counts = await counts_cursor.fetchone()
        if counts is None:
            raise RuntimeError("Could not count alert history")

        event_ids = (
            f"SELECT seq FROM events WHERE event_type IN ({placeholders})"
        )
        await db.execute(
            f"UPDATE decoy_connections SET event_seq = NULL "
            f"WHERE event_seq IN ({event_ids})",
            _ALERT_EVENT_TYPES,
        )
        await db.execute(
            f"UPDATE canary_observations SET event_seq = NULL "
            f"WHERE event_seq IN ({event_ids})",
            _ALERT_EVENT_TYPES,
        )
        await _backfill_port_risk_tombstones_async(db)
        await db.execute(
            "UPDATE security_insight_state SET alert_id = NULL "
            "WHERE alert_id IS NOT NULL"
        )
        await db.execute("DELETE FROM home_alerts")
        await db.execute("DELETE FROM incidents")
        await db.execute(
            f"DELETE FROM events WHERE event_type IN ({placeholders})",
            _ALERT_EVENT_TYPES,
        )
        cleared_at = datetime.now(UTC).isoformat()
        payload = {
            "alerts_deleted": int(counts[0]),
            "incidents_deleted": int(counts[1]),
            "replay_events_deleted": int(counts[2]),
            "backup_file": backup_path.name,
            "cleared_at": cleared_at,
        }
        marker = await db.execute(
            """INSERT INTO events (event_type, payload, created_at)
               VALUES ('alerts.history_cleared', ?, ?)""",
            (json.dumps(payload), cleared_at),
        )
        await db.commit()
        if marker.lastrowid is None:
            raise RuntimeError("Alert clear marker was not persisted")
        return AlertHistoryClearResult(
            alerts_deleted=int(counts[0]),
            incidents_deleted=int(counts[1]),
            replay_events_deleted=int(counts[2]),
            backup_file=backup_path.name,
            cleared_at=cleared_at,
            event_seq=int(marker.lastrowid),
        )
    except Exception:
        await db.rollback()
        raise


async def clear_alert_history(
    db: aiosqlite.Connection,
    *,
    backup_dir: Path,
) -> AlertHistoryClearResult:
    """Back up the live database, then atomically clear alert history.

    Device inventory, decoys, scout profiles, configuration, and raw decoy
    connection records are deliberately preserved. Alert and incident replay
    events are removed so a reconnect cannot repopulate the app with deleted
    history.
    """
    async with _clear_lock:
        database_file = await _database_file(db)
        if database_file is None:
            result = await _clear_shared_test_database(db, backup_dir)
        else:
            result = await asyncio.to_thread(
                _clear_file_database,
                database_file,
                backup_dir,
            )
        logger.warning(
            "Cleared alert history: %d alerts, %d incidents, %d replay events; "
            "backup=%s",
            result.alerts_deleted,
            result.incidents_deleted,
            result.replay_events_deleted,
            backup_dir / result.backup_file,
        )
        return result
