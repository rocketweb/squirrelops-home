"""Schema version tracking and migration runner.

Checks the current schema version in the database and applies any pending
migrations in order. Version 0 means no schema exists yet.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import aiosqlite

from squirrelops_home_sensor.db.schema import SCHEMA_V1_SQL, SCHEMA_VERSION

logger = logging.getLogger(__name__)


async def _get_current_version(db: aiosqlite.Connection) -> int:
    """Return the current schema version, or 0 if the table does not exist."""
    cursor = await db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    )
    row = await cursor.fetchone()
    if row is None:
        return 0
    cursor = await db.execute("SELECT MAX(version) FROM schema_version")
    row = await cursor.fetchone()
    return row[0] if row and row[0] is not None else 0


async def _apply_v1(db: aiosqlite.Connection) -> None:
    """Apply schema version 1: create all initial tables and indexes."""
    await db.executescript(SCHEMA_V1_SQL)
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
        (1, now),
    )
    await db.commit()


async def _column_exists(db: aiosqlite.Connection, table: str, column: str) -> bool:
    """Check whether a column already exists in a table."""
    cursor = await db.execute(f"PRAGMA table_info({table})")
    rows = await cursor.fetchall()
    return any(row[1] == column for row in rows)


async def _apply_v2(db: aiosqlite.Connection) -> None:
    """Apply schema version 2: add model_name column to devices."""
    if not await _column_exists(db, "devices", "model_name"):
        await db.execute("ALTER TABLE devices ADD COLUMN model_name TEXT")
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
        (2, now),
    )
    await db.commit()


async def _apply_v3(db: aiosqlite.Connection) -> None:
    """V3: Add area column to devices table."""
    if not await _column_exists(db, "devices", "area"):
        await db.execute("ALTER TABLE devices ADD COLUMN area TEXT")
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
        (3, now),
    )
    await db.commit()


async def _table_exists(db: aiosqlite.Connection, table: str) -> bool:
    """Check whether a table already exists in the database."""
    cursor = await db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    )
    return await cursor.fetchone() is not None


async def _apply_v4(db: aiosqlite.Connection) -> None:
    """V4: Add device_open_ports and security_insight_state tables."""
    if not await _table_exists(db, "device_open_ports"):
        await db.executescript("""
            CREATE TABLE device_open_ports (
                id          INTEGER PRIMARY KEY,
                device_id   INTEGER NOT NULL REFERENCES devices(id),
                port        INTEGER NOT NULL,
                protocol    TEXT NOT NULL DEFAULT 'tcp',
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                UNIQUE(device_id, port, protocol)
            );
            CREATE INDEX idx_device_ports_device ON device_open_ports(device_id);
            CREATE INDEX idx_device_ports_port ON device_open_ports(port);
        """)

    if not await _table_exists(db, "security_insight_state"):
        await db.executescript("""
            CREATE TABLE security_insight_state (
                id          INTEGER PRIMARY KEY,
                device_id   INTEGER NOT NULL REFERENCES devices(id),
                insight_key TEXT NOT NULL,
                alert_id    INTEGER REFERENCES home_alerts(id),
                dismissed   INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL,
                resolved_at TEXT,
                UNIQUE(device_id, insight_key)
            );
            CREATE INDEX idx_insight_state_device ON security_insight_state(device_id);
            CREATE INDEX idx_insight_state_key ON security_insight_state(insight_key);
        """)

    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
        (4, now),
    )
    await db.commit()


async def _apply_v5(db: aiosqlite.Connection) -> None:
    """V5: Add service_name and banner columns to device_open_ports."""
    if not await _column_exists(db, "device_open_ports", "service_name"):
        await db.execute("ALTER TABLE device_open_ports ADD COLUMN service_name TEXT")
    if not await _column_exists(db, "device_open_ports", "banner"):
        await db.execute("ALTER TABLE device_open_ports ADD COLUMN banner TEXT")

    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
        (5, now),
    )
    await db.commit()


async def _apply_v6(db: aiosqlite.Connection) -> None:
    """V6: Add Squirrel Scouts tables -- service profiles, virtual IPs, mimic templates."""
    if not await _table_exists(db, "service_profiles"):
        await db.executescript("""
            CREATE TABLE service_profiles (
                id INTEGER PRIMARY KEY,
                device_id INTEGER NOT NULL REFERENCES devices(id),
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                service_name TEXT,
                http_status INTEGER,
                http_headers TEXT,
                http_body_snippet TEXT,
                http_server_header TEXT,
                favicon_hash TEXT,
                tls_cn TEXT,
                tls_issuer TEXT,
                tls_not_after TEXT,
                protocol_version TEXT,
                scouted_at TEXT NOT NULL,
                UNIQUE(device_id, port, protocol)
            );
            CREATE INDEX idx_svc_profiles_device ON service_profiles(device_id);
        """)

    if not await _table_exists(db, "virtual_ips"):
        await db.executescript("""
            CREATE TABLE virtual_ips (
                id INTEGER PRIMARY KEY,
                ip_address TEXT NOT NULL UNIQUE,
                interface TEXT NOT NULL DEFAULT 'en0',
                decoy_id INTEGER REFERENCES decoys(id),
                created_at TEXT NOT NULL,
                released_at TEXT
            );
        """)

    if not await _table_exists(db, "mimic_templates"):
        await db.executescript("""
            CREATE TABLE mimic_templates (
                id INTEGER PRIMARY KEY,
                source_device_id INTEGER REFERENCES devices(id),
                source_ip TEXT NOT NULL,
                device_category TEXT NOT NULL,
                routes_json TEXT NOT NULL,
                server_header TEXT,
                credential_types_json TEXT,
                mdns_service_type TEXT,
                mdns_name TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)

    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
        (6, now),
    )
    await db.commit()


async def _apply_v7(db: aiosqlite.Connection) -> None:
    """V7: Deduplicate historical security alerts.

    Before the security_insight_state dedup table was introduced (V4), the
    analyzer created a new alert for every scan cycle that found the same open
    port on the same device.  This migration removes those historical duplicates,
    keeping only the latest alert per unique (device_id, alert_type, title)
    combination.  Insight state entries already point to the latest alert so
    they remain valid after the cleanup.
    """
    # Step 1: Count duplicates so we can log useful info
    cursor = await db.execute("""
        SELECT COUNT(*) FROM home_alerts
        WHERE incident_id IS NULL
        AND id NOT IN (
            SELECT MAX(id) FROM home_alerts
            WHERE incident_id IS NULL
            GROUP BY device_id, alert_type, title
        )
    """)
    row = await cursor.fetchone()
    dup_count = row[0] if row else 0

    if dup_count > 0:
        # Step 2: Delete duplicate standalone alerts, keeping only the latest
        await db.execute("""
            DELETE FROM home_alerts
            WHERE incident_id IS NULL
            AND id NOT IN (
                SELECT MAX(id) FROM home_alerts
                WHERE incident_id IS NULL
                GROUP BY device_id, alert_type, title
            )
        """)

        # Step 3: Clean up any orphaned insight_state entries that may reference
        # deleted alerts (shouldn't happen since we keep the MAX id, but be safe)
        await db.execute("""
            DELETE FROM security_insight_state
            WHERE alert_id IS NOT NULL
            AND alert_id NOT IN (SELECT id FROM home_alerts)
        """)

        logger.info(
            "V7 migration: removed %d duplicate alerts, keeping latest per condition",
            dup_count,
        )

    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
        (7, now),
    )
    await db.commit()


async def _apply_v8(db: aiosqlite.Connection) -> None:
    """V8: Alert grouping by issue type.

    Adds columns for grouped alerts (issue_key, affected_devices, device_count,
    risk_description, remediation) and consolidates existing per-device
    security.port_risk alerts into one grouped alert per issue type.
    """
    import json

    # -- Schema additions --
    if not await _column_exists(db, "home_alerts", "issue_key"):
        await db.execute("ALTER TABLE home_alerts ADD COLUMN issue_key TEXT")
    if not await _column_exists(db, "home_alerts", "affected_devices"):
        await db.execute("ALTER TABLE home_alerts ADD COLUMN affected_devices TEXT")
    if not await _column_exists(db, "home_alerts", "device_count"):
        await db.execute(
            "ALTER TABLE home_alerts ADD COLUMN device_count INTEGER DEFAULT 1"
        )
    if not await _column_exists(db, "home_alerts", "risk_description"):
        await db.execute("ALTER TABLE home_alerts ADD COLUMN risk_description TEXT")
    if not await _column_exists(db, "home_alerts", "remediation"):
        await db.execute("ALTER TABLE home_alerts ADD COLUMN remediation TEXT")

    # Index for fast issue_key lookups
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_issue_key "
        "ON home_alerts(issue_key) WHERE issue_key IS NOT NULL"
    )
    await db.commit()

    # -- Data migration: consolidate per-device alerts into grouped alerts --
    cursor = await db.execute(
        "SELECT * FROM home_alerts WHERE alert_type = 'security.port_risk' "
        "AND issue_key IS NULL ORDER BY created_at DESC"
    )
    rows = await cursor.fetchall()

    if rows:
        # Group alerts by (port, service_name) extracted from detail JSON
        groups: dict[str, list[dict]] = {}
        for row in rows:
            detail = row["detail"]
            if isinstance(detail, str):
                try:
                    detail = json.loads(detail)
                except (json.JSONDecodeError, TypeError):
                    detail = {}
            if not isinstance(detail, dict):
                detail = {}

            port = detail.get("port")
            service_name = detail.get("service_name", "")

            # Build issue key matching the new logic
            service_slug = service_name.lower().replace(" ", "_")
            if "unencrypted" in service_slug:
                issue_key = "port_risk:unencrypted_admin"
            elif port is not None:
                issue_key = f"port_risk:{service_slug}:{port}"
            else:
                continue

            groups.setdefault(issue_key, []).append(dict(row))

        for issue_key, alert_rows in groups.items():
            # First row is the latest (ORDER BY created_at DESC)
            winner = alert_rows[0]
            winner_id = winner["id"]

            # Build affected_devices from all alerts in this group
            affected = []
            seen_device_ids: set[int] = set()
            for a in alert_rows:
                detail = a["detail"]
                if isinstance(detail, str):
                    try:
                        detail = json.loads(detail)
                    except (json.JSONDecodeError, TypeError):
                        detail = {}
                did = a.get("device_id") or detail.get("device_id")
                if did and did not in seen_device_ids:
                    seen_device_ids.add(did)
                    svc = detail.get("service_name", "")
                    title_str = a.get("title", "")
                    display = title_str.replace(f"{svc} open on ", "") if svc else title_str
                    affected.append({
                        "device_id": did,
                        "ip_address": a.get("source_ip", ""),
                        "mac_address": a.get("source_mac"),
                        "display_name": display,
                        "port": detail.get("port", 0),
                    })

            # Extract risk info from winner's detail
            winner_detail = winner["detail"]
            if isinstance(winner_detail, str):
                try:
                    winner_detail = json.loads(winner_detail)
                except (json.JSONDecodeError, TypeError):
                    winner_detail = {}
            risk_desc = winner_detail.get("risk_description", "")
            remediation_text = winner_detail.get("remediation_steps", "")

            # Compute new title
            service_name = winner_detail.get("service_name", "Unknown")
            n = len(affected)
            new_title = f"{service_name} open on {n} device{'s' if n > 1 else ''}"

            # Update the winner alert with grouped data
            await db.execute(
                "UPDATE home_alerts SET "
                "issue_key = ?, affected_devices = ?, device_count = ?, "
                "risk_description = ?, remediation = ?, title = ?, "
                "source_ip = NULL, source_mac = NULL, device_id = NULL "
                "WHERE id = ?",
                (
                    issue_key,
                    json.dumps(affected),
                    n,
                    risk_desc,
                    remediation_text,
                    new_title,
                    winner_id,
                ),
            )

            # Delete non-winner alerts and update insight_state references
            non_winner_ids = [a["id"] for a in alert_rows if a["id"] != winner_id]
            if non_winner_ids:
                placeholders = ",".join("?" * len(non_winner_ids))
                await db.execute(
                    f"DELETE FROM home_alerts WHERE id IN ({placeholders})",
                    non_winner_ids,
                )
                await db.execute(
                    f"UPDATE security_insight_state SET alert_id = ? "
                    f"WHERE alert_id IN ({placeholders})",
                    [winner_id] + non_winner_ids,
                )

        await db.commit()
        logger.info(
            "V8 migration: consolidated %d per-device alerts into %d grouped alerts",
            len(rows),
            len(groups),
        )

    # -- Clean stale alert events from the events replay table --
    # Old alert.new/alert.updated events referencing deleted alerts would
    # cause the app to re-add per-device alerts during WebSocket replay.
    await db.execute(
        "DELETE FROM events WHERE event_type IN ('alert.new', 'alert.updated') "
        "AND json_extract(payload, '$.id') NOT IN (SELECT id FROM home_alerts)"
    )
    await db.commit()

    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
        (8, now),
    )
    await db.commit()


# Ordered list of migration functions. Index 0 = migration to version 1.
_MIGRATIONS: list[tuple[int, callable]] = [
    (1, _apply_v1),
    (2, _apply_v2),
    (3, _apply_v3),
    (4, _apply_v4),
    (5, _apply_v5),
    (6, _apply_v6),
    (7, _apply_v7),
    (8, _apply_v8),
]


async def apply_migrations(db: aiosqlite.Connection) -> None:
    """Apply all pending migrations to bring the database to the current version.

    Safe to call multiple times -- skips already-applied migrations.
    """
    current = await _get_current_version(db)

    if current >= SCHEMA_VERSION:
        return

    for target_version, migrate_fn in _MIGRATIONS:
        if current < target_version:
            await migrate_fn(db)
            current = target_version
