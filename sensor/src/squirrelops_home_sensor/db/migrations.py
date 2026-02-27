"""Schema version tracking and migration runner.

Checks the current schema version in the database and applies any pending
migrations in order. Version 0 means no schema exists yet.
"""

from __future__ import annotations

from datetime import datetime, timezone

import aiosqlite

from squirrelops_home_sensor.db.schema import SCHEMA_V1_SQL, SCHEMA_VERSION


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


# Ordered list of migration functions. Index 0 = migration to version 1.
_MIGRATIONS: list[tuple[int, callable]] = [
    (1, _apply_v1),
    (2, _apply_v2),
    (3, _apply_v3),
    (4, _apply_v4),
    (5, _apply_v5),
    (6, _apply_v6),
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
