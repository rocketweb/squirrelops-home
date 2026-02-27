"""Integration tests for database schema creation and migrations."""

from __future__ import annotations

import asyncio

import aiosqlite
import pytest


from squirrelops_home_sensor.db.schema import (
    SCHEMA_VERSION,
    get_all_table_names,
)
from squirrelops_home_sensor.db.migrations import apply_migrations


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_tables(db: aiosqlite.Connection) -> set[str]:
    """Return the set of user table names in the database."""
    cursor = await db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    )
    rows = await cursor.fetchall()
    return {row[0] for row in rows}


async def _get_indexes(db: aiosqlite.Connection) -> set[str]:
    """Return the set of user index names in the database."""
    cursor = await db.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
    )
    rows = await cursor.fetchall()
    return {row[0] for row in rows}


async def _get_schema_version(db: aiosqlite.Connection) -> int:
    """Return the current schema version from the schema_version table."""
    cursor = await db.execute("SELECT MAX(version) FROM schema_version")
    row = await cursor.fetchone()
    return row[0] if row and row[0] is not None else 0


async def _table_has_column(
    db: aiosqlite.Connection, table: str, column: str
) -> bool:
    """Check whether a table has a specific column."""
    cursor = await db.execute(f"PRAGMA table_info({table})")
    rows = await cursor.fetchall()
    return any(row[1] == column for row in rows)


async def _get_foreign_keys(
    db: aiosqlite.Connection, table: str
) -> list[tuple[str, str, str]]:
    """Return list of (from_col, to_table, to_col) for a table's foreign keys."""
    cursor = await db.execute(f"PRAGMA foreign_key_list({table})")
    rows = await cursor.fetchall()
    # PRAGMA foreign_key_list columns: id, seq, table, from, to, on_update, on_delete, match
    return [(row[3], row[2], row[4]) for row in rows]


# ---------------------------------------------------------------------------
# Tests: Fresh database creation
# ---------------------------------------------------------------------------

class TestFreshDatabase:
    """Test creating the schema on a brand-new empty database."""

    @pytest.mark.asyncio
    async def test_apply_migrations_creates_all_tables(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)

            tables = await _get_tables(db)
            expected = {
                "events",
                "device_fingerprints",
                "device_trust",
                "incidents",
                "home_alerts",
                "decoys",
                "planted_credentials",
                "decoy_connections",
                "pairing",
                "canary_observations",
                "schema_version",
            }
            for table in expected:
                assert table in tables, f"Missing table: {table}"

    @pytest.mark.asyncio
    async def test_schema_version_is_set(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            version = await _get_schema_version(db)
            assert version == SCHEMA_VERSION

    @pytest.mark.asyncio
    async def test_all_table_names_helper(self) -> None:
        names = get_all_table_names()
        assert "events" in names
        assert "schema_version" in names
        assert len(names) == 13

    @pytest.mark.asyncio
    async def test_idempotent_migration(self) -> None:
        """Running apply_migrations twice should not raise or duplicate data."""
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            await apply_migrations(db)
            version = await _get_schema_version(db)
            assert version == SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Tests: Table structures
# ---------------------------------------------------------------------------

class TestEventsTable:
    """Verify the events table structure."""

    @pytest.mark.asyncio
    async def test_events_has_autoincrement_pk(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            # Insert and verify autoincrement behavior
            await db.execute(
                "INSERT INTO events (event_type, payload) VALUES ('test', '{}')"
            )
            await db.execute(
                "INSERT INTO events (event_type, payload) VALUES ('test2', '{}')"
            )
            cursor = await db.execute("SELECT seq FROM events ORDER BY seq")
            rows = await cursor.fetchall()
            assert rows[0][0] == 1
            assert rows[1][0] == 2

    @pytest.mark.asyncio
    async def test_events_has_required_columns(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            for col in ["seq", "event_type", "payload", "source_id", "created_at"]:
                assert await _table_has_column(db, "events", col), (
                    f"events missing column: {col}"
                )

    @pytest.mark.asyncio
    async def test_events_created_at_default(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            await db.execute(
                "INSERT INTO events (event_type, payload) VALUES ('test', '{}')"
            )
            cursor = await db.execute("SELECT created_at FROM events WHERE seq = 1")
            row = await cursor.fetchone()
            assert row is not None
            assert row[0] is not None  # Default should have populated


class TestDeviceFingerprintsTable:
    """Verify the device_fingerprints table structure."""

    @pytest.mark.asyncio
    async def test_has_required_columns(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            expected_cols = [
                "id", "device_id", "mac_address", "mdns_hostname",
                "dhcp_fingerprint_hash", "connection_pattern_hash",
                "open_ports_hash", "composite_hash", "signal_count",
                "confidence", "first_seen", "last_seen",
            ]
            for col in expected_cols:
                assert await _table_has_column(db, "device_fingerprints", col), (
                    f"device_fingerprints missing column: {col}"
                )


class TestDeviceTrustTable:
    """Verify the device_trust table structure."""

    @pytest.mark.asyncio
    async def test_has_required_columns(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            for col in ["device_id", "status", "approved_by", "updated_at"]:
                assert await _table_has_column(db, "device_trust", col)

    @pytest.mark.asyncio
    async def test_status_check_constraint(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = OFF")
            await apply_migrations(db)
            with pytest.raises(Exception):
                await db.execute(
                    "INSERT INTO device_trust (device_id, status, updated_at) "
                    "VALUES (1, 'invalid_status', '2025-01-01T00:00:00Z')"
                )


class TestIncidentsTable:
    """Verify the incidents table structure."""

    @pytest.mark.asyncio
    async def test_has_required_columns(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            expected = [
                "id", "source_ip", "source_mac", "status", "severity",
                "alert_count", "first_alert_at", "last_alert_at",
                "closed_at", "summary",
            ]
            for col in expected:
                assert await _table_has_column(db, "incidents", col)

    @pytest.mark.asyncio
    async def test_status_check_constraint(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = OFF")
            await apply_migrations(db)
            with pytest.raises(Exception):
                await db.execute(
                    "INSERT INTO incidents (source_ip, status, severity, "
                    "first_alert_at, last_alert_at) "
                    "VALUES ('1.2.3.4', 'bogus', 'high', '2025-01-01', '2025-01-01')"
                )

    @pytest.mark.asyncio
    async def test_severity_check_constraint(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = OFF")
            await apply_migrations(db)
            with pytest.raises(Exception):
                await db.execute(
                    "INSERT INTO incidents (source_ip, status, severity, "
                    "first_alert_at, last_alert_at) "
                    "VALUES ('1.2.3.4', 'active', 'bogus', '2025-01-01', '2025-01-01')"
                )


class TestHomeAlertsTable:
    """Verify the home_alerts table structure."""

    @pytest.mark.asyncio
    async def test_has_required_columns(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            expected = [
                "id", "incident_id", "alert_type", "severity", "title",
                "detail", "source_ip", "source_mac", "device_id",
                "decoy_id", "read_at", "actioned_at", "event_seq", "created_at",
            ]
            for col in expected:
                assert await _table_has_column(db, "home_alerts", col)

    @pytest.mark.asyncio
    async def test_foreign_key_to_incidents(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            fks = await _get_foreign_keys(db, "home_alerts")
            fk_tables = [fk[1] for fk in fks]
            assert "incidents" in fk_tables


class TestDecoysTable:
    """Verify the decoys table structure."""

    @pytest.mark.asyncio
    async def test_has_required_columns(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            expected = [
                "id", "name", "decoy_type", "bind_address", "port",
                "status", "config", "connection_count",
                "credential_trip_count", "failure_count",
                "last_failure_at", "created_at", "updated_at",
            ]
            for col in expected:
                assert await _table_has_column(db, "decoys", col)

    @pytest.mark.asyncio
    async def test_status_check_constraint(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = OFF")
            await apply_migrations(db)
            with pytest.raises(Exception):
                await db.execute(
                    "INSERT INTO decoys (name, decoy_type, bind_address, port, "
                    "status, created_at, updated_at) "
                    "VALUES ('test', 'dev_server', '0.0.0.0', 3000, "
                    "'bogus', '2025-01-01', '2025-01-01')"
                )


class TestPlantedCredentialsTable:
    """Verify the planted_credentials table structure."""

    @pytest.mark.asyncio
    async def test_has_required_columns(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            expected = [
                "id", "credential_type", "credential_value",
                "canary_hostname", "planted_location", "decoy_id",
                "tripped", "first_tripped_at", "created_at",
            ]
            for col in expected:
                assert await _table_has_column(db, "planted_credentials", col)

    @pytest.mark.asyncio
    async def test_foreign_key_to_decoys(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            fks = await _get_foreign_keys(db, "planted_credentials")
            fk_tables = [fk[1] for fk in fks]
            assert "decoys" in fk_tables


class TestDecoyConnectionsTable:
    """Verify the decoy_connections table structure."""

    @pytest.mark.asyncio
    async def test_has_required_columns(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            expected = [
                "id", "decoy_id", "source_ip", "source_mac", "port",
                "protocol", "request_path", "credential_used",
                "credential_id", "event_seq", "timestamp",
            ]
            for col in expected:
                assert await _table_has_column(db, "decoy_connections", col)

    @pytest.mark.asyncio
    async def test_foreign_key_to_decoys(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            fks = await _get_foreign_keys(db, "decoy_connections")
            fk_tables = [fk[1] for fk in fks]
            assert "decoys" in fk_tables


class TestPairingTable:
    """Verify the pairing table structure."""

    @pytest.mark.asyncio
    async def test_has_required_columns(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            expected = [
                "id", "client_name", "client_cert_fingerprint",
                "is_local", "paired_at", "last_connected_at",
            ]
            for col in expected:
                assert await _table_has_column(db, "pairing", col)


class TestCanaryObservationsTable:
    """Verify the canary_observations table structure."""

    @pytest.mark.asyncio
    async def test_has_required_columns(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            expected = [
                "id", "credential_id", "canary_hostname",
                "queried_by_ip", "queried_by_mac", "event_seq", "observed_at",
            ]
            for col in expected:
                assert await _table_has_column(db, "canary_observations", col)

    @pytest.mark.asyncio
    async def test_foreign_key_to_planted_credentials(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            fks = await _get_foreign_keys(db, "canary_observations")
            fk_tables = [fk[1] for fk in fks]
            assert "planted_credentials" in fk_tables


# ---------------------------------------------------------------------------
# Tests: Indexes
# ---------------------------------------------------------------------------

class TestIndexes:
    """Verify all expected indexes are created."""

    @pytest.mark.asyncio
    async def test_all_indexes_created(self) -> None:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await apply_migrations(db)
            indexes = await _get_indexes(db)
            expected_indexes = {
                "idx_events_type",
                "idx_events_created",
                "idx_fp_device",
                "idx_fp_composite",
                "idx_incidents_source",
                "idx_incidents_active",
                "idx_alerts_severity",
                "idx_alerts_type",
                "idx_alerts_created",
                "idx_alerts_incident",
                "idx_alerts_unread",
                "idx_creds_canary",
                "idx_creds_value",
                "idx_conn_decoy",
                "idx_conn_source",
                "idx_canary_hostname",
            }
            for idx in expected_indexes:
                assert idx in indexes, f"Missing index: {idx}"
