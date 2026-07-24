"""Integration tests for database schema creation and migrations."""

from __future__ import annotations

import aiosqlite
import pytest

from squirrelops_home_sensor.db import migrations as db_migrations
from squirrelops_home_sensor.db.migrations import apply_migrations
from squirrelops_home_sensor.db.schema import (
    SCHEMA_VERSION,
    get_all_table_names,
)

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


async def _apply_through_v8(db: aiosqlite.Connection) -> None:
    """Build the exact pre-V9 schema for migration regressions."""
    for version, migration in db_migrations._MIGRATIONS:
        if version >= 9:
            break
        await migration(db)


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
        assert "decoy_hosts" in names
        assert "schema_version" in names
        assert len(names) == 19

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
            rows = list(await cursor.fetchall())
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


class TestV9MimicMigration:
    """Verify legacy fake hosts migrate without unsafe bindings or lost evidence."""

    @pytest.mark.asyncio
    async def test_unspecified_legacy_binding_is_retired_and_released(
        self,
    ) -> None:
        async with aiosqlite.connect(":memory:") as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA foreign_keys = ON")
            await _apply_through_v8(db)
            await db.execute(
                """INSERT INTO decoys
                   (name, decoy_type, bind_address, port, status, config,
                    created_at, updated_at)
                   VALUES ('broken.local', 'mimic', '0.0.0.0', 8080,
                           'active', '{}', '2026-01-01', '2026-01-01')"""
            )
            decoy_id = (await (
                await db.execute("SELECT id FROM decoys")
            ).fetchone())["id"]
            await db.execute(
                """INSERT INTO virtual_ips
                   (ip_address, interface, decoy_id, created_at)
                   VALUES ('0.0.0.0', 'en0', ?, '2026-01-01')""",
                (decoy_id,),
            )
            await db.commit()

            await db_migrations._apply_v9(db)

            service = await (
                await db.execute(
                    """SELECT status, retired_at, retirement_reason
                       FROM decoys WHERE id = ?""",
                    (decoy_id,),
                )
            ).fetchone()
            host = await (
                await db.execute(
                    """SELECT retired_at, retirement_reason
                       FROM decoy_hosts WHERE bind_address = '0.0.0.0'"""
                )
            ).fetchone()
            assert service["status"] == "stopped"
            assert service["retired_at"] is not None
            assert service["retirement_reason"] == (
                "invalid_legacy_bind_address"
            )
            assert host["retired_at"] is not None
            assert host["retirement_reason"] == (
                "invalid_legacy_bind_address"
            )
            assert await (
                await db.execute(
                    "SELECT id FROM virtual_ips WHERE ip_address = '0.0.0.0'"
                )
            ).fetchone() is None

    @pytest.mark.asyncio
    async def test_partial_overlap_remaps_evidence_without_deleting_history(
        self,
    ) -> None:
        async with aiosqlite.connect(":memory:") as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA foreign_keys = ON")
            await _apply_through_v8(db)
            common = (
                "legacy.local",
                "mimic",
                "192.168.1.200",
                "active",
                "2026-01-01",
                "2026-01-01",
            )
            first = await db.execute(
                """INSERT INTO decoys
                   (name, decoy_type, bind_address, port, status, config,
                    connection_count, credential_trip_count,
                    created_at, updated_at)
                   VALUES (?, ?, ?, 80, ?, ?, 0, 0, ?, ?)""",
                (*common[:4], '{"port_configs":[{"port":80}]}', *common[4:]),
            )
            second = await db.execute(
                """INSERT INTO decoys
                   (name, decoy_type, bind_address, port, status, config,
                    connection_count, credential_trip_count,
                    created_at, updated_at)
                   VALUES (?, ?, ?, 80, ?, ?, 2, 1, ?, ?)""",
                (
                    *common[:4],
                    (
                        '{"port_configs":['
                        '{"port":80},{"port":443,"tls":true}]}'
                    ),
                    *common[4:],
                ),
            )
            primary_id = int(first.lastrowid)
            overlap_id = int(second.lastrowid)
            credential = await db.execute(
                """INSERT INTO planted_credentials
                   (credential_type, credential_value, planted_location,
                    decoy_id, created_at)
                   VALUES ('password', 'secret', '/passwords.txt', ?,
                           '2026-01-01')""",
                (overlap_id,),
            )
            credential_id = int(credential.lastrowid)
            await db.execute(
                """INSERT INTO decoy_connections
                   (decoy_id, source_ip, port, protocol, timestamp)
                   VALUES (?, '192.168.1.50', 80, 'tcp', '2026-01-01')""",
                (overlap_id,),
            )
            await db.execute(
                """INSERT INTO decoy_connections
                   (decoy_id, source_ip, port, protocol, credential_used,
                    credential_id, timestamp)
                   VALUES (?, '192.168.1.50', 443, 'tcp', 'secret', ?,
                           '2026-01-01')""",
                (overlap_id, credential_id),
            )
            incident = await db.execute(
                """INSERT INTO incidents
                   (source_ip, severity, first_alert_at, last_alert_at)
                   VALUES ('192.168.1.50', 'high', '2026-01-01',
                           '2026-01-01')"""
            )
            incident_id = int(incident.lastrowid)
            for title, detail in (
                ("HTTP", '{"dest_port":80,"protocol":"tcp"}'),
                ("HTTPS", '{"dest_port":443,"protocol":"tcp"}'),
                ("Malformed", "{not-json"),
                (
                    "NonInteger",
                    '{"dest_port":"443oops","protocol":"tcp"}',
                ),
            ):
                await db.execute(
                    """INSERT INTO home_alerts
                       (incident_id, alert_type, severity, title, detail,
                        decoy_id, created_at)
                       VALUES (?, 'decoy_trip', 'high', ?, ?, ?,
                               '2026-01-01')""",
                    (incident_id, title, detail, overlap_id),
                )
            await db.commit()

            await db_migrations._apply_v9(db)

            services = list(await (
                await db.execute(
                    """SELECT id, port, connection_count,
                              credential_trip_count
                       FROM decoys
                       WHERE bind_address = '192.168.1.200'
                       ORDER BY port"""
                )
            ).fetchall())
            assert [
                (
                    row["id"],
                    row["port"],
                    row["connection_count"],
                    row["credential_trip_count"],
                )
                for row in services
            ] == [
                (primary_id, 80, 1, 0),
                (overlap_id, 443, 1, 1),
            ]
            connections = list(await (
                await db.execute(
                    """SELECT port, decoy_id
                       FROM decoy_connections ORDER BY port"""
                )
            ).fetchall())
            assert [(row["port"], row["decoy_id"]) for row in connections] == [
                (80, primary_id),
                (443, overlap_id),
            ]
            alerts = list(await (
                await db.execute(
                    "SELECT title, decoy_id, incident_id FROM home_alerts"
                )
            ).fetchall())
            assert {
                row["title"]: (row["decoy_id"], row["incident_id"])
                for row in alerts
            } == {
                "HTTP": (primary_id, incident_id),
                "HTTPS": (overlap_id, incident_id),
                "Malformed": (primary_id, incident_id),
                "NonInteger": (primary_id, incident_id),
            }
            owner = await (
                await db.execute(
                    """SELECT decoy_id FROM planted_credentials
                       WHERE id = ?""",
                    (credential_id,),
                )
            ).fetchone()
            assert owner["decoy_id"] == primary_id

    @pytest.mark.asyncio
    async def test_full_overlap_dispatches_evidence_to_retained_services(
        self,
    ) -> None:
        async with aiosqlite.connect(":memory:") as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA foreign_keys = ON")
            await _apply_through_v8(db)
            config = (
                '{"port_configs":['
                '{"port":80,"protocol":"tcp"},'
                '{"port":443,"protocol":"tcp","tls":true}]}'
            )
            first = await db.execute(
                """INSERT INTO decoys
                   (name, decoy_type, bind_address, port, status, config,
                    connection_count, credential_trip_count,
                    created_at, updated_at)
                   VALUES ('legacy.local', 'mimic', '192.168.1.200', 80,
                           'active', ?, 1, 0, '2026-01-01',
                           '2026-01-01')""",
                (config,),
            )
            duplicate = await db.execute(
                """INSERT INTO decoys
                   (name, decoy_type, bind_address, port, status, config,
                    connection_count, credential_trip_count,
                    created_at, updated_at)
                   VALUES ('legacy.local', 'mimic', '192.168.1.200', 80,
                           'active', ?, 3, 1, '2026-01-01',
                           '2026-01-01')""",
                (config,),
            )
            primary_id = int(first.lastrowid)
            duplicate_id = int(duplicate.lastrowid)
            await db.execute(
                """INSERT INTO decoy_connections
                   (decoy_id, source_ip, port, protocol, timestamp)
                   VALUES (?, '192.168.1.50', 80, 'tcp', '2026-01-01')""",
                (primary_id,),
            )
            credential = await db.execute(
                """INSERT INTO planted_credentials
                   (credential_type, credential_value, planted_location,
                    decoy_id, created_at)
                   VALUES ('password', 'secret', '/passwords.txt', ?,
                           '2026-01-01')""",
                (duplicate_id,),
            )
            credential_id = int(credential.lastrowid)
            await db.execute(
                """INSERT INTO decoy_connections
                   (decoy_id, source_ip, port, protocol, credential_used,
                    credential_id, timestamp)
                   VALUES (?, '192.168.1.51', 443, 'tcp', 'secret', ?,
                           '2026-01-01')""",
                (duplicate_id, credential_id),
            )
            await db.execute(
                """INSERT INTO decoy_connections
                   (decoy_id, source_ip, port, protocol, timestamp)
                   VALUES (?, '192.168.1.52', 9999, 'tcp', '2026-01-01')""",
                (duplicate_id,),
            )
            for title, detail in (
                ("HTTPS", '{"dest_port":443,"protocol":"tcp"}'),
                ("Unknown", '{"dest_port":9999,"protocol":"tcp"}'),
                ("Malformed", "{not-json"),
            ):
                await db.execute(
                    """INSERT INTO home_alerts
                       (alert_type, severity, title, detail, decoy_id,
                        created_at)
                       VALUES ('decoy_trip', 'high', ?, ?, ?,
                               '2026-01-01')""",
                    (title, detail, duplicate_id),
                )
            await db.execute(
                """INSERT INTO virtual_ips
                   (ip_address, interface, decoy_id, created_at)
                   VALUES ('192.168.1.200', 'en0', ?, '2026-01-01')""",
                (duplicate_id,),
            )
            await db.commit()

            await db_migrations._apply_v9(db)

            services = list(await (
                await db.execute(
                    """SELECT id, port, connection_count,
                              credential_trip_count
                       FROM decoys
                       WHERE bind_address = '192.168.1.200'
                       ORDER BY port"""
                )
            ).fetchall())
            assert len(services) == 2
            service_ids = {
                int(row["port"]): int(row["id"])
                for row in services
            }
            assert service_ids[80] == primary_id
            assert [
                (
                    int(row["port"]),
                    int(row["connection_count"]),
                    int(row["credential_trip_count"]),
                )
                for row in services
            ] == [(80, 3, 0), (443, 1, 1)]

            connections = list(await (
                await db.execute(
                    """SELECT port, decoy_id
                       FROM decoy_connections ORDER BY id"""
                )
            ).fetchall())
            assert [
                (int(row["port"]), int(row["decoy_id"]))
                for row in connections
            ] == [
                (80, service_ids[80]),
                (443, service_ids[443]),
                (9999, service_ids[80]),
            ]
            alerts = list(await (
                await db.execute(
                    "SELECT title, decoy_id FROM home_alerts ORDER BY id"
                )
            ).fetchall())
            assert {
                row["title"]: int(row["decoy_id"])
                for row in alerts
            } == {
                "HTTPS": service_ids[443],
                "Unknown": service_ids[80],
                "Malformed": service_ids[80],
            }
            credential_owner = await (
                await db.execute(
                    """SELECT decoy_id FROM planted_credentials
                       WHERE id = ?""",
                    (credential_id,),
                )
            ).fetchone()
            assert int(credential_owner["decoy_id"]) == service_ids[80]
            virtual_ip = await (
                await db.execute(
                    """SELECT decoy_id FROM virtual_ips
                       WHERE ip_address = '192.168.1.200'"""
                )
            ).fetchone()
            assert int(virtual_ip["decoy_id"]) == service_ids[80]

    @pytest.mark.asyncio
    async def test_full_overlap_keeps_ambiguous_service_evidence_primary(
        self,
    ) -> None:
        async with aiosqlite.connect(":memory:") as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA foreign_keys = ON")
            await _apply_through_v8(db)
            config = (
                '{"port_configs":['
                '{"port":80,"protocol":"tcp"},'
                '{"port":443,"protocol":"tcp","tls":true},'
                '{"port":443,"protocol":"udp"},'
                '{"port":8443,"protocol":"tcp","tls":true}]}'
            )
            first = await db.execute(
                """INSERT INTO decoys
                   (name, decoy_type, bind_address, port, status, config,
                    created_at, updated_at)
                   VALUES ('legacy.local', 'mimic', '192.168.1.200', 80,
                           'active', ?, '2026-01-01', '2026-01-01')""",
                (config,),
            )
            duplicate = await db.execute(
                """INSERT INTO decoys
                   (name, decoy_type, bind_address, port, status, config,
                    connection_count, created_at, updated_at)
                   VALUES ('legacy.local', 'mimic', '192.168.1.200', 80,
                           'active', ?, 4, '2026-01-01',
                           '2026-01-01')""",
                (config,),
            )
            primary_id = int(first.lastrowid)
            duplicate_id = int(duplicate.lastrowid)
            subset = await db.execute(
                """INSERT INTO decoys
                   (name, decoy_type, bind_address, port, status, config,
                    connection_count, created_at, updated_at)
                   VALUES ('legacy.local', 'mimic', '192.168.1.200', 443,
                           'active', ?, 1, '2026-01-01', '2026-01-01')""",
                (
                    '{"port_configs":['
                    '{"port":443,"protocol":"tcp"}]}',
                ),
            )
            subset_id = int(subset.lastrowid)
            for port, protocol in (
                (443, None),
                (443, "tcp"),
                (443, "udp"),
                (8443, None),
            ):
                await db.execute(
                    """INSERT INTO decoy_connections
                       (decoy_id, source_ip, port, protocol, timestamp)
                       VALUES (?, '192.168.1.50', ?, ?, '2026-01-01')""",
                    (duplicate_id, port, protocol),
                )
            await db.execute(
                """INSERT INTO decoy_connections
                   (decoy_id, source_ip, port, protocol, timestamp)
                   VALUES (?, '192.168.1.51', 443, NULL, '2026-01-01')""",
                (subset_id,),
            )
            for title, detail in (
                ("Ambiguous", '{"dest_port":443}'),
                ("TCP", '{"dest_port":443,"protocol":"tcp"}'),
                ("UDP", '{"dest_port":443,"protocol":"udp"}'),
                ("Single", '{"dest_port":8443}'),
                ("Real", '{"dest_port":443.9,"protocol":"tcp"}'),
                ("Prefix", '{"dest_port":"443oops","protocol":"tcp"}'),
                ("String", '{"dest_port":"443","protocol":"tcp"}'),
                ("Fallback", '{"port":443,"protocol":"tcp"}'),
            ):
                await db.execute(
                    """INSERT INTO home_alerts
                       (alert_type, severity, title, detail, decoy_id,
                        created_at)
                       VALUES ('decoy_trip', 'high', ?, ?, ?,
                               '2026-01-01')""",
                    (title, detail, duplicate_id),
                )
            await db.execute(
                """INSERT INTO home_alerts
                   (alert_type, severity, title, detail, decoy_id,
                    created_at)
                   VALUES ('decoy_trip', 'high', 'SubsetAmbiguous',
                           '{"dest_port":443}', ?, '2026-01-01')""",
                (subset_id,),
            )
            await db.commit()

            await db_migrations._apply_v9(db)

            services = list(await (
                await db.execute(
                    """SELECT id, port, protocol, connection_count
                       FROM decoys
                       WHERE bind_address = '192.168.1.200'"""
                )
            ).fetchall())
            service_ids = {
                (int(row["port"]), row["protocol"]): int(row["id"])
                for row in services
            }
            assert service_ids[(80, "tcp")] == primary_id
            assert {
                key: int(row["connection_count"])
                for row in services
                if (key := (int(row["port"]), row["protocol"]))
            } == {
                (80, "tcp"): 2,
                (443, "tcp"): 1,
                (443, "udp"): 1,
                (8443, "tcp"): 1,
            }
            connections = list(await (
                await db.execute(
                    """SELECT port, protocol, decoy_id
                       FROM decoy_connections ORDER BY id"""
                )
            ).fetchall())
            assert [
                (int(row["port"]), row["protocol"], int(row["decoy_id"]))
                for row in connections
            ] == [
                (443, None, service_ids[(80, "tcp")]),
                (443, "tcp", service_ids[(443, "tcp")]),
                (443, "udp", service_ids[(443, "udp")]),
                (8443, None, service_ids[(8443, "tcp")]),
                (443, None, service_ids[(80, "tcp")]),
            ]
            alerts = list(await (
                await db.execute(
                    "SELECT title, decoy_id FROM home_alerts ORDER BY id"
                )
            ).fetchall())
            assert {
                row["title"]: int(row["decoy_id"])
                for row in alerts
            } == {
                "Ambiguous": service_ids[(80, "tcp")],
                "TCP": service_ids[(443, "tcp")],
                "UDP": service_ids[(443, "udp")],
                "Single": service_ids[(8443, "tcp")],
                "Real": service_ids[(80, "tcp")],
                "Prefix": service_ids[(80, "tcp")],
                "String": service_ids[(80, "tcp")],
                "Fallback": service_ids[(443, "tcp")],
                "SubsetAmbiguous": service_ids[(80, "tcp")],
            }

    @pytest.mark.asyncio
    async def test_full_overlap_conservatively_merges_failure_metadata(
        self,
    ) -> None:
        async with aiosqlite.connect(":memory:") as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA foreign_keys = ON")
            await _apply_through_v8(db)
            config = '{"port_configs":[{"port":80,"protocol":"tcp"}]}'
            rows = (
                (
                    "192.168.1.210",
                    "active",
                    2,
                    "2026-01-02T00:00:00+00:00",
                ),
                (
                    "192.168.1.210",
                    "degraded",
                    3,
                    "2026-01-03T00:00:00+00:00",
                ),
                (
                    "192.168.1.211",
                    "active",
                    1,
                    "2026-01-05T00:00:00+00:00",
                ),
                (
                    "192.168.1.211",
                    "stopped",
                    7,
                    "2026-01-04T00:00:00+00:00",
                ),
            )
            primary_ids: dict[str, int] = {}
            for bind_address, status, failures, last_failure_at in rows:
                inserted = await db.execute(
                    """INSERT INTO decoys
                       (name, decoy_type, bind_address, port, status, config,
                        failure_count, last_failure_at, created_at,
                        updated_at)
                       VALUES ('legacy.local', 'mimic', ?, 80, ?, ?, ?, ?,
                               '2026-01-01', '2026-01-01')""",
                    (
                        bind_address,
                        status,
                        config,
                        failures,
                        last_failure_at,
                    ),
                )
                primary_ids.setdefault(
                    bind_address,
                    int(inserted.lastrowid),
                )
            await db.commit()

            await db_migrations._apply_v9(db)

            migrated = list(await (
                await db.execute(
                    """SELECT id, bind_address, status, failure_count,
                              last_failure_at
                       FROM decoys
                       WHERE bind_address IN (
                           '192.168.1.210',
                           '192.168.1.211'
                       )
                       ORDER BY bind_address"""
                )
            ).fetchall())
            assert [
                (
                    int(row["id"]),
                    row["bind_address"],
                    row["status"],
                    int(row["failure_count"]),
                    row["last_failure_at"],
                )
                for row in migrated
            ] == [
                (
                    primary_ids["192.168.1.210"],
                    "192.168.1.210",
                    "degraded",
                    5,
                    "2026-01-03T00:00:00+00:00",
                ),
                (
                    primary_ids["192.168.1.211"],
                    "192.168.1.211",
                    "active",
                    8,
                    "2026-01-05T00:00:00+00:00",
                ),
            ]

    @pytest.mark.asyncio
    async def test_initial_split_keeps_ambiguous_service_evidence_primary(
        self,
    ) -> None:
        async with aiosqlite.connect(":memory:") as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA foreign_keys = ON")
            await _apply_through_v8(db)
            config = (
                '{"port_configs":['
                '{"port":80,"protocol":"tcp"},'
                '{"port":443,"protocol":"tcp","tls":true},'
                '{"port":443,"protocol":"udp"},'
                '{"port":8443,"protocol":"tcp","tls":true}]}'
            )
            inserted = await db.execute(
                """INSERT INTO decoys
                   (name, decoy_type, bind_address, port, status, config,
                    connection_count, created_at, updated_at)
                   VALUES ('legacy.local', 'mimic', '192.168.1.200', 80,
                           'active', ?, 2, '2026-01-01',
                           '2026-01-01')""",
                (config,),
            )
            primary_id = int(inserted.lastrowid)
            for port in (443, 8443):
                await db.execute(
                    """INSERT INTO decoy_connections
                       (decoy_id, source_ip, port, protocol, timestamp)
                       VALUES (?, '192.168.1.50', ?, NULL,
                               '2026-01-01')""",
                    (primary_id, port),
                )
            for title, detail in (
                ("Ambiguous", '{"dest_port":443}'),
                ("Single", '{"dest_port":8443}'),
                ("Real", '{"dest_port":443.9,"protocol":"tcp"}'),
                ("Prefix", '{"dest_port":"443oops","protocol":"tcp"}'),
                ("Exact", '{"dest_port":443,"protocol":"tcp"}'),
            ):
                await db.execute(
                    """INSERT INTO home_alerts
                       (alert_type, severity, title, detail, decoy_id,
                        created_at)
                       VALUES ('decoy_trip', 'high', ?, ?, ?,
                               '2026-01-01')""",
                    (title, detail, primary_id),
                )
            await db.commit()

            await db_migrations._apply_v9(db)

            services = list(await (
                await db.execute(
                    """SELECT id, port, protocol, connection_count
                       FROM decoys
                       WHERE bind_address = '192.168.1.200'"""
                )
            ).fetchall())
            service_ids = {
                (int(row["port"]), row["protocol"]): int(row["id"])
                for row in services
            }
            assert service_ids[(80, "tcp")] == primary_id
            assert {
                (int(row["port"]), row["protocol"]): int(
                    row["connection_count"]
                )
                for row in services
            } == {
                (80, "tcp"): 1,
                (443, "tcp"): 0,
                (443, "udp"): 0,
                (8443, "tcp"): 1,
            }
            connections = list(await (
                await db.execute(
                    "SELECT port, decoy_id FROM decoy_connections ORDER BY id"
                )
            ).fetchall())
            assert [
                (int(row["port"]), int(row["decoy_id"]))
                for row in connections
            ] == [
                (443, service_ids[(80, "tcp")]),
                (8443, service_ids[(8443, "tcp")]),
            ]
            alerts = list(await (
                await db.execute(
                    "SELECT title, decoy_id FROM home_alerts ORDER BY id"
                )
            ).fetchall())
            assert {
                row["title"]: int(row["decoy_id"])
                for row in alerts
            } == {
                "Ambiguous": service_ids[(80, "tcp")],
                "Single": service_ids[(8443, "tcp")],
                "Real": service_ids[(80, "tcp")],
                "Prefix": service_ids[(80, "tcp")],
                "Exact": service_ids[(443, "tcp")],
            }
