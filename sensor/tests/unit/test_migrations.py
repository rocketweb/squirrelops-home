"""Tests for schema migrations."""
from __future__ import annotations

import json

import aiosqlite
import pytest

from squirrelops_home_sensor.db.migrations import (
    _apply_v3,
    _apply_v7,
    _apply_v8,
    _apply_v10,
    apply_migrations,
)
from squirrelops_home_sensor.db.schema import SCHEMA_VERSION


class TestMigrationV2:
    """Test migration from V1 to V2: add model_name column."""

    @pytest.mark.asyncio
    async def test_v2_adds_model_name_column(self, tmp_path) -> None:
        """Applying migrations adds model_name column to devices table."""
        db = await aiosqlite.connect(str(tmp_path / "test.db"))
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)

        # Verify column exists by inserting a device with model_name
        await db.execute(
            "INSERT INTO devices (ip_address, model_name, first_seen, last_seen) "
            "VALUES ('192.168.1.1', 'Sonos One', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
        )
        cursor = await db.execute("SELECT model_name FROM devices WHERE ip_address = '192.168.1.1'")
        row = await cursor.fetchone()
        assert row["model_name"] == "Sonos One"

        await db.close()

    @pytest.mark.asyncio
    async def test_v2_migration_is_idempotent(self, tmp_path) -> None:
        """Applying migrations twice doesn't fail."""
        db = await aiosqlite.connect(str(tmp_path / "test.db"))
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)
        await apply_migrations(db)  # Should be a no-op

        cursor = await db.execute("SELECT MAX(version) FROM schema_version")
        row = await cursor.fetchone()
        assert row[0] == SCHEMA_VERSION

        await db.close()

    @pytest.mark.asyncio
    async def test_model_name_defaults_to_null(self, tmp_path) -> None:
        """Existing devices get NULL model_name after migration."""
        db = await aiosqlite.connect(str(tmp_path / "test.db"))
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)

        await db.execute(
            "INSERT INTO devices (ip_address, first_seen, last_seen) "
            "VALUES ('192.168.1.1', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
        )
        cursor = await db.execute("SELECT model_name FROM devices WHERE ip_address = '192.168.1.1'")
        row = await cursor.fetchone()
        assert row["model_name"] is None

        await db.close()


class TestMigrationV3:
    """Test migration from V2 to V3: add area column to devices."""

    @pytest.mark.asyncio
    async def test_v3_adds_area_column(self, tmp_path) -> None:
        """Applying migrations adds area column to devices table."""
        db = await aiosqlite.connect(str(tmp_path / "test.db"))
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)

        # Verify column exists by inserting a device with area
        await db.execute(
            "INSERT INTO devices (ip_address, area, first_seen, last_seen) "
            "VALUES ('192.168.1.1', 'Living Room', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
        )
        cursor = await db.execute("SELECT area FROM devices WHERE ip_address = '192.168.1.1'")
        row = await cursor.fetchone()
        assert row["area"] == "Living Room"

        await db.close()

    @pytest.mark.asyncio
    async def test_v3_area_defaults_to_null(self, tmp_path) -> None:
        """Existing devices get NULL area after migration."""
        db = await aiosqlite.connect(str(tmp_path / "test.db"))
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)

        await db.execute(
            "INSERT INTO devices (ip_address, first_seen, last_seen) "
            "VALUES ('192.168.1.1', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
        )
        cursor = await db.execute("SELECT area FROM devices WHERE ip_address = '192.168.1.1'")
        row = await cursor.fetchone()
        assert row["area"] is None

        await db.close()

    @pytest.mark.asyncio
    async def test_v3_idempotent(self, tmp_path) -> None:
        """Running _apply_v3 twice does not raise an error."""
        db = await aiosqlite.connect(str(tmp_path / "test.db"))
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)

        # Run the V3 migration function again directly -- should be a no-op
        await _apply_v3(db)

        # Verify area column still works
        await db.execute(
            "INSERT INTO devices (ip_address, area, first_seen, last_seen) "
            "VALUES ('192.168.1.1', 'Office', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
        )
        cursor = await db.execute("SELECT area FROM devices WHERE ip_address = '192.168.1.1'")
        row = await cursor.fetchone()
        assert row["area"] == "Office"

        await db.close()


class TestMigrationV7:
    """Test V7 migration: deduplicate historical security alerts."""

    async def _setup_db_with_duplicates(self, tmp_path):
        """Create a DB at V6 and seed it with duplicate alerts."""
        db = await aiosqlite.connect(str(tmp_path / "test.db"))
        db.row_factory = aiosqlite.Row
        # Apply all migrations up to V6
        await apply_migrations(db)

        # The schema is now at V7 because SCHEMA_VERSION = 7; roll back to V6
        # by deleting the V7 record so we can test V7 migration explicitly
        await db.execute("DELETE FROM schema_version WHERE version = 7")
        await db.commit()

        # Insert a device
        await db.execute(
            "INSERT INTO devices (id, ip_address, first_seen, last_seen) "
            "VALUES (1, '192.168.1.10', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
        )

        # Insert duplicate alerts for the same condition (SSH on device 1)
        for i in range(5):
            detail = json.dumps({"device_id": 1, "port": 22, "service_name": "SSH"})
            await db.execute(
                "INSERT INTO home_alerts "
                "(alert_type, severity, title, detail, source_ip, device_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "security.port_risk",
                    "medium",
                    "SSH open on 192.168.1.10",
                    detail,
                    "192.168.1.10",
                    1,
                    f"2026-01-0{i + 1}T00:00:00Z",
                ),
            )

        # Insert a unique alert (different condition, should be kept)
        detail = json.dumps({"device_id": 1, "port": 80, "service_name": "HTTP"})
        await db.execute(
            "INSERT INTO home_alerts "
            "(alert_type, severity, title, detail, source_ip, device_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "security.port_risk",
                "low",
                "HTTP open on 192.168.1.10",
                detail,
                "192.168.1.10",
                1,
                "2026-01-06T00:00:00Z",
            ),
        )

        # Add insight_state referencing the latest SSH alert (id=5)
        await db.execute(
            "INSERT INTO security_insight_state "
            "(device_id, insight_key, alert_id, created_at) "
            "VALUES (?, ?, ?, ?)",
            (1, "risky_port:22", 5, "2026-01-05T00:00:00Z"),
        )

        await db.commit()
        return db

    @pytest.mark.asyncio
    async def test_v7_removes_duplicate_alerts(self, tmp_path) -> None:
        """V7 migration deletes duplicate alerts, keeping only the latest."""
        db = await self._setup_db_with_duplicates(tmp_path)

        # Verify we start with 6 alerts (5 SSH dupes + 1 HTTP)
        cursor = await db.execute("SELECT COUNT(*) FROM home_alerts")
        assert (await cursor.fetchone())[0] == 6

        await _apply_v7(db)

        # Should now have 2 alerts: latest SSH + HTTP
        cursor = await db.execute("SELECT COUNT(*) FROM home_alerts")
        assert (await cursor.fetchone())[0] == 2

        # The remaining SSH alert should be the one with the highest id
        cursor = await db.execute(
            "SELECT id FROM home_alerts WHERE title = 'SSH open on 192.168.1.10'"
        )
        row = await cursor.fetchone()
        assert row["id"] == 5  # MAX(id) from the 5 SSH alerts

        # The HTTP alert should also remain
        cursor = await db.execute(
            "SELECT id FROM home_alerts WHERE title = 'HTTP open on 192.168.1.10'"
        )
        row = await cursor.fetchone()
        assert row is not None

        await db.close()

    @pytest.mark.asyncio
    async def test_v7_preserves_insight_state_references(self, tmp_path) -> None:
        """V7 migration keeps insight_state entries that reference surviving alerts."""
        db = await self._setup_db_with_duplicates(tmp_path)

        await _apply_v7(db)

        # Insight state should still reference alert 5 (the kept alert)
        cursor = await db.execute(
            "SELECT alert_id FROM security_insight_state WHERE insight_key = 'risky_port:22'"
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row["alert_id"] == 5

        await db.close()

    @pytest.mark.asyncio
    async def test_v7_repoints_duplicate_insight_before_fk_delete(self, tmp_path) -> None:
        """V7 repoints insight state before deleting an alert it references."""
        db = await self._setup_db_with_duplicates(tmp_path)
        await db.execute(
            "UPDATE security_insight_state SET alert_id = 1 "
            "WHERE insight_key = 'risky_port:22'"
        )
        await db.commit()
        await db.execute("PRAGMA foreign_keys = ON")
        assert (await (await db.execute("PRAGMA foreign_keys")).fetchone())[0] == 1

        await _apply_v7(db)

        row = await (
            await db.execute(
                "SELECT alert_id FROM security_insight_state "
                "WHERE insight_key = 'risky_port:22'"
            )
        ).fetchone()
        assert row["alert_id"] == 5
        assert list(await (await db.execute("PRAGMA foreign_key_check")).fetchall()) == []

        await db.close()

    @pytest.mark.asyncio
    async def test_v7_rolls_back_all_changes_when_version_write_fails(
        self, tmp_path
    ) -> None:
        """V7 restores all rows when a late migration statement fails."""
        db = await self._setup_db_with_duplicates(tmp_path)
        await db.execute("""
            CREATE TRIGGER fail_v7_version
            BEFORE INSERT ON schema_version
            WHEN NEW.version = 7
            BEGIN
                SELECT RAISE(ABORT, 'forced V7 version failure');
            END
        """)
        await db.commit()
        await db.execute("PRAGMA foreign_keys = ON")

        with pytest.raises(
            aiosqlite.IntegrityError, match="forced V7 version failure"
        ):
            await _apply_v7(db)

        alert_ids = [
            row["id"]
            for row in await (
                await db.execute("SELECT id FROM home_alerts ORDER BY id")
            ).fetchall()
        ]
        assert alert_ids == [1, 2, 3, 4, 5, 6]
        assert (
            await (
                await db.execute(
                    "SELECT COUNT(*) FROM schema_version WHERE version = 7"
                )
            ).fetchone()
        )[0] == 0

        await db.execute("DROP TRIGGER fail_v7_version")
        await _apply_v7(db)
        alert_ids = [
            row["id"]
            for row in await (
                await db.execute("SELECT id FROM home_alerts ORDER BY id")
            ).fetchall()
        ]
        assert alert_ids == [5, 6]

        await db.close()

    @pytest.mark.asyncio
    async def test_v7_idempotent(self, tmp_path) -> None:
        """Running V7 migration twice doesn't fail or delete more data."""
        db = await self._setup_db_with_duplicates(tmp_path)

        await _apply_v7(db)
        count_after_first = (
            await (await db.execute("SELECT COUNT(*) FROM home_alerts")).fetchone()
        )[0]

        # Run again -- should be a no-op
        await _apply_v7(db)
        count_after_second = (
            await (await db.execute("SELECT COUNT(*) FROM home_alerts")).fetchone()
        )[0]

        assert count_after_first == count_after_second == 2

        await db.close()

    @pytest.mark.asyncio
    async def test_v7_no_duplicates_is_noop(self, tmp_path) -> None:
        """V7 migration is a no-op when there are no duplicates."""
        db = await aiosqlite.connect(str(tmp_path / "test.db"))
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)

        # Fresh DB with no alerts -- V7 should have no effect
        cursor = await db.execute("SELECT COUNT(*) FROM home_alerts")
        assert (await cursor.fetchone())[0] == 0

        await db.close()

    @pytest.mark.asyncio
    async def test_v7_preserves_incident_alerts(self, tmp_path) -> None:
        """V7 migration doesn't touch alerts that belong to incidents."""
        db = await self._setup_db_with_duplicates(tmp_path)

        # Create an incident and assign some duplicate SSH alerts to it
        await db.execute(
            "INSERT INTO incidents "
            "(source_ip, status, severity, alert_count, first_alert_at, last_alert_at) "
            "VALUES ('192.168.1.10', 'active', 'medium', 2, '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z')"
        )
        # Assign first two SSH alerts to the incident
        await db.execute("UPDATE home_alerts SET incident_id = 1 WHERE id IN (1, 2)")
        await db.commit()

        await _apply_v7(db)

        # Incident alerts should still exist (2 incident + 1 standalone SSH + 1 HTTP = 4)
        cursor = await db.execute("SELECT COUNT(*) FROM home_alerts")
        total = (await cursor.fetchone())[0]
        assert total == 4

        # The 2 incident alerts should be preserved
        cursor = await db.execute(
            "SELECT COUNT(*) FROM home_alerts WHERE incident_id IS NOT NULL"
        )
        assert (await cursor.fetchone())[0] == 2

        await db.close()


class TestMigrationV8:
    """Test V8 migration: consolidate per-device alerts into grouped alerts."""

    async def _setup_db_with_per_device_alerts(self, tmp_path):
        """Create a DB at V7 and seed it with per-device security alerts."""
        db = await aiosqlite.connect(str(tmp_path / "test.db"))
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)

        # Roll back to V7 so we can test V8 migration explicitly
        await db.execute("DELETE FROM schema_version WHERE version = 8")
        # Remove V8 columns (we need to re-create without them for a true test)
        # Since SQLite doesn't support DROP COLUMN, we'll just set them to NULL
        # and clear the issue_key so the migration thinks they're unmigrated
        await db.commit()

        # Insert devices
        for i in range(1, 4):
            await db.execute(
                "INSERT INTO devices (id, ip_address, mac_address, first_seen, last_seen) "
                "VALUES (?, ?, ?, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                (i, f"192.168.1.{10 + i}", f"AA:BB:CC:DD:EE:{i:02X}"),
            )

        # Insert 3 per-device SSH alerts (should be consolidated into 1 grouped alert)
        for i in range(1, 4):
            detail = json.dumps({
                "device_id": i,
                "port": 22,
                "service_name": "SSH",
                "risk_description": "SSH on IoT devices uses default credentials.",
                "remediation_steps": "Disable SSH or change password.",
            })
            await db.execute(
                "INSERT INTO home_alerts "
                "(alert_type, severity, title, detail, source_ip, source_mac, "
                " device_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "security.port_risk",
                    "medium",
                    f"SSH open on 192.168.1.{10 + i}",
                    detail,
                    f"192.168.1.{10 + i}",
                    f"AA:BB:CC:DD:EE:{i:02X}",
                    i,
                    f"2026-01-0{i}T00:00:00Z",
                ),
            )

        # Insert 1 FTP alert (different issue, should be its own group)
        ftp_detail = json.dumps({
            "device_id": 1,
            "port": 21,
            "service_name": "FTP",
            "risk_description": "FTP transmits in plaintext.",
            "remediation_steps": "Disable FTP.",
        })
        await db.execute(
            "INSERT INTO home_alerts "
            "(alert_type, severity, title, detail, source_ip, device_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "security.port_risk",
                "medium",
                "FTP open on 192.168.1.11",
                ftp_detail,
                "192.168.1.11",
                1,
                "2026-01-04T00:00:00Z",
            ),
        )

        # Insert a non-port-risk alert (should be untouched)
        await db.execute(
            "INSERT INTO home_alerts "
            "(alert_type, severity, title, detail, source_ip, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                "device.new",
                "medium",
                "New device detected",
                json.dumps({"info": "new device"}),
                "192.168.1.50",
                "2026-01-05T00:00:00Z",
            ),
        )

        # Add insight_state entries
        await db.execute(
            "INSERT INTO security_insight_state "
            "(device_id, insight_key, alert_id, created_at) "
            "VALUES (?, ?, ?, ?)",
            (1, "risky_port:22", 1, "2026-01-01T00:00:00Z"),
        )
        await db.execute(
            "INSERT INTO security_insight_state "
            "(device_id, insight_key, alert_id, created_at) "
            "VALUES (?, ?, ?, ?)",
            (2, "risky_port:22", 2, "2026-01-02T00:00:00Z"),
        )

        await db.commit()
        return db

    @pytest.mark.asyncio
    async def test_v8_adds_grouped_alert_columns(self, tmp_path) -> None:
        """V8 migration adds issue_key, affected_devices, device_count,
        risk_description, remediation columns."""
        db = await aiosqlite.connect(str(tmp_path / "test.db"))
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)

        # Verify columns exist by inserting an alert with grouped fields
        await db.execute(
            "INSERT INTO home_alerts (alert_type, severity, title, detail, "
            "issue_key, affected_devices, device_count, risk_description, remediation, "
            "created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "security.port_risk", "medium", "SSH open on 2 devices",
                json.dumps({"port": 22}), "port_risk:ssh:22",
                json.dumps([{"device_id": 1, "ip_address": "192.168.1.10"}]),
                2, "SSH is risky", "Disable SSH",
                "2026-01-01T00:00:00Z",
            ),
        )
        cursor = await db.execute(
            "SELECT issue_key, device_count, risk_description, remediation "
            "FROM home_alerts WHERE issue_key = 'port_risk:ssh:22'"
        )
        row = await cursor.fetchone()
        assert row["issue_key"] == "port_risk:ssh:22"
        assert row["device_count"] == 2
        assert row["risk_description"] == "SSH is risky"
        assert row["remediation"] == "Disable SSH"

        await db.close()


    @pytest.mark.asyncio
    async def test_v8_consolidates_per_device_alerts(self, tmp_path) -> None:
        """V8 migration consolidates 3 SSH per-device alerts into 1 grouped alert."""
        db = await self._setup_db_with_per_device_alerts(tmp_path)

        # Before: 3 SSH + 1 FTP + 1 device.new = 5 alerts
        cursor = await db.execute("SELECT COUNT(*) FROM home_alerts")
        assert (await cursor.fetchone())[0] == 5

        await _apply_v8(db)

        # After: 1 grouped SSH + 1 grouped FTP + 1 device.new = 3 alerts
        cursor = await db.execute("SELECT COUNT(*) FROM home_alerts")
        assert (await cursor.fetchone())[0] == 3

        # The SSH grouped alert should have issue_key and device_count=3
        cursor = await db.execute(
            "SELECT * FROM home_alerts WHERE issue_key = 'port_risk:ssh:22'"
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row["device_count"] == 3
        assert "3 devices" in row["title"]
        assert row["source_ip"] is None  # nulled for grouped alerts
        assert row["device_id"] is None  # nulled for grouped alerts

        # Verify affected_devices JSON
        affected = json.loads(row["affected_devices"])
        assert len(affected) == 3
        device_ids = {d["device_id"] for d in affected}
        assert device_ids == {1, 2, 3}

        # The FTP grouped alert should exist too
        cursor = await db.execute(
            "SELECT * FROM home_alerts WHERE issue_key = 'port_risk:ftp:21'"
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row["device_count"] == 1

        # The device.new alert should be untouched
        cursor = await db.execute(
            "SELECT * FROM home_alerts WHERE alert_type = 'device.new'"
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row["issue_key"] is None

        await db.close()

    @pytest.mark.asyncio
    async def test_v8_updates_insight_state_references(self, tmp_path) -> None:
        """V8 migration updates insight_state to point to the surviving grouped alert."""
        db = await self._setup_db_with_per_device_alerts(tmp_path)

        await _apply_v8(db)

        # Find the surviving SSH grouped alert
        cursor = await db.execute(
            "SELECT id FROM home_alerts WHERE issue_key = 'port_risk:ssh:22'"
        )
        winner = await cursor.fetchone()
        winner_id = winner["id"]

        # Both insight_state entries should now reference the winner
        cursor = await db.execute(
            "SELECT alert_id FROM security_insight_state WHERE insight_key = 'risky_port:22'"
        )
        rows = await cursor.fetchall()
        for row in rows:
            assert row["alert_id"] == winner_id

        await db.close()

    @pytest.mark.asyncio
    async def test_v8_repoints_insights_before_fk_delete(self, tmp_path) -> None:
        """V8 repoints insight state before deleting grouped-alert losers."""
        db = await self._setup_db_with_per_device_alerts(tmp_path)
        await db.execute("PRAGMA foreign_keys = ON")
        assert (await (await db.execute("PRAGMA foreign_keys")).fetchone())[0] == 1

        await _apply_v8(db)

        rows = list(
            await (
                await db.execute(
                    "SELECT alert_id FROM security_insight_state "
                    "WHERE insight_key = 'risky_port:22' ORDER BY device_id"
                )
            ).fetchall()
        )
        assert [row["alert_id"] for row in rows] == [3, 3]
        assert list(await (await db.execute("PRAGMA foreign_key_check")).fetchall()) == []

        await db.close()

    @pytest.mark.asyncio
    async def test_v8_rolls_back_all_changes_when_version_write_fails(
        self, tmp_path
    ) -> None:
        """V8 restores all rows when a late migration statement fails."""
        db = await self._setup_db_with_per_device_alerts(tmp_path)
        await db.execute(
            "UPDATE security_insight_state SET alert_id = 3 "
            "WHERE insight_key = 'risky_port:22'"
        )
        await db.execute("""
            CREATE TRIGGER fail_v8_version
            BEFORE INSERT ON schema_version
            WHEN NEW.version = 8
            BEGIN
                SELECT RAISE(ABORT, 'forced V8 version failure');
            END
        """)
        await db.commit()
        await db.execute("PRAGMA foreign_keys = ON")

        with pytest.raises(
            aiosqlite.IntegrityError, match="forced V8 version failure"
        ):
            await _apply_v8(db)

        rows = list(
            await (
                await db.execute(
                    "SELECT id, issue_key FROM home_alerts ORDER BY id"
                )
            ).fetchall()
        )
        assert [(row["id"], row["issue_key"]) for row in rows] == [
            (1, None),
            (2, None),
            (3, None),
            (4, None),
            (5, None),
        ]
        assert (
            await (
                await db.execute(
                    "SELECT COUNT(*) FROM schema_version WHERE version = 8"
                )
            ).fetchone()
        )[0] == 0

        await db.execute("DROP TRIGGER fail_v8_version")
        await _apply_v8(db)
        assert (
            await (await db.execute("SELECT COUNT(*) FROM home_alerts")).fetchone()
        )[0] == 3

        await db.close()

    @pytest.mark.asyncio
    async def test_v8_idempotent(self, tmp_path) -> None:
        """Running V8 migration twice doesn't fail or corrupt data."""
        db = await self._setup_db_with_per_device_alerts(tmp_path)

        await _apply_v8(db)
        count_after_first = (
            await (await db.execute("SELECT COUNT(*) FROM home_alerts")).fetchone()
        )[0]

        # Run again — should be a no-op (all alerts already have issue_key)
        await _apply_v8(db)
        count_after_second = (
            await (await db.execute("SELECT COUNT(*) FROM home_alerts")).fetchone()
        )[0]

        assert count_after_first == count_after_second == 3

        await db.close()

    @pytest.mark.asyncio
    async def test_v8_creates_issue_key_index(self, tmp_path) -> None:
        """V8 migration creates the idx_alerts_issue_key index."""
        db = await aiosqlite.connect(str(tmp_path / "test.db"))
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)

        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='index' "
            "AND name='idx_alerts_issue_key'"
        )
        row = await cursor.fetchone()
        assert row is not None

        await db.close()


class TestMigrationV10:
    """Test V10 normalized mDNS-label uniqueness and V9 reconciliation."""

    @staticmethod
    async def _setup_v9_collision(tmp_path):
        db = await aiosqlite.connect(str(tmp_path / "v9-collision.db"))
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)
        await db.execute(
            "DROP INDEX idx_decoy_hosts_active_mdns_label_nocase"
        )
        await db.execute("DELETE FROM schema_version WHERE version = 10")

        now = "2026-01-01T00:00:00Z"
        await db.executemany(
            """INSERT INTO decoy_hosts
               (id, hostname, bind_address, tls_cert_pem, tls_key_pem,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    10,
                    "server.local",
                    "192.168.1.200",
                    None,
                    None,
                    now,
                    now,
                ),
                (
                    20,
                    "server.localdomain",
                    "192.168.1.201",
                    "legacy-cert",
                    "legacy-key",
                    now,
                    now,
                ),
            ],
        )
        await db.executemany(
            """INSERT INTO decoys
               (id, name, decoy_type, bind_address, port, status, config,
                created_at, updated_at, host_id, protocol, service_name,
                is_primary)
               VALUES (?, ?, 'mimic', ?, 443, 'active', ?, ?, ?, ?,
                       'tcp', 'https', 1)""",
            [
                (
                    100,
                    "server.local",
                    "192.168.1.200",
                    json.dumps({"mdns_hostname": "server"}),
                    now,
                    now,
                    10,
                ),
                (
                    200,
                    "server.localdomain",
                    "192.168.1.201",
                    json.dumps({"mdns_hostname": "server"}),
                    now,
                    now,
                    20,
                ),
            ],
        )
        await db.commit()
        return db

    @pytest.mark.asyncio
    async def test_v10_reconciles_v9_suffix_collision_deterministically(
        self,
        tmp_path,
    ) -> None:
        db = await self._setup_v9_collision(tmp_path)

        await _apply_v10(db)

        hosts = list(
            await (
                await db.execute(
                    """SELECT id, hostname, tls_cert_pem, tls_key_pem
                       FROM decoy_hosts
                       ORDER BY id"""
                )
            ).fetchall()
        )
        assert [(row["id"], row["hostname"]) for row in hosts] == [
            (10, "server.local"),
            (20, "server-20.localdomain"),
        ]
        assert hosts[1]["tls_cert_pem"] != "legacy-cert"
        assert hosts[1]["tls_key_pem"] != "legacy-key"

        service = await (
            await db.execute(
                "SELECT name, config FROM decoys WHERE id = 200"
            )
        ).fetchone()
        assert service["name"] == "server-20.localdomain"
        assert json.loads(service["config"])["mdns_hostname"] == "server-20"
        assert (
            await (
                await db.execute(
                    "SELECT COUNT(*) FROM schema_version WHERE version = 10"
                )
            ).fetchone()
        )[0] == 1

        await _apply_v10(db)
        assert (
            await (
                await db.execute(
                    "SELECT hostname FROM decoy_hosts WHERE id = 20"
                )
            ).fetchone()
        )["hostname"] == "server-20.localdomain"
        await db.close()

    @pytest.mark.asyncio
    async def test_v10_reserves_later_legacy_labels_when_renaming(
        self,
        tmp_path,
    ) -> None:
        db = await self._setup_v9_collision(tmp_path)
        now = "2026-01-01T00:00:00Z"
        await db.execute(
            """INSERT INTO decoy_hosts
               (id, hostname, bind_address, created_at, updated_at)
               VALUES (30, 'server-20.local', '192.168.1.202', ?, ?)""",
            (now, now),
        )
        await db.commit()

        await _apply_v10(db)

        hosts = list(
            await (
                await db.execute(
                    "SELECT id, hostname FROM decoy_hosts ORDER BY id"
                )
            ).fetchall()
        )
        assert [(row["id"], row["hostname"]) for row in hosts] == [
            (10, "server.local"),
            (20, "server-20-2.localdomain"),
            (30, "server-20.local"),
        ]
        await db.close()

    @pytest.mark.asyncio
    async def test_v10_two_phase_rename_handles_occupied_final_name(
        self,
        tmp_path,
    ) -> None:
        db = await self._setup_v9_collision(tmp_path)
        now = "2026-01-01T00:00:00Z"
        await db.execute(
            """INSERT INTO decoy_hosts
               (id, hostname, bind_address, created_at, updated_at)
               VALUES (5, 'server.local.', '192.168.1.202', ?, ?)""",
            (now, now),
        )
        await db.commit()

        await _apply_v10(db)

        hosts = list(
            await (
                await db.execute(
                    "SELECT id, hostname FROM decoy_hosts ORDER BY id"
                )
            ).fetchall()
        )
        assert [(row["id"], row["hostname"]) for row in hosts] == [
            (5, "server.local"),
            (10, "server-10.local"),
            (20, "server-20.localdomain"),
        ]
        await db.close()

    @pytest.mark.asyncio
    async def test_v10_index_enforces_normalized_active_label(
        self,
        tmp_path,
    ) -> None:
        db = await self._setup_v9_collision(tmp_path)
        await _apply_v10(db)
        now = "2026-01-01T00:00:00Z"

        with pytest.raises(aiosqlite.IntegrityError):
            await db.execute(
                """INSERT INTO decoy_hosts
                   (hostname, bind_address, created_at, updated_at)
                   VALUES ('SERVER.', '192.168.1.202', ?, ?)""",
                (now, now),
            )

        await db.execute(
            """INSERT INTO decoy_hosts
               (hostname, bind_address, retired_at, created_at, updated_at)
               VALUES ('SERVER.localdomain.', '192.168.1.203', ?, ?, ?)""",
            (now, now, now),
        )
        await db.rollback()
        await db.close()
