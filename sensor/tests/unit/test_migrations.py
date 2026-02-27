"""Tests for schema migrations."""
from __future__ import annotations

import aiosqlite
import pytest

from squirrelops_home_sensor.db.migrations import _apply_v3, apply_migrations


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
        assert row[0] == 6

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
