"""Tests for port API routes: network-wide port view and probe endpoint."""

from __future__ import annotations

from datetime import datetime, timezone

import aiosqlite
import pytest

from squirrelops_home_sensor.db.migrations import apply_migrations


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@pytest.fixture
async def db():
    """In-memory SQLite DB with full schema (V1-V5 migrations applied)."""
    async with aiosqlite.connect(":memory:") as conn:
        conn.row_factory = aiosqlite.Row
        await apply_migrations(conn)
        yield conn


async def _insert_device(
    db: aiosqlite.Connection,
    device_id: int,
    ip_address: str,
    hostname: str | None = None,
    device_type: str = "computer",
) -> None:
    now = _now_iso()
    await db.execute(
        """INSERT INTO devices
           (id, ip_address, hostname, device_type, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (device_id, ip_address, hostname, device_type, now, now),
    )
    await db.execute(
        """INSERT INTO device_trust (device_id, status, updated_at)
           VALUES (?, 'unknown', ?)""",
        (device_id, now),
    )
    await db.commit()


async def _insert_port(
    db: aiosqlite.Connection,
    device_id: int,
    port: int,
    service_name: str | None = None,
    banner: str | None = None,
) -> None:
    now = _now_iso()
    await db.execute(
        """INSERT INTO device_open_ports
           (device_id, port, protocol, service_name, banner, first_seen, last_seen)
           VALUES (?, ?, 'tcp', ?, ?, ?, ?)""",
        (device_id, port, service_name, banner, now, now),
    )
    await db.commit()


class TestNetworkPortsQuery:
    """Test the network ports aggregation SQL and grouping logic."""

    @pytest.mark.asyncio
    async def test_groups_by_port(self, db) -> None:
        """Two devices with the same port appear as one group."""
        await _insert_device(db, 1, "192.168.1.10", "host-a")
        await _insert_device(db, 2, "192.168.1.20", "host-b")
        await _insert_port(db, 1, 22, service_name="SSH")
        await _insert_port(db, 2, 22, service_name="SSH")

        cursor = await db.execute(
            """SELECT p.port, p.protocol, p.service_name,
                      d.id as device_id, d.ip_address, d.hostname
               FROM device_open_ports p
               JOIN devices d ON d.id = p.device_id
               ORDER BY p.port, d.ip_address"""
        )
        rows = await cursor.fetchall()

        assert len(rows) == 2
        assert all(r["port"] == 22 for r in rows)
        ips = {r["ip_address"] for r in rows}
        assert ips == {"192.168.1.10", "192.168.1.20"}

    @pytest.mark.asyncio
    async def test_multiple_ports_per_device(self, db) -> None:
        """A device with multiple ports produces multiple rows."""
        await _insert_device(db, 1, "192.168.1.10", "host-a")
        await _insert_port(db, 1, 22, service_name="SSH")
        await _insert_port(db, 1, 80, service_name="HTTP")
        await _insert_port(db, 1, 443, service_name="HTTPS")

        cursor = await db.execute(
            "SELECT COUNT(*) FROM device_open_ports WHERE device_id = 1"
        )
        row = await cursor.fetchone()
        assert row[0] == 3

    @pytest.mark.asyncio
    async def test_empty_network(self, db) -> None:
        """No devices or ports returns empty results."""
        cursor = await db.execute(
            """SELECT p.port FROM device_open_ports p
               JOIN devices d ON d.id = p.device_id"""
        )
        rows = await cursor.fetchall()
        assert len(rows) == 0

    @pytest.mark.asyncio
    async def test_service_name_and_banner_stored(self, db) -> None:
        """Service name and banner are correctly stored and retrieved."""
        await _insert_device(db, 1, "192.168.1.10")
        await _insert_port(db, 1, 22, service_name="SSH", banner="SSH-2.0-OpenSSH_9.6")

        cursor = await db.execute(
            "SELECT service_name, banner FROM device_open_ports WHERE port = 22"
        )
        row = await cursor.fetchone()
        assert row["service_name"] == "SSH"
        assert row["banner"] == "SSH-2.0-OpenSSH_9.6"


class TestProbeResultPersistence:
    """Test that probe results get persisted via UPDATE."""

    @pytest.mark.asyncio
    async def test_coalesce_preserves_existing_data(self, db) -> None:
        """COALESCE in UPDATE keeps existing service_name if new value is NULL."""
        await _insert_device(db, 1, "192.168.1.10")
        await _insert_port(db, 1, 22, service_name="SSH", banner="SSH-2.0-OpenSSH")

        # Simulate probe result with no service_name but a new banner
        await db.execute(
            """UPDATE device_open_ports
               SET service_name = COALESCE(?, device_open_ports.service_name),
                   banner = COALESCE(?, device_open_ports.banner)
               WHERE port = ? AND device_id IN (
                   SELECT id FROM devices WHERE ip_address = ?
               )""",
            (None, "SSH-2.0-OpenSSH_9.7", 22, "192.168.1.10"),
        )
        await db.commit()

        cursor = await db.execute(
            "SELECT service_name, banner FROM device_open_ports WHERE port = 22"
        )
        row = await cursor.fetchone()
        assert row["service_name"] == "SSH"  # preserved
        assert row["banner"] == "SSH-2.0-OpenSSH_9.7"  # updated

    @pytest.mark.asyncio
    async def test_update_writes_new_service_data(self, db) -> None:
        """When no prior data exists, new probe results are stored."""
        await _insert_device(db, 1, "192.168.1.10")
        await _insert_port(db, 1, 8080)  # no service_name or banner

        await db.execute(
            """UPDATE device_open_ports
               SET service_name = COALESCE(?, device_open_ports.service_name),
                   banner = COALESCE(?, device_open_ports.banner)
               WHERE port = ? AND device_id IN (
                   SELECT id FROM devices WHERE ip_address = ?
               )""",
            ("HTTP Proxy", "Apache/2.4.52", 8080, "192.168.1.10"),
        )
        await db.commit()

        cursor = await db.execute(
            "SELECT service_name, banner FROM device_open_ports WHERE port = 8080"
        )
        row = await cursor.fetchone()
        assert row["service_name"] == "HTTP Proxy"
        assert row["banner"] == "Apache/2.4.52"


class TestMigrationV5:
    """Test V5 migration adds service_name and banner columns."""

    @pytest.mark.asyncio
    async def test_v5_columns_exist(self, db) -> None:
        """After migrations, device_open_ports has service_name and banner."""
        cursor = await db.execute("PRAGMA table_info(device_open_ports)")
        columns = {row["name"] for row in await cursor.fetchall()}
        assert "service_name" in columns
        assert "banner" in columns

    @pytest.mark.asyncio
    async def test_v5_columns_nullable(self, db) -> None:
        """service_name and banner default to NULL."""
        await _insert_device(db, 1, "192.168.1.10")
        now = _now_iso()
        await db.execute(
            """INSERT INTO device_open_ports
               (device_id, port, protocol, first_seen, last_seen)
               VALUES (1, 22, 'tcp', ?, ?)""",
            (now, now),
        )
        await db.commit()

        cursor = await db.execute(
            "SELECT service_name, banner FROM device_open_ports WHERE port = 22"
        )
        row = await cursor.fetchone()
        assert row["service_name"] is None
        assert row["banner"] is None
