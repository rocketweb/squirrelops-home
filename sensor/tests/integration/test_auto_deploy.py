"""Tests for decoy auto-deploy and resume functionality."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import aiosqlite
import pytest

from squirrelops_home_sensor.db.schema import create_all_tables
from squirrelops_home_sensor.decoys import orchestrator as orchestrator_module
from squirrelops_home_sensor.decoys.orchestrator import DecoyOrchestrator


@pytest.fixture()
async def db(tmp_path):
    """Create an in-memory database with schema."""
    db_path = tmp_path / "test.db"
    conn = await aiosqlite.connect(str(db_path))
    conn.row_factory = aiosqlite.Row
    await create_all_tables(conn)
    yield conn
    await conn.close()


@pytest.fixture()
def event_bus():
    bus = MagicMock()
    bus.publish = AsyncMock(return_value=1)
    return bus


@pytest.fixture()
def orchestrator(event_bus, db):
    return DecoyOrchestrator(event_bus=event_bus, db=db, max_decoys=8)


class TestAutoDeployReconcilesExistingTypes:
    async def test_fills_missing_type_when_an_active_type_exists(self, orchestrator, db):
        """An existing listener must not prevent a different useful type."""
        await db.execute(
            """INSERT INTO decoys (name, decoy_type, bind_address, port, status, config, created_at, updated_at)
               VALUES ('test', 'file_share', '0.0.0.0', 8080, 'active', '{}', '2026-01-01', '2026-01-01')"""
        )
        await db.commit()

        result = await orchestrator.auto_deploy([{"ip": "10.0.0.1", "port": 8080, "protocol": "tcp"}])
        assert result == 1
        cursor = await db.execute("SELECT decoy_type FROM decoys ORDER BY id")
        assert [row["decoy_type"] for row in await cursor.fetchall()] == [
            "file_share",
            "dev_server",
        ]

    async def test_fills_missing_type_without_replacing_stopped_type(
        self, orchestrator, db,
    ):
        """A disabled type stays disabled while other useful types can be added."""
        await db.execute(
            """INSERT INTO decoys (name, decoy_type, bind_address, port, status, config, created_at, updated_at)
               VALUES ('old', 'file_share', '0.0.0.0', 8080, 'stopped', '{}', '2026-01-01', '2026-01-01')"""
        )
        await db.commit()

        result = await orchestrator.auto_deploy([{"ip": "10.0.0.1", "port": 3000, "protocol": "tcp"}])
        assert result == 1
        cursor = await db.execute(
            "SELECT decoy_type, status FROM decoys ORDER BY id"
        )
        rows = await cursor.fetchall()
        assert [(row["decoy_type"], row["status"]) for row in rows] == [
            ("file_share", "stopped"),
            ("dev_server", "active"),
        ]

    async def test_does_not_duplicate_a_stopped_type(self, orchestrator, db):
        """A scan must not silently replace a listener the user disabled."""
        await db.execute(
            """INSERT INTO decoys
               (name, decoy_type, bind_address, port, status, config,
                created_at, updated_at)
               VALUES ('old', 'file_share', '0.0.0.0', 8080, 'stopped', '{}',
                       '2026-01-01', '2026-01-01')"""
        )
        await db.commit()

        result = await orchestrator.auto_deploy(
            [{"ip": "10.0.0.1", "port": 22, "protocol": "tcp"}]
        )

        assert result == 0
        cursor = await db.execute("SELECT COUNT(*) FROM decoys")
        assert (await cursor.fetchone())[0] == 1


class TestAutoDeployCreatesDecoys:
    async def test_defers_without_lan_then_deploys_after_network_returns(
        self, db, event_bus, monkeypatch,
    ):
        """No-LAN scans create no unreachable rows and re-resolve on the next scan."""
        bindable_lan_address = orchestrator_module._route_selected_ip()
        assert bindable_lan_address is not None
        route_address: dict[str, str | None] = {"value": None}
        monkeypatch.setattr(
            "squirrelops_home_sensor.decoys.orchestrator._route_selected_ip",
            lambda: route_address["value"],
        )
        monkeypatch.setattr(
            "squirrelops_home_sensor.decoys.orchestrator._interface_ipv4_addresses",
            lambda _: [],
        )
        orchestrator = DecoyOrchestrator(event_bus=event_bus, db=db, max_decoys=8)

        services = [{"ip": "10.0.0.1", "port": 22, "protocol": "tcp"}]
        assert await orchestrator.auto_deploy(services) == 0
        assert (await (await db.execute("SELECT COUNT(*) FROM decoys")).fetchone())[0] == 0
        assert (
            await (
                await db.execute("SELECT COUNT(*) FROM planted_credentials")
            ).fetchone()
        )[0] == 0

        route_address["value"] = bindable_lan_address
        assert await orchestrator.auto_deploy(services) == 1
        row = await (
            await db.execute("SELECT status, bind_address FROM decoys")
        ).fetchone()
        assert (row["status"], row["bind_address"]) == (
            "active",
            bindable_lan_address,
        )

    async def test_deploys_file_share_fallback(self, orchestrator, db, event_bus):
        """Deploys a file share decoy when no recognizable ports detected."""
        services = [{"ip": "10.0.0.1", "port": 22, "protocol": "tcp"}]
        deployed = await orchestrator.auto_deploy(services)

        assert deployed == 1

        # Verify DB row was created
        cursor = await db.execute("SELECT * FROM decoys")
        rows = await cursor.fetchall()
        assert len(rows) == 1
        assert rows[0]["decoy_type"] == "file_share"
        assert rows[0]["name"] == "Network Share"
        assert rows[0]["status"] == "active"

    async def test_deploys_dev_server_for_dev_ports(self, orchestrator, db):
        """Deploys a dev server decoy when dev ports detected."""
        services = [{"ip": "10.0.0.1", "port": 3000, "protocol": "tcp"}]
        deployed = await orchestrator.auto_deploy(services)

        assert deployed == 1
        cursor = await db.execute("SELECT decoy_type FROM decoys")
        row = await cursor.fetchone()
        assert row["decoy_type"] == "dev_server"

    async def test_deploys_multiple_types(self, orchestrator, db):
        """Deploys multiple decoy types when multiple service categories detected."""
        services = [
            {"ip": "10.0.0.1", "port": 3000, "protocol": "tcp"},
            {"ip": "10.0.0.2", "port": 8123, "protocol": "tcp"},
            {"ip": "10.0.0.3", "port": 445, "protocol": "tcp"},
        ]
        deployed = await orchestrator.auto_deploy(services)

        assert deployed == 3
        cursor = await db.execute("SELECT decoy_type FROM decoys ORDER BY id")
        rows = await cursor.fetchall()
        types = {row["decoy_type"] for row in rows}
        assert types == {"dev_server", "home_assistant", "file_share"}

    async def test_generates_planted_credentials(self, orchestrator, db):
        """Auto-deploy generates and persists planted credentials."""
        services = [{"ip": "10.0.0.1", "port": 22, "protocol": "tcp"}]
        await orchestrator.auto_deploy(services)

        cursor = await db.execute("SELECT * FROM planted_credentials")
        rows = await cursor.fetchall()
        # File share generates passwords (8-12) + 1 SSH key
        assert len(rows) >= 9

    async def test_publishes_status_changed_events(self, orchestrator, db, event_bus):
        """Auto-deploy publishes decoy.status_changed for the app."""
        services = [{"ip": "10.0.0.1", "port": 22, "protocol": "tcp"}]
        await orchestrator.auto_deploy(services)

        # Find the decoy.status_changed publish call
        status_calls = [
            call for call in event_bus.publish.call_args_list
            if call.args[0] == "decoy.status_changed"
        ]
        assert len(status_calls) == 1
        payload = status_calls[0].args[1]
        assert payload["decoy_type"] == "file_share"
        assert payload["status"] == "active"
        assert "id" in payload
        assert "port" in payload

    async def test_port_updated_after_start(self, orchestrator, db):
        """Decoy port is updated in DB after start (OS-assigned from port=0)."""
        services = [{"ip": "10.0.0.1", "port": 22, "protocol": "tcp"}]
        await orchestrator.auto_deploy(services)

        cursor = await db.execute("SELECT port FROM decoys")
        row = await cursor.fetchone()
        # Port should be non-zero after the emulator starts
        assert row["port"] > 0


class TestResumeActive:
    async def test_resumes_active_decoys(self, orchestrator, db, event_bus):
        """Resume loads active decoys from DB and starts them."""
        await db.execute(
            """INSERT INTO decoys (name, decoy_type, bind_address, port, status, config, created_at, updated_at)
               VALUES ('Test Share', 'file_share', '0.0.0.0', 0, 'active', '{}', '2026-01-01', '2026-01-01')"""
        )
        await db.commit()

        resumed = await orchestrator.resume_active()
        assert resumed == 1
        # Verify the decoy is now tracked
        assert len(orchestrator._records) == 1

    async def test_skips_stopped_decoys(self, orchestrator, db):
        """Resume only loads active decoys, not stopped ones."""
        await db.execute(
            """INSERT INTO decoys (name, decoy_type, bind_address, port, status, config, created_at, updated_at)
               VALUES ('Stopped', 'file_share', '0.0.0.0', 0, 'stopped', '{}', '2026-01-01', '2026-01-01')"""
        )
        await db.commit()

        resumed = await orchestrator.resume_active()
        assert resumed == 0

    async def test_resume_empty_db(self, orchestrator, db):
        """Resume returns 0 when no decoys in database."""
        resumed = await orchestrator.resume_active()
        assert resumed == 0

    async def test_resume_stops_rows_above_current_profile_limit(
        self, event_bus, db,
    ):
        """Startup cannot reactivate more classic listeners than the profile allows."""
        orchestrator = DecoyOrchestrator(
            event_bus=event_bus,
            db=db,
            max_decoys=1,
        )
        await db.executemany(
            """INSERT INTO decoys
               (name, decoy_type, bind_address, port, status, config,
                created_at, updated_at)
               VALUES (?, ?, '0.0.0.0', 0, 'active', '{}',
                       '2026-01-01', '2026-01-01')""",
            [
                ("Share", "file_share"),
                ("Dev Server", "dev_server"),
            ],
        )
        await db.commit()

        resumed = await orchestrator.resume_active()

        assert resumed == 1
        cursor = await db.execute("SELECT status FROM decoys ORDER BY id")
        assert [row["status"] for row in await cursor.fetchall()] == [
            "active",
            "stopped",
        ]

    async def test_resume_loads_credentials(self, orchestrator, db):
        """Resume loads planted credentials for the decoy."""
        await db.execute(
            """INSERT INTO decoys (id, name, decoy_type, bind_address, port, status, config, created_at, updated_at)
               VALUES (1, 'Share', 'file_share', '0.0.0.0', 0, 'active', '{}', '2026-01-01', '2026-01-01')"""
        )
        await db.execute(
            """INSERT INTO planted_credentials
               (credential_type, credential_value, planted_location, decoy_id, created_at)
               VALUES ('password', 'admin:Test123!', 'passwords.txt', 1, '2026-01-01')"""
        )
        await db.commit()

        resumed = await orchestrator.resume_active()
        assert resumed == 1

        # The deployed decoy should have the credential loaded
        record = orchestrator._records[1]
        assert len(record.decoy._planted_credentials) == 1
        assert record.decoy._planted_credentials[0].credential_value == "admin:Test123!"
