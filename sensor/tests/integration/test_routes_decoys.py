"""Integration tests for decoy routes: list, get, restart, update config, connections."""
import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from tests.integration.conftest import seed_decoys


class _FakeDecoyOrchestrator:
    def __init__(self, db):
        self.db = db

    async def restart_decoy(self, decoy_id):
        return await self.enable_decoy(decoy_id)

    async def enable_decoy(self, decoy_id):
        now = datetime.now(UTC).isoformat()
        await self.db.execute(
            """UPDATE decoys SET status = 'active', failure_count = 0,
               last_failure_at = NULL, updated_at = ? WHERE id = ?""",
            (now, decoy_id),
        )
        await self.db.commit()
        return True

    async def disable_decoy(self, decoy_id):
        now = datetime.now(UTC).isoformat()
        await self.db.execute(
            "UPDATE decoys SET status = 'stopped', updated_at = ? WHERE id = ?",
            (now, decoy_id),
        )
        await self.db.commit()
        return True


class _FakeMimicOrchestrator:
    def __init__(self, db):
        self.db = db
        self.calls = []
        self.degraded_ids = set()

    def effective_mimic_status(self, decoy_id, persisted_status):
        if persisted_status == "active" and decoy_id in self.degraded_ids:
            return "degraded"
        return persisted_status

    async def restart_mimic(self, decoy_id):
        self.calls.append(("restart", decoy_id))
        return await self.enable_mimic(decoy_id)

    async def enable_mimic(self, decoy_id):
        self.calls.append(("enable", decoy_id))
        await self.db.execute(
            "UPDATE decoys SET status = 'active' WHERE id = ?", (decoy_id,)
        )
        await self.db.commit()
        return True

    async def disable_mimic(self, decoy_id):
        self.calls.append(("disable", decoy_id))
        await self.db.execute(
            "UPDATE decoys SET status = 'stopped' WHERE id = ?", (decoy_id,)
        )
        await self.db.commit()
        return True


@pytest.fixture(autouse=True)
def live_decoy_controls(app, db):
    from squirrelops_home_sensor.api.routes_decoys import get_decoy_orchestrator
    from squirrelops_home_sensor.api.routes_scouts import get_mimic_orchestrator

    classic = _FakeDecoyOrchestrator(db)
    mimic = _FakeMimicOrchestrator(db)
    app.dependency_overrides[get_decoy_orchestrator] = lambda: classic
    app.dependency_overrides[get_mimic_orchestrator] = lambda: mimic
    yield classic, mimic
    app.dependency_overrides.pop(get_decoy_orchestrator, None)
    app.dependency_overrides.pop(get_mimic_orchestrator, None)


async def seed_decoy_connections(db, decoy_id, count=3):
    """Insert test decoy connections. Returns list of connection IDs."""
    ids = []
    for i in range(1, count + 1):
        cursor = await db.execute(
            """INSERT INTO decoy_connections
               (decoy_id, source_ip, source_mac, port, protocol, request_path, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                decoy_id,
                f"192.168.1.{50 + i}",
                f"FF:FF:FF:FF:FF:{i:02X}",
                8080,
                "tcp",
                f"/path-{i}",
                f"2026-02-22T{i:02d}:00:00Z",
            ),
        )
        ids.append(cursor.lastrowid)
    await db.commit()
    return ids


class TestListDecoys:
    """GET /decoys -- list with status and connection counts."""

    def test_list_returns_200(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=2))
        response = client.get("/decoys")
        assert response.status_code == 200

    def test_list_returns_all_decoys(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=2))
        response = client.get("/decoys")
        data = response.json()
        assert len(data["items"]) == 2

    def test_list_includes_status(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        response = client.get("/decoys")
        data = response.json()
        assert data["items"][0]["status"] == "active"

    def test_list_overlays_unpublished_mimic_as_degraded(
        self,
        client,
        db,
        live_decoy_controls,
    ):
        asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        row = asyncio.get_event_loop().run_until_complete(
            db.execute("SELECT id FROM decoys ORDER BY id LIMIT 1")
        )
        decoy_id = asyncio.get_event_loop().run_until_complete(
            row.fetchone()
        )[0]
        asyncio.get_event_loop().run_until_complete(
            db.execute(
                "UPDATE decoys SET decoy_type = 'mimic' WHERE id = ?",
                (decoy_id,),
            )
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        live_decoy_controls[1].degraded_ids.add(decoy_id)

        response = client.get("/decoys")

        assert response.status_code == 200
        assert response.json()["items"][0]["status"] == "degraded"

    def test_list_includes_connection_count(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        response = client.get("/decoys")
        data = response.json()
        assert "connection_count" in data["items"][0]

    def test_list_includes_credential_trip_count(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        response = client.get("/decoys")
        data = response.json()
        assert "credential_trip_count" in data["items"][0]

    def test_list_empty_database(self, client, db):
        response = client.get("/decoys")
        data = response.json()
        assert data["items"] == []


class TestGetDecoy:
    """GET /decoys/{id} -- detail with connection log summary."""

    def test_get_returns_200(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        response = client.get(f"/decoys/{ids[0]}")
        assert response.status_code == 200

    def test_get_returns_decoy_fields(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        response = client.get(f"/decoys/{ids[0]}")
        data = response.json()
        assert "id" in data
        assert "name" in data
        assert "decoy_type" in data
        assert "bind_address" in data
        assert "port" in data
        assert "status" in data
        assert "config" in data
        assert "connection_count" in data
        assert "credential_trip_count" in data
        assert "created_at" in data

    def test_get_includes_config_as_object(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        response = client.get(f"/decoys/{ids[0]}")
        data = response.json()
        assert isinstance(data["config"], dict)
        assert "banner" in data["config"]

    def test_get_nonexistent_returns_404(self, client, db):
        response = client.get("/decoys/9999")
        assert response.status_code == 404


class TestRestartDecoy:
    """POST /decoys/{id}/restart -- restart a decoy service."""

    def test_restart_returns_200(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        response = client.post(f"/decoys/{ids[0]}/restart")
        assert response.status_code == 200

    def test_restart_returns_decoy_status(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        response = client.post(f"/decoys/{ids[0]}/restart")
        data = response.json()
        assert data["status"] in ("active", "restarting")

    def test_restart_resets_failure_count(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        # Set failure count
        asyncio.get_event_loop().run_until_complete(
            db.execute("UPDATE decoys SET failure_count = 3 WHERE id = ?", (ids[0],))
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        response = client.post(f"/decoys/{ids[0]}/restart")
        data = response.json()
        assert data["failure_count"] == 0

    def test_restart_nonexistent_returns_404(self, client, db):
        response = client.post("/decoys/9999/restart")
        assert response.status_code == 404

    def test_restart_controls_mimic_runtime(
        self, client, db, live_decoy_controls,
    ):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        asyncio.get_event_loop().run_until_complete(
            db.execute(
                "UPDATE decoys SET decoy_type = 'mimic' WHERE id = ?", (ids[0],)
            )
        )
        asyncio.get_event_loop().run_until_complete(db.commit())

        response = client.post(f"/decoys/{ids[0]}/restart")

        assert response.status_code == 200
        assert ("restart", ids[0]) in live_decoy_controls[1].calls


class TestEnableDecoy:
    """POST /decoys/{id}/enable -- enable a stopped decoy."""

    def test_enable_returns_200(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        # Set decoy to stopped first
        asyncio.get_event_loop().run_until_complete(
            db.execute("UPDATE decoys SET status = 'stopped' WHERE id = ?", (ids[0],))
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        response = client.post(f"/decoys/{ids[0]}/enable")
        assert response.status_code == 200

    def test_enable_sets_status_active(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        asyncio.get_event_loop().run_until_complete(
            db.execute("UPDATE decoys SET status = 'stopped' WHERE id = ?", (ids[0],))
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        response = client.post(f"/decoys/{ids[0]}/enable")
        data = response.json()
        assert data["status"] == "active"

    def test_enable_resets_failure_count(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        asyncio.get_event_loop().run_until_complete(
            db.execute(
                "UPDATE decoys SET status = 'stopped', failure_count = 3 WHERE id = ?",
                (ids[0],),
            )
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        response = client.post(f"/decoys/{ids[0]}/enable")
        data = response.json()
        assert data["failure_count"] == 0

    def test_enable_already_active_is_noop(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        # Decoy is already active by default from seed
        response = client.post(f"/decoys/{ids[0]}/enable")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "active"

    def test_enable_nonexistent_returns_404(self, client, db):
        response = client.post("/decoys/9999/enable")
        assert response.status_code == 404

    def test_enable_failure_does_not_fake_active_state(
        self, client, db, live_decoy_controls,
    ):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        asyncio.get_event_loop().run_until_complete(
            db.execute("UPDATE decoys SET status = 'stopped' WHERE id = ?", (ids[0],))
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        live_decoy_controls[0].enable_decoy = AsyncMock(return_value=False)

        response = client.post(f"/decoys/{ids[0]}/enable")

        assert response.status_code == 409
        cursor = asyncio.get_event_loop().run_until_complete(
            db.execute("SELECT status FROM decoys WHERE id = ?", (ids[0],))
        )
        assert asyncio.get_event_loop().run_until_complete(cursor.fetchone())[0] == "stopped"


class TestDisableDecoy:
    """POST /decoys/{id}/disable -- disable an active decoy."""

    def test_disable_returns_200(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        response = client.post(f"/decoys/{ids[0]}/disable")
        assert response.status_code == 200

    def test_disable_sets_status_stopped(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        response = client.post(f"/decoys/{ids[0]}/disable")
        data = response.json()
        assert data["status"] == "stopped"

    def test_disable_already_stopped_is_noop(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        asyncio.get_event_loop().run_until_complete(
            db.execute("UPDATE decoys SET status = 'stopped' WHERE id = ?", (ids[0],))
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        response = client.post(f"/decoys/{ids[0]}/disable")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "stopped"

    def test_disable_nonexistent_returns_404(self, client, db):
        response = client.post("/decoys/9999/disable")
        assert response.status_code == 404

    def test_disable_controls_mimic_runtime(
        self, client, db, live_decoy_controls,
    ):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        asyncio.get_event_loop().run_until_complete(
            db.execute(
                "UPDATE decoys SET decoy_type = 'mimic' WHERE id = ?", (ids[0],)
            )
        )
        asyncio.get_event_loop().run_until_complete(db.commit())

        response = client.post(f"/decoys/{ids[0]}/disable")

        assert response.status_code == 200
        assert ("disable", ids[0]) in live_decoy_controls[1].calls
        assert response.json()["status"] == "stopped"


class TestUpdateDecoyConfig:
    """PUT /decoys/{id}/config -- update decoy-specific configuration."""

    def test_update_config_returns_200(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        response = client.put(
            f"/decoys/{ids[0]}/config",
            json={"banner": "new-banner", "delay_ms": 100},
        )
        assert response.status_code == 200

    def test_update_config_merges_with_existing(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        response = client.put(
            f"/decoys/{ids[0]}/config",
            json={"delay_ms": 200},
        )
        data = response.json()
        config = data["config"]
        # Original banner should still be present
        assert "banner" in config
        # New key should be added
        assert config["delay_ms"] == 200

    def test_update_config_overwrites_existing_keys(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        response = client.put(
            f"/decoys/{ids[0]}/config",
            json={"banner": "updated-banner"},
        )
        data = response.json()
        assert data["config"]["banner"] == "updated-banner"

    def test_update_config_nonexistent_returns_404(self, client, db):
        response = client.put("/decoys/9999/config", json={"key": "value"})
        assert response.status_code == 404


class TestDecoyConnections:
    """GET /decoys/{id}/connections -- paginated connection log."""

    def test_connections_returns_200(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        response = client.get(f"/decoys/{ids[0]}/connections")
        assert response.status_code == 200

    def test_connections_returns_entries(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        asyncio.get_event_loop().run_until_complete(
            seed_decoy_connections(db, ids[0], count=3)
        )
        response = client.get(f"/decoys/{ids[0]}/connections")
        data = response.json()
        assert len(data["items"]) == 3

    def test_connections_pagination(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        asyncio.get_event_loop().run_until_complete(
            seed_decoy_connections(db, ids[0], count=5)
        )
        response = client.get(f"/decoys/{ids[0]}/connections?limit=2")
        data = response.json()
        assert len(data["items"]) == 2
        assert data["total"] == 5

    def test_connections_ordered_by_timestamp_desc(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        asyncio.get_event_loop().run_until_complete(
            seed_decoy_connections(db, ids[0], count=3)
        )
        response = client.get(f"/decoys/{ids[0]}/connections")
        data = response.json()
        items = data["items"]
        for i in range(len(items) - 1):
            assert items[i]["timestamp"] >= items[i + 1]["timestamp"]

    def test_connections_includes_source_fields(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        asyncio.get_event_loop().run_until_complete(
            seed_decoy_connections(db, ids[0], count=1)
        )
        response = client.get(f"/decoys/{ids[0]}/connections")
        data = response.json()
        item = data["items"][0]
        assert "source_ip" in item
        assert "source_mac" in item
        assert "port" in item
        assert "protocol" in item
        assert "timestamp" in item

    def test_connections_empty(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
        response = client.get(f"/decoys/{ids[0]}/connections")
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_connections_nonexistent_decoy_returns_404(self, client, db):
        response = client.get("/decoys/9999/connections")
        assert response.status_code == 404
