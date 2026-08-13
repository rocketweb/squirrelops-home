"""Integration tests for system routes: health, status, profile, learning."""
import asyncio
from datetime import UTC
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from squirrelops_home_sensor import __version__
from squirrelops_home_sensor.compatibility import SENSOR_API_PROTOCOL_VERSION


class TestHealthEndpoint:
    """GET /system/health -- unauthenticated liveness probe only."""

    def test_health_returns_200(self, client):
        response = client.get("/system/health")
        assert response.status_code == 200

    def test_health_is_liveness_only(self, client):
        response = client.get("/system/health")
        data = response.json()
        assert data["status"] == "ok"
        assert "uptime_seconds" in data

    def test_health_does_not_leak_version_or_sensor_id(self, client):
        """Unauthenticated callers must not learn the version or sensor_id."""
        data = client.get("/system/health").json()
        assert "version" not in data
        assert "sensor_id" not in data

    def test_health_uptime_is_non_negative(self, client):
        response = client.get("/system/health")
        data = response.json()
        assert data["uptime_seconds"] >= 0


class TestStatusEndpoint:
    """GET /system/status -- requires auth."""

    def test_status_returns_200(self, client, db):
        response = client.get("/system/status")
        assert response.status_code == 200

    def test_status_contains_required_fields(self, client, db):
        response = client.get("/system/status")
        data = response.json()
        assert "version" in data
        assert "profile" in data
        assert "learning_mode" in data
        assert "device_count" in data
        assert "decoy_count" in data
        assert "alert_count" in data

    def test_status_exposes_version_only_after_authentication(self, client):
        data = client.get("/system/status").json()
        assert data["version"] == __version__
        assert data["api_protocol_version"] == SENSOR_API_PROTOCOL_VERSION

    def test_status_profile_matches_config(self, client, sensor_config):
        response = client.get("/system/status")
        data = response.json()
        assert data["profile"] == sensor_config["profile"]

    def test_status_counts_reflect_database(self, client, db):
        from tests.integration.conftest import seed_alerts, seed_decoys, seed_devices

        asyncio.get_event_loop().run_until_complete(seed_devices(db, count=5))
        asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=3))
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=7))

        response = client.get("/system/status")
        data = response.json()
        assert data["device_count"] == 5
        assert data["decoy_count"] == 3
        assert data["alert_count"] == 7

    def test_status_counts_only_operational_mimics(
        self,
        client,
        app,
        db,
    ):
        from squirrelops_home_sensor.api.routes_scouts import (
            get_mimic_orchestrator,
        )
        from tests.integration.conftest import seed_decoys

        asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=3))
        asyncio.get_event_loop().run_until_complete(
            db.execute(
                "UPDATE decoys SET decoy_type = 'mimic' WHERE id IN (1, 2)"
            )
        )
        asyncio.get_event_loop().run_until_complete(db.commit())

        async def mimic_dependency():
            return SimpleNamespace(active_count=1)

        app.dependency_overrides[get_mimic_orchestrator] = mimic_dependency
        try:
            response = client.get("/system/status")
        finally:
            app.dependency_overrides.pop(get_mimic_orchestrator, None)

        assert response.status_code == 200
        # One classic plus one operational mimic; the second DB-active mimic
        # is excluded until its network publication is verified.
        assert response.json()["decoy_count"] == 2

    def test_status_includes_event_cursor_for_snapshot_replay(self, client, db):
        """REST bootstrap exposes the point from which WebSocket replay starts."""
        asyncio.get_event_loop().run_until_complete(
            db.executemany(
                """INSERT INTO events (event_type, payload, created_at)
                   VALUES (?, '{}', '2026-07-23T00:00:00Z')""",
                [
                    ("device.updated",),
                    ("alert.new",),
                    ("system.status_changed",),
                ],
            )
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        cursor = asyncio.get_event_loop().run_until_complete(
            db.execute("SELECT MAX(seq) FROM events")
        )
        latest_seq = asyncio.get_event_loop().run_until_complete(
            cursor.fetchone()
        )[0]

        response = client.get("/system/status")

        assert response.status_code == 200
        assert response.json()["event_seq"] == latest_seq

    def test_status_decoy_count_excludes_stopped_records(self, client, db):
        asyncio.get_event_loop().run_until_complete(
            db.execute(
                """INSERT INTO decoys
                   (name, decoy_type, bind_address, port, status, config,
                    created_at, updated_at)
                   VALUES
                   ('active', 'file_share', '192.168.1.18', 63217, 'active',
                    '{}', '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z'),
                   ('stopped mimic', 'mimic', '192.168.1.202', 80, 'stopped',
                    '{}', '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z')"""
            )
        )
        asyncio.get_event_loop().run_until_complete(db.commit())

        response = client.get("/system/status")

        assert response.status_code == 200
        assert response.json()["decoy_count"] == 1

    def test_status_device_count_excludes_mimic_decoys(self, client, db):
        from tests.integration.conftest import seed_devices

        asyncio.get_event_loop().run_until_complete(seed_devices(db, count=3))
        asyncio.get_event_loop().run_until_complete(
            db.execute(
                """INSERT INTO decoys
                   (name, decoy_type, bind_address, port, status, config,
                    created_at, updated_at)
                   VALUES ('files.local', 'mimic', '192.168.1.102', 80,
                           'active', '{}', '2026-02-22T00:00:00Z',
                           '2026-02-22T00:00:00Z')"""
            )
        )
        asyncio.get_event_loop().run_until_complete(db.commit())

        response = client.get("/system/status")
        data = response.json()
        assert data["device_count"] == 2


class TestProfileEndpoints:
    """GET /system/profile and PUT /system/profile."""

    def test_get_profile_returns_200(self, client):
        response = client.get("/system/profile")
        assert response.status_code == 200

    def test_get_profile_contains_profile_name(self, client, sensor_config):
        response = client.get("/system/profile")
        data = response.json()
        assert data["profile"] == sensor_config["profile"]

    def test_get_profile_contains_settings(self, client):
        response = client.get("/system/profile")
        data = response.json()
        assert "scan_interval_seconds" in data
        assert "max_decoys" in data

    def test_profile_uses_endpoint_location_for_editable_local_provider(
        self,
        client,
        sensor_config,
    ):
        sensor_config["classifier"] = {
            "mode": "cloud_llm",
            "llm_provider": "lmstudio",
            "llm_endpoint": "https://models.example.com/v1",
            "llm_model": "model",
        }
        assert client.get("/system/profile").json()["llm_classification"] == (
            "cloud_llm"
        )

        sensor_config["classifier"]["llm_endpoint"] = (
            "http://models.home.localdomain:1234/v1"
        )
        assert client.get("/system/profile").json()["llm_classification"] == (
            "local_llm"
        )

    def test_put_profile_switches_profile(self, client, sensor_config):
        response = client.put(
            "/system/profile",
            json={"profile": "lite"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["profile"] == "lite"

    def test_put_profile_invalid_profile_returns_422(self, client):
        response = client.put(
            "/system/profile",
            json={"profile": "nonexistent"},
        )
        assert response.status_code == 422

    def test_put_profile_updates_scan_interval(self, client):
        response = client.put(
            "/system/profile",
            json={"profile": "lite"},
        )
        data = response.json()
        assert data["scan_interval_seconds"] == 900  # 15 min for lite

    def test_put_profile_full_has_correct_limits(self, client):
        response = client.put(
            "/system/profile",
            json={"profile": "full"},
        )
        data = response.json()
        assert data["scan_interval_seconds"] == 60  # 1 min for full
        assert data["max_decoys"] == 3
        assert data["max_mimic_decoys"] == 10
        assert data["total_decoy_capacity"] == 13

    def test_put_profile_reconfigures_all_live_subsystems(
        self, client, app, sensor_config,
    ):
        from squirrelops_home_sensor.api.routes_decoys import get_decoy_orchestrator
        from squirrelops_home_sensor.api.routes_scouts import (
            get_mimic_orchestrator,
            get_scout_scheduler,
        )
        from squirrelops_home_sensor.api.routes_system import get_scan_loop

        scan_loop = SimpleNamespace(scan_interval=300, set_scan_interval=Mock())
        scheduler = SimpleNamespace(
            interval_minutes=60,
            reconfigure=AsyncMock(),
        )
        decoys = SimpleNamespace(
            max_decoys=8,
            reconfigure=AsyncMock(return_value=[]),
        )
        mimics = SimpleNamespace(
            max_mimics=10,
            reconfigure=AsyncMock(return_value=[]),
        )

        async def scan_dependency():
            return scan_loop

        async def scheduler_dependency():
            return scheduler

        async def decoy_dependency():
            return decoys

        async def mimic_dependency():
            return mimics

        app.dependency_overrides[get_scan_loop] = scan_dependency
        app.dependency_overrides[get_scout_scheduler] = scheduler_dependency
        app.dependency_overrides[get_decoy_orchestrator] = decoy_dependency
        app.dependency_overrides[get_mimic_orchestrator] = mimic_dependency

        response = client.put("/system/profile", json={"profile": "full"})

        assert response.status_code == 200
        scan_loop.set_scan_interval.assert_called_once_with(60)
        scheduler.reconfigure.assert_awaited_once_with(30)
        decoys.reconfigure.assert_awaited_once_with(3)
        mimics.reconfigure.assert_awaited_once_with(10)
        assert sensor_config["network"]["scan_interval"] == 60
        assert sensor_config["scouts"]["max_mimic_decoys"] == 10
        assert sensor_config["scouts"]["max_virtual_ips"] == 10

    def test_failed_live_profile_change_is_not_persisted(
        self, client, app, sensor_config,
    ):
        from squirrelops_home_sensor.api.routes_decoys import get_decoy_orchestrator
        from squirrelops_home_sensor.api.routes_scouts import (
            get_mimic_orchestrator,
            get_scout_scheduler,
        )
        from squirrelops_home_sensor.api.routes_system import get_scan_loop

        scan_loop = SimpleNamespace(scan_interval=300, set_scan_interval=Mock())
        scheduler = SimpleNamespace(
            interval_minutes=60,
            reconfigure=AsyncMock(),
        )
        decoys = SimpleNamespace(
            max_decoys=8,
            reconfigure=AsyncMock(return_value=[]),
        )
        mimics = SimpleNamespace(
            max_mimics=10,
            reconfigure=AsyncMock(side_effect=RuntimeError("no helper")),
        )

        async def scan_dependency():
            return scan_loop

        async def scheduler_dependency():
            return scheduler

        async def decoy_dependency():
            return decoys

        async def mimic_dependency():
            return mimics

        app.dependency_overrides[get_scan_loop] = scan_dependency
        app.dependency_overrides[get_scout_scheduler] = scheduler_dependency
        app.dependency_overrides[get_decoy_orchestrator] = decoy_dependency
        app.dependency_overrides[get_mimic_orchestrator] = mimic_dependency

        with patch(
            "squirrelops_home_sensor.api.routes_config._persist_config"
        ) as persist:
            response = client.put("/system/profile", json={"profile": "full"})

        assert response.status_code == 500
        assert sensor_config["profile"] == "standard"
        persist.assert_not_called()

    def test_persistence_failure_restores_config_and_live_limits(
        self, client, app, sensor_config,
    ):
        from squirrelops_home_sensor.api.routes_decoys import get_decoy_orchestrator
        from squirrelops_home_sensor.api.routes_scouts import (
            get_mimic_orchestrator,
            get_scout_scheduler,
        )
        from squirrelops_home_sensor.api.routes_system import get_scan_loop

        scan_loop = SimpleNamespace(scan_interval=300, set_scan_interval=Mock())
        scheduler = SimpleNamespace(
            interval_minutes=60,
            reconfigure=AsyncMock(),
        )
        decoys = SimpleNamespace(
            max_decoys=8,
            reconfigure=AsyncMock(return_value=[]),
        )
        mimics = SimpleNamespace(
            max_mimics=10,
            reconfigure=AsyncMock(return_value=[]),
        )

        async def scan_dependency():
            return scan_loop

        async def scheduler_dependency():
            return scheduler

        async def decoy_dependency():
            return decoys

        async def mimic_dependency():
            return mimics

        app.dependency_overrides[get_scan_loop] = scan_dependency
        app.dependency_overrides[get_scout_scheduler] = scheduler_dependency
        app.dependency_overrides[get_decoy_orchestrator] = decoy_dependency
        app.dependency_overrides[get_mimic_orchestrator] = mimic_dependency

        with patch(
            "squirrelops_home_sensor.api.routes_config._persist_config",
            side_effect=RuntimeError("disk full"),
        ):
            response = client.put("/system/profile", json={"profile": "full"})

        assert response.status_code == 500
        assert sensor_config["profile"] == "standard"
        assert sensor_config["scan_interval_seconds"] == 300
        assert sensor_config["max_decoys"] == 8
        assert "network" not in sensor_config
        assert "scouts" not in sensor_config
        assert [call.args for call in scan_loop.set_scan_interval.call_args_list] == [
            (60,),
            (300,),
        ]
        assert [call.args for call in scheduler.reconfigure.await_args_list] == [
            (30,),
            (60,),
        ]
        assert [call.args for call in decoys.reconfigure.await_args_list] == [
            (3,),
            (8,),
        ]
        assert [call.args for call in mimics.reconfigure.await_args_list] == [
            (10,),
            (10,),
        ]


class TestLearningEndpoint:
    """GET /system/learning -- learning mode progress."""

    def test_learning_returns_200(self, client):
        response = client.get("/system/learning")
        assert response.status_code == 200

    def test_learning_contains_required_fields(self, client):
        response = client.get("/system/learning")
        data = response.json()
        assert "enabled" in data
        assert "hours_elapsed" in data
        assert "hours_total" in data
        assert "phase" in data

    def test_learning_mode_disabled_shows_complete(self, client, sensor_config):
        sensor_config["learning_mode"]["enabled"] = False
        response = client.get("/system/learning")
        data = response.json()
        assert data["enabled"] is False
        assert data["phase"] == "complete"

    def test_learning_mode_enabled_shows_progress(self, client, sensor_config):
        from datetime import datetime, timedelta

        started = datetime.now(UTC) - timedelta(hours=12)
        sensor_config["learning_mode"]["enabled"] = True
        sensor_config["learning_mode"]["started_at"] = started.isoformat()
        response = client.get("/system/learning")
        data = response.json()
        assert data["enabled"] is True
        assert 11 <= data["hours_elapsed"] <= 13  # approximately 12 hours
        assert data["hours_total"] == 48
        assert data["phase"] == "learning"

    def test_learning_mode_past_48_hours_shows_complete(self, client, sensor_config):
        from datetime import datetime, timedelta

        started = datetime.now(UTC) - timedelta(hours=50)
        sensor_config["learning_mode"]["enabled"] = True
        sensor_config["learning_mode"]["started_at"] = started.isoformat()
        response = client.get("/system/learning")
        data = response.json()
        assert data["phase"] == "complete"
