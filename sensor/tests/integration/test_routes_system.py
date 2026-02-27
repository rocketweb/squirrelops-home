"""Integration tests for system routes: health, status, profile, learning."""
import asyncio
import json
import time

import pytest
from fastapi.testclient import TestClient

from squirrelops_home_sensor import __version__


class TestHealthEndpoint:
    """GET /system/health -- no auth required."""

    def test_health_returns_200(self, client):
        response = client.get("/system/health")
        assert response.status_code == 200

    def test_health_contains_required_fields(self, client):
        response = client.get("/system/health")
        data = response.json()
        assert "version" in data
        assert "sensor_id" in data
        assert "uptime_seconds" in data

    def test_health_version_matches_config(self, client, sensor_config):
        response = client.get("/system/health")
        data = response.json()
        assert data["version"] == __version__

    def test_health_sensor_id_matches_config(self, client, sensor_config):
        response = client.get("/system/health")
        data = response.json()
        assert data["sensor_id"] == sensor_config["sensor_id"]

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
        assert "profile" in data
        assert "learning_mode" in data
        assert "device_count" in data
        assert "decoy_count" in data
        assert "alert_count" in data

    def test_status_profile_matches_config(self, client, sensor_config):
        response = client.get("/system/status")
        data = response.json()
        assert data["profile"] == sensor_config["profile"]

    def test_status_counts_reflect_database(self, client, db):
        from tests.integration.conftest import seed_devices, seed_decoys, seed_alerts

        asyncio.get_event_loop().run_until_complete(seed_devices(db, count=5))
        asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=3))
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=7))

        response = client.get("/system/status")
        data = response.json()
        assert data["device_count"] == 5
        assert data["decoy_count"] == 3
        assert data["alert_count"] == 7


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
        assert data["max_decoys"] >= 16


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
        from datetime import datetime, timezone, timedelta

        started = datetime.now(timezone.utc) - timedelta(hours=12)
        sensor_config["learning_mode"]["enabled"] = True
        sensor_config["learning_mode"]["started_at"] = started.isoformat()
        response = client.get("/system/learning")
        data = response.json()
        assert data["enabled"] is True
        assert 11 <= data["hours_elapsed"] <= 13  # approximately 12 hours
        assert data["hours_total"] == 48
        assert data["phase"] == "learning"

    def test_learning_mode_past_48_hours_shows_complete(self, client, sensor_config):
        from datetime import datetime, timezone, timedelta

        started = datetime.now(timezone.utc) - timedelta(hours=50)
        sensor_config["learning_mode"]["enabled"] = True
        sensor_config["learning_mode"]["started_at"] = started.isoformat()
        response = client.get("/system/learning")
        data = response.json()
        assert data["phase"] == "complete"


class TestUpdateCheckEndpoint:
    """GET /system/updates -- update checking."""

    def test_check_updates_no_manifest(self, client):
        """Update check returns gracefully when no manifest URL configured."""
        resp = client.get("/system/updates")
        assert resp.status_code == 200
        data = resp.json()
        assert "current_version" in data
        assert data["update_available"] is False
        assert "No update source" in data["message"]
