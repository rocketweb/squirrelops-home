"""Integration tests for config routes: get/set config, alert methods, ha-status."""
import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient


class TestGetConfig:
    """GET /config -- full sensor configuration."""

    def test_get_config_returns_200(self, client):
        response = client.get("/config")
        assert response.status_code == 200

    def test_get_config_returns_full_config(self, client, sensor_config):
        response = client.get("/config")
        data = response.json()
        assert data["sensor_id"] == sensor_config["sensor_id"]
        assert data["sensor_name"] == sensor_config["sensor_name"]
        assert data["profile"] == sensor_config["profile"]

    def test_get_config_includes_learning_mode(self, client):
        response = client.get("/config")
        data = response.json()
        assert "learning_mode" in data

    def test_get_config_includes_scan_interval(self, client):
        response = client.get("/config")
        data = response.json()
        assert "scan_interval_seconds" in data

    def test_get_config_includes_max_decoys(self, client):
        response = client.get("/config")
        data = response.json()
        assert "max_decoys" in data

    def test_get_config_includes_subnet(self, client):
        response = client.get("/config")
        data = response.json()
        assert "subnet" in data


class TestUpdateConfig:
    """PUT /config -- partial config update (merge semantics)."""

    def test_update_returns_200(self, client):
        response = client.put("/config", json={"subnet": "10.0.0.0/24"})
        assert response.status_code == 200

    def test_update_changes_specified_field(self, client):
        client.put("/config", json={"subnet": "10.0.0.0/24"})
        response = client.get("/config")
        data = response.json()
        assert data["subnet"] == "10.0.0.0/24"

    def test_update_preserves_unspecified_fields(self, client, sensor_config):
        client.put("/config", json={"subnet": "10.0.0.0/24"})
        response = client.get("/config")
        data = response.json()
        assert data["sensor_id"] == sensor_config["sensor_id"]
        assert data["profile"] == sensor_config["profile"]

    def test_update_multiple_fields(self, client):
        response = client.put(
            "/config",
            json={"subnet": "10.0.0.0/24", "scan_interval_seconds": 120},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["subnet"] == "10.0.0.0/24"
        assert data["scan_interval_seconds"] == 120

    def test_update_nested_field(self, client):
        response = client.put(
            "/config",
            json={
                "learning_mode": {
                    "enabled": True,
                    "started_at": "2026-02-22T12:00:00Z",
                    "duration_hours": 48,
                }
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["learning_mode"]["enabled"] is True

    def test_update_rejects_protected_fields(self, client, sensor_config):
        """sensor_id and version should not be overwritable via config update."""
        original_id = sensor_config["sensor_id"]
        response = client.put("/config", json={"sensor_id": "hacked-id"})
        # The update should either reject or silently ignore the protected field
        get_response = client.get("/config")
        assert get_response.json()["sensor_id"] == original_id

    def test_update_empty_body_returns_200(self, client):
        response = client.put("/config", json={})
        assert response.status_code == 200


class TestGetAlertMethods:
    """GET /config/alert-methods -- configured notification methods."""

    def test_get_alert_methods_returns_200(self, client):
        response = client.get("/config/alert-methods")
        assert response.status_code == 200

    def test_get_alert_methods_returns_configured_methods(self, client):
        response = client.get("/config/alert-methods")
        data = response.json()
        assert "log" in data
        assert data["log"]["enabled"] is True

    def test_get_alert_methods_includes_slack(self, client):
        response = client.get("/config/alert-methods")
        data = response.json()
        assert "slack" in data
        assert "enabled" in data["slack"]


class TestUpdateAlertMethods:
    """PUT /config/alert-methods -- update notification methods."""

    def test_update_alert_methods_returns_200(self, client):
        response = client.put(
            "/config/alert-methods",
            json={"slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/test"}},
        )
        assert response.status_code == 200

    def test_update_alert_methods_changes_config(self, client):
        client.put(
            "/config/alert-methods",
            json={"slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/test"}},
        )
        response = client.get("/config/alert-methods")
        data = response.json()
        assert data["slack"]["enabled"] is True
        assert data["slack"]["webhook_url"] == "https://hooks.slack.com/test"

    def test_update_alert_methods_preserves_other_methods(self, client):
        client.put(
            "/config/alert-methods",
            json={"slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/test"}},
        )
        response = client.get("/config/alert-methods")
        data = response.json()
        # log method should still be present
        assert "log" in data
        assert data["log"]["enabled"] is True

    def test_update_alert_methods_add_new_method(self, client):
        response = client.put(
            "/config/alert-methods",
            json={"apns": {"enabled": True, "device_token": "abc123"}},
        )
        assert response.status_code == 200
        data = response.json()
        assert "apns" in data


class TestHAStatus:
    """GET /config/ha-status -- Home Assistant connection status."""

    def test_ha_status_returns_200(self, client):
        response = client.get("/config/ha-status")
        assert response.status_code == 200

    def test_ha_status_disconnected_when_not_configured(self, client):
        """When HA is not configured, returns connected=false, device_count=0."""
        response = client.get("/config/ha-status")
        data = response.json()
        assert data["connected"] is False
        assert data["device_count"] == 0

    def test_ha_status_disconnected_when_disabled(self, client, sensor_config):
        """When HA is configured but disabled, returns connected=false."""
        sensor_config["home_assistant"] = {
            "enabled": False,
            "url": "http://ha.local:8123",
            "token": "test-token",
        }
        response = client.get("/config/ha-status")
        data = response.json()
        assert data["connected"] is False
        assert data["device_count"] == 0

    def test_ha_status_disconnected_when_missing_url(self, client, sensor_config):
        """When HA is enabled but missing URL, returns connected=false."""
        sensor_config["home_assistant"] = {
            "enabled": True,
            "url": "",
            "token": "test-token",
        }
        response = client.get("/config/ha-status")
        data = response.json()
        assert data["connected"] is False

    def test_ha_status_disconnected_when_missing_token(self, client, sensor_config):
        """When HA is enabled but missing token, returns connected=false."""
        sensor_config["home_assistant"] = {
            "enabled": True,
            "url": "http://ha.local:8123",
            "token": "",
        }
        response = client.get("/config/ha-status")
        data = response.json()
        assert data["connected"] is False

    @patch("squirrelops_home_sensor.api.routes_config.HomeAssistantClient")
    def test_ha_status_connected_with_devices(self, mock_client_cls, client, sensor_config):
        """When HA is configured and reachable, returns connected=true and device count."""
        sensor_config["home_assistant"] = {
            "enabled": True,
            "url": "http://ha.local:8123",
            "token": "test-token",
        }
        mock_instance = AsyncMock()
        mock_instance.test_connection.return_value = True
        mock_instance.get_devices.return_value = [
            {"id": "dev1"},
            {"id": "dev2"},
            {"id": "dev3"},
        ]
        mock_client_cls.return_value = mock_instance

        response = client.get("/config/ha-status")
        data = response.json()
        assert data["connected"] is True
        assert data["device_count"] == 3

    @patch("squirrelops_home_sensor.api.routes_config.HomeAssistantClient")
    def test_ha_status_connection_failed(self, mock_client_cls, client, sensor_config):
        """When HA is configured but unreachable, returns connected=false."""
        sensor_config["home_assistant"] = {
            "enabled": True,
            "url": "http://ha.local:8123",
            "token": "test-token",
        }
        mock_instance = AsyncMock()
        mock_instance.test_connection.return_value = False
        mock_client_cls.return_value = mock_instance

        response = client.get("/config/ha-status")
        data = response.json()
        assert data["connected"] is False
        assert data["device_count"] == 0
