"""Integration tests for config routes: get/set config, alert methods, ha-status."""
import stat
from copy import deepcopy
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from squirrelops_home_sensor.api.config_secrets import REDACTED


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
        # Flat "subnet" key gets mapped to nested network.subnet
        assert data["network"]["subnet"] == "10.0.0.0/24"

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
        # Flat keys get mapped to their nested model paths
        assert data["network"]["subnet"] == "10.0.0.0/24"
        assert data["network"]["scan_interval"] == 120

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
        assert response.status_code == 422
        get_response = client.get("/config")
        assert get_response.json()["sensor_id"] == original_id

    def test_update_rejects_profile_bypass(self, client, sensor_config):
        """Resource profiles change through the transactional system endpoint."""
        original_profile = sensor_config["profile"]

        response = client.put("/config", json={"profile": "full"})

        assert response.status_code == 422
        assert sensor_config["profile"] == original_profile

    def test_update_empty_body_returns_200(self, client):
        response = client.put("/config", json={})
        assert response.status_code == 200

    def test_empty_updates_are_rate_limited(self, client):
        with patch(
            "squirrelops_home_sensor.api.routes_config.CONFIG_UPDATES_PER_MINUTE",
            2,
        ):
            assert client.put("/config", json={}).status_code == 200
            assert client.put("/config", json={}).status_code == 200
            limited = client.put("/config", json={})
        assert limited.status_code == 429

    def test_rate_limiter_prunes_expired_identities(self, client, app):
        app.state.config_update_requests = {
            "expired-client": [0.0],
        }

        response = client.put("/config", json={})

        assert response.status_code == 200
        assert "expired-client" not in app.state.config_update_requests

    def test_updates_are_rate_limited_per_authenticated_client(self, client):
        with patch(
            "squirrelops_home_sensor.api.routes_config.CONFIG_UPDATES_PER_MINUTE",
            2,
        ):
            assert client.put("/config", json={"sensor_name": "One"}).status_code == 200
            assert client.put("/config", json={"sensor_name": "Two"}).status_code == 200
            limited = client.put("/config", json={"sensor_name": "Three"})
        assert limited.status_code == 429

    def test_successful_update_writes_value_free_audit_event(
        self, client, db
    ):
        import asyncio
        import json

        response = client.put(
            "/config",
            json={
                "home_assistant": {
                    "enabled": True,
                    "url": "http://192.168.1.2:8123",
                    "token": "never-log-this-token",
                }
            },
        )
        assert response.status_code == 200
        cursor = asyncio.get_event_loop().run_until_complete(
            db.execute(
                "SELECT payload FROM events WHERE event_type = 'config.updated' "
                "ORDER BY seq DESC LIMIT 1"
            )
        )
        row = asyncio.get_event_loop().run_until_complete(cursor.fetchone())
        payload = json.loads(row[0])
        assert payload["client_name"] == "test-client"
        assert payload["sections"] == ["home_assistant"]
        assert "never-log-this-token" not in row[0]

    def test_update_cannot_change_sensor_data_dir(self, client):
        """data_dir governs where the DB, CA, and secret store live and must be
        immutable at runtime (otherwise a paired client redirects trust state)."""
        resp = client.put("/config", json={"sensor": {"data_dir": "/etc/evil"}})
        assert resp.status_code == 422
        assert resp.json().get("sensor", {}).get("data_dir") != "/etc/evil"

    def test_update_cannot_set_secret_passphrase(self, client, sensor_config):
        original = deepcopy(sensor_config["sensor"])
        resp = client.put("/config", json={"sensor": {"secret_passphrase": "attacker"}})
        assert resp.status_code == 422
        assert sensor_config["sensor"] == original

    def test_update_cannot_disable_tls_or_persist_it(self, client, sensor_config):
        """A paired request cannot make plaintext bearer auth sticky."""
        original = deepcopy(sensor_config["sensor"])

        response = client.put(
            "/config",
            json={"sensor": {"tls": {"enabled": False}}},
        )

        assert response.status_code == 422
        assert sensor_config["sensor"] == original
        path = Path(sensor_config["sensor"]["data_dir"]) / "config.yaml"
        assert not path.exists()

    def test_update_rejects_unknown_nested_field_atomically(
        self, client, sensor_config
    ):
        original = deepcopy(sensor_config)

        response = client.put(
            "/config",
            json={
                "home_assistant": {
                    "enabled": True,
                    "url": "http://192.168.1.2:8123",
                    "token": "secret-token",
                    "tls": False,
                }
            },
        )

        assert response.status_code == 422
        assert sensor_config == original
        path = Path(sensor_config["sensor"]["data_dir"]) / "config.yaml"
        assert not path.exists()

    def test_update_rejects_invalid_type_and_range_atomically(
        self, client, sensor_config
    ):
        original = deepcopy(sensor_config)

        wrong_type = client.put(
            "/config",
            json={"network": {"scan_interval": "fast"}},
        )
        out_of_range = client.put(
            "/config",
            json={"scouts": {"max_concurrent_probes": 100000}},
        )

        assert wrong_type.status_code == 422
        assert out_of_range.status_code == 422
        assert sensor_config == original
        path = Path(sensor_config["sensor"]["data_dir"]) / "config.yaml"
        assert not path.exists()

    def test_persistence_failure_does_not_mutate_live_config(
        self, client, sensor_config
    ):
        original = deepcopy(sensor_config)

        with patch(
            "squirrelops_home_sensor.api.routes_config.atomic_write_private_text",
            side_effect=OSError("disk full"),
        ):
            response = client.put(
                "/config",
                json={"home_assistant": {"enabled": True}},
            )

        assert response.status_code == 500
        assert sensor_config == original

    def test_update_sanitizes_credential_filename_path_traversal(self, client):
        resp = client.put("/config", json={"credential_filename": "../../etc/passwd"})
        # Persisted as a bare filename, never a traversal path.
        cfg = resp.json()
        cred = cfg.get("decoys", {}).get("credential_filename") or cfg.get("credential_filename")
        assert cred is None or ("/" not in cred and ".." not in cred)

    def test_update_rejects_unsupported_dns_canaries(self, client, sensor_config):
        original_decoys = dict(sensor_config.get("decoys", {}))

        response = client.put(
            "/config",
            json={
                "decoys": {
                    "dns_canaries": {
                        "enabled": True,
                        "domain": "canary.example.com",
                    }
                }
            },
        )

        assert response.status_code == 422
        assert "DNS canaries are not supported" in response.json()["detail"]
        assert sensor_config.get("decoys", {}) == original_decoys

    def test_persisted_config_is_private_and_keeps_mutable_sensor_fields(
        self, client, sensor_config, secret_store
    ):
        response = client.put(
            "/config",
            json={
                "sensor": {"name": "Renamed Sensor"},
                "home_assistant": {
                    "enabled": True,
                    "url": "http://192.168.1.2:8123",
                    "token": "secret-token",
                },
            },
        )
        assert response.status_code == 200

        path = Path(sensor_config["sensor"]["data_dir"]) / "config.yaml"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        saved = path.read_text()
        assert "Renamed Sensor" in saved
        assert "secret-token" not in saved
        assert secret_store.values["config.home_assistant.token"] == "secret-token"
        assert "data_dir" not in saved
        assert "test-sensor-001" not in saved

    def test_cloud_llm_provider_uses_canonical_endpoint_and_applies_live(
        self,
        app,
        client,
        sensor_config,
    ):
        from squirrelops_home_sensor.api.routes_system import get_scan_loop

        scan_loop = MagicMock()
        app.dependency_overrides[get_scan_loop] = lambda: scan_loop

        response = client.put(
            "/config",
            json={
                "classifier": {
                    "llm_provider": "openrouter",
                    "llm_endpoint": "https://attacker.invalid/v1",
                    "llm_model": "provider/model",
                    "llm_api_key": "secret",
                },
            },
        )

        assert response.status_code == 200
        classifier = response.json()["classifier"]
        assert classifier["llm_endpoint"] == "https://openrouter.ai/api/v1"
        scan_loop.set_classifier_config.assert_called_once_with(sensor_config)

    def test_failed_live_classifier_swap_does_not_persist_or_mutate_config(
        self,
        app,
        client,
        sensor_config,
    ):
        from squirrelops_home_sensor.api.routes_system import get_scan_loop

        original = deepcopy(sensor_config)
        scan_loop = MagicMock()
        scan_loop.set_classifier_config.side_effect = RuntimeError("swap failed")
        app.dependency_overrides[get_scan_loop] = lambda: scan_loop

        response = client.put(
            "/config",
            json={
                "classifier": {
                    "llm_provider": "fireworks",
                    "llm_model": "accounts/account/models/model",
                    "llm_api_key": "new-secret",
                },
            },
        )

        assert response.status_code == 500
        assert response.json()["detail"] == (
            "Classifier configuration was not applied."
        )
        assert sensor_config == original
        assert not (
            Path(sensor_config["sensor"]["data_dir"]) / "config.yaml"
        ).exists()

    def test_switching_to_local_provider_clears_cloud_key(
        self,
        client,
        sensor_config,
    ):
        sensor_config["classifier"] = {
            "mode": "cloud_llm",
            "confidence_threshold": 0.70,
            "llm_provider": "openrouter",
            "llm_endpoint": "https://openrouter.ai/api/v1",
            "llm_model": "provider/model",
            "llm_api_key": "secret",
        }

        response = client.put(
            "/config",
            json={
                "classifier": {
                    "llm_provider": "ollama",
                    "llm_endpoint": "",
                    "llm_model": "qwen3",
                    "llm_api_key": None,
                },
            },
        )

        assert response.status_code == 200
        classifier = response.json()["classifier"]
        assert classifier["llm_endpoint"] == "http://localhost:11434/v1"
        assert classifier["llm_api_key"] is None

    def test_provider_switch_without_key_does_not_reuse_previous_secret(
        self,
        client,
        sensor_config,
    ):
        sensor_config["classifier"] = {
            "mode": "cloud_llm",
            "confidence_threshold": 0.70,
            "llm_provider": "openrouter",
            "llm_endpoint": "https://openrouter.ai/api/v1",
            "llm_model": "provider/model",
            "llm_api_key": "openrouter-secret",
        }

        response = client.put(
            "/config",
            json={
                "classifier": {
                    "llm_provider": "fireworks",
                    "llm_model": "accounts/account/models/model",
                },
            },
        )

        assert response.status_code == 200
        classifier = response.json()["classifier"]
        assert classifier["llm_endpoint"] == (
            "https://api.fireworks.ai/inference/v1"
        )
        assert classifier["llm_api_key"] is None

    def test_provider_switch_with_redaction_marker_does_not_reuse_previous_secret(
        self,
        client,
        sensor_config,
    ):
        sensor_config["classifier"] = {
            "mode": "cloud_llm",
            "confidence_threshold": 0.70,
            "llm_provider": "openrouter",
            "llm_endpoint": "https://openrouter.ai/api/v1",
            "llm_model": "provider/model",
            "llm_api_key": "openrouter-secret",
        }

        response = client.put(
            "/config",
            json={
                "classifier": {
                    "llm_provider": "custom",
                    "llm_endpoint": "https://attacker.invalid/v1",
                    "llm_model": "model",
                    "llm_api_key": REDACTED,
                },
            },
        )

        assert response.status_code == 200
        classifier = sensor_config["classifier"]
        assert classifier["llm_endpoint"] == "https://attacker.invalid/v1"
        assert classifier["llm_api_key"] is None

    def test_custom_endpoint_switch_with_marker_does_not_reuse_previous_secret(
        self,
        client,
        sensor_config,
    ):
        sensor_config["classifier"] = {
            "mode": "cloud_llm",
            "confidence_threshold": 0.70,
            "llm_provider": "custom",
            "llm_endpoint": "https://trusted.example/v1",
            "llm_model": "model",
            "llm_api_key": "custom-secret",
        }

        response = client.put(
            "/config",
            json={
                "classifier": {
                    "llm_endpoint": "https://attacker.invalid/v1",
                    "llm_api_key": REDACTED,
                },
            },
        )

        assert response.status_code == 200
        classifier = sensor_config["classifier"]
        assert classifier["llm_endpoint"] == "https://attacker.invalid/v1"
        assert classifier["llm_api_key"] is None


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

    def test_update_alert_methods_changes_config(self, client, sensor_config):
        client.put(
            "/config/alert-methods",
            json={"slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/test"}},
        )
        response = client.get("/config/alert-methods")
        data = response.json()
        assert data["slack"]["enabled"] is True
        # The webhook is a secret, so the response only confirms it is set.
        # Assert the stored value to prove the update actually landed.
        assert data["slack"]["webhook_url"] == REDACTED
        assert (
            sensor_config["alert_methods"]["slack"]["webhook_url"]
            == "https://hooks.slack.com/test"
        )

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
            "url": "http://192.168.1.20:8123",
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
    def test_ha_status_blocks_ssrf_to_non_lan_url(self, mock_client_cls, client, sensor_config):
        """A public / metadata HA URL must be refused before any server-side fetch."""
        sensor_config["home_assistant"] = {
            "enabled": True,
            "url": "http://169.254.169.254/latest/meta-data",
            "token": "test-token",
        }
        response = client.get("/config/ha-status")
        data = response.json()
        assert data["connected"] is False
        mock_client_cls.assert_not_called()

    @patch("squirrelops_home_sensor.api.routes_config.HomeAssistantClient")
    def test_ha_status_connection_failed(self, mock_client_cls, client, sensor_config):
        """When HA is configured but unreachable, returns connected=false."""
        sensor_config["home_assistant"] = {
            "enabled": True,
            "url": "http://192.168.1.20:8123",
            "token": "test-token",
        }
        mock_instance = AsyncMock()
        mock_instance.test_connection.return_value = False
        mock_client_cls.return_value = mock_instance

        response = client.get("/config/ha-status")
        data = response.json()
        assert data["connected"] is False
        assert data["device_count"] == 0


class TestSecretRedaction:
    """Config responses must not carry credentials to disk-caching clients."""

    @staticmethod
    def _seed_secrets(sensor_config):
        sensor_config["home_assistant"] = {
            "enabled": True,
            "url": "http://192.168.1.20:8123",
            "token": "eyJhbGciOiJIUzI1NiJ9.real-ha-token",
        }
        sensor_config["classifier"] = {
            "mode": "cloud",
            "llm_provider": "fireworks",
            "llm_api_key": "fw-real-api-key",
        }
        sensor_config["sensor"]["secret_passphrase"] = "real-passphrase"
        sensor_config["alert_methods"]["slack"] = {
            "enabled": True,
            "min_severity": "low",
            "include_device_info": False,
            "webhook_url": "https://hooks.slack.com/services/T1/B2/real-secret",
        }
        return sensor_config

    def test_get_config_redacts_every_secret(self, client, sensor_config):
        self._seed_secrets(sensor_config)
        sensor_config["alert_methods"]["push"] = {
            "enabled": True,
            "relay_token": "relay-secret",
            "device_token": "device-secret",
        }
        data = client.get("/config").json()
        assert data["home_assistant"]["token"] == REDACTED
        assert data["classifier"]["llm_api_key"] == REDACTED
        assert data["sensor"]["secret_passphrase"] == REDACTED
        assert data["alert_methods"]["slack"]["webhook_url"] == REDACTED
        assert data["alert_methods"]["push"]["relay_token"] == REDACTED
        assert data["alert_methods"]["push"]["device_token"] == REDACTED

    def test_get_config_still_returns_non_secret_fields(self, client, sensor_config):
        self._seed_secrets(sensor_config)
        data = client.get("/config").json()
        assert data["home_assistant"]["url"] == "http://192.168.1.20:8123"
        assert data["alert_methods"]["slack"]["enabled"] is True
        assert data["subnet"] == "192.168.1.0/24"

    def test_get_config_does_not_mutate_the_live_config(self, client, sensor_config):
        self._seed_secrets(sensor_config)
        client.get("/config")
        assert sensor_config["home_assistant"]["token"].endswith("real-ha-token")

    def test_unset_secret_is_not_reported_as_configured(self, client, sensor_config):
        sensor_config["alert_methods"]["slack"] = {"enabled": False, "webhook_url": ""}
        data = client.get("/config").json()
        assert data["alert_methods"]["slack"]["webhook_url"] == ""

    def test_config_responses_are_not_cacheable(self, client):
        assert client.get("/config").headers["cache-control"] == "no-store"
        assert client.get("/config/alert-methods").headers["cache-control"] == "no-store"

    def test_get_alert_methods_redacts_webhook(self, client, sensor_config):
        self._seed_secrets(sensor_config)
        data = client.get("/config/alert-methods").json()
        assert data["slack"]["webhook_url"] == REDACTED
        assert data["slack"]["enabled"] is True

    def test_get_alert_methods_redacts_push_credentials(self, client, sensor_config):
        sensor_config["alert_methods"]["push"] = {
            "enabled": True,
            "relay_url": "https://push.example/relay",
            "relay_token": "relay-secret",
            "device_token": "device-secret",
        }
        data = client.get("/config/alert-methods").json()
        assert data["push"]["relay_url"] == "https://push.example/relay"
        assert data["push"]["relay_token"] == REDACTED
        assert data["push"]["device_token"] == REDACTED


class TestSecretWriteBack:
    """Echoing a redacted value back must never destroy the stored secret."""

    def test_put_config_marker_preserves_stored_secret(self, client, sensor_config):
        sensor_config["home_assistant"] = {
            "enabled": True,
            "url": "http://192.168.1.20:8123",
            "token": "real-ha-token",
        }
        response = client.put(
            "/config",
            json={"home_assistant": {"enabled": False, "token": REDACTED}},
        )
        assert response.status_code == 200
        assert sensor_config["home_assistant"]["token"] == "real-ha-token"
        assert sensor_config["home_assistant"]["enabled"] is False

    def test_put_config_real_value_still_updates(self, client, sensor_config):
        sensor_config["home_assistant"] = {
            "enabled": True,
            "url": "http://192.168.1.20:8123",
            "token": "old-token",
        }
        client.put("/config", json={"home_assistant": {"token": "new-token"}})
        assert sensor_config["home_assistant"]["token"] == "new-token"

    def test_put_config_response_is_redacted(self, client, sensor_config):
        sensor_config["home_assistant"] = {
            "enabled": True,
            "url": "http://192.168.1.20:8123",
            "token": "real-ha-token",
        }
        data = client.put("/config", json={"home_assistant": {"enabled": True}}).json()
        assert data["home_assistant"]["token"] == REDACTED

    def test_settings_screen_round_trip_keeps_the_webhook(self, client, sensor_config):
        """The exact SettingsView flow: GET, then PUT the whole slack section.

        SettingsView seeds its state from the GET response and writes the whole
        method back whenever any field changes, so the marker comes straight
        back. This is the regression that makes redaction safe to ship.
        """
        sensor_config["alert_methods"]["slack"] = {
            "enabled": True,
            "min_severity": "low",
            "include_device_info": False,
            "webhook_url": "https://hooks.slack.com/services/T1/B2/real-secret",
        }
        fetched = client.get("/config/alert-methods").json()
        assert fetched["slack"]["webhook_url"] == REDACTED

        response = client.put(
            "/config/alert-methods",
            json={
                "slack": {
                    "enabled": True,
                    "min_severity": "high",
                    "include_device_info": False,
                    "webhook_url": fetched["slack"]["webhook_url"],
                }
            },
        )
        assert response.status_code == 200
        stored = sensor_config["alert_methods"]["slack"]
        assert stored["webhook_url"].endswith("/real-secret")
        assert stored["min_severity"] == "high"
        assert response.json()["slack"]["webhook_url"] == REDACTED

    def test_partial_push_update_preserves_tokens(self, client, sensor_config):
        sensor_config["alert_methods"]["push"] = {
            "enabled": True,
            "min_severity": "low",
            "relay_url": "https://push.example/relay",
            "relay_token": "relay-secret",
            "device_token": "device-secret",
        }

        response = client.put(
            "/config/alert-methods",
            json={"push": {"enabled": False, "min_severity": "high"}},
        )

        assert response.status_code == 200
        stored = sensor_config["alert_methods"]["push"]
        assert stored["enabled"] is False
        assert stored["relay_token"] == "relay-secret"
        assert stored["device_token"] == "device-secret"
        assert response.json()["push"]["relay_token"] == REDACTED
        assert response.json()["push"]["device_token"] == REDACTED

    def test_put_alert_methods_real_webhook_still_updates(self, client, sensor_config):
        sensor_config["alert_methods"]["slack"] = {
            "enabled": True,
            "webhook_url": "https://hooks.slack.com/services/old",
        }
        client.put(
            "/config/alert-methods",
            json={"slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/services/new"}},
        )
        assert sensor_config["alert_methods"]["slack"]["webhook_url"].endswith("/new")

    def test_empty_webhook_still_clears_the_secret(self, client, sensor_config):
        sensor_config["alert_methods"]["slack"] = {
            "enabled": True,
            "webhook_url": "https://hooks.slack.com/services/old",
        }
        client.put(
            "/config/alert-methods",
            json={"slack": {"enabled": False, "webhook_url": ""}},
        )
        assert sensor_config["alert_methods"]["slack"]["webhook_url"] == ""

    def test_marker_is_never_written_to_disk(
        self, client, sensor_config, secret_store
    ):
        sensor_config["alert_methods"]["slack"] = {
            "enabled": True,
            "webhook_url": "https://hooks.slack.com/services/T1/B2/real-secret",
        }
        client.put(
            "/config/alert-methods",
            json={"slack": {"enabled": True, "webhook_url": REDACTED}},
        )
        persisted = Path(sensor_config["sensor"]["data_dir"]) / "config.yaml"
        text = persisted.read_text()
        assert REDACTED not in text
        assert "real-secret" not in text
        assert (
            "https://hooks.slack.com/services/T1/B2/real-secret"
            in secret_store.values.values()
        )

    def test_marker_without_a_stored_secret_is_dropped(self, client, sensor_config):
        sensor_config["alert_methods"]["slack"] = {"enabled": False}
        client.put(
            "/config/alert-methods",
            json={"slack": {"enabled": True, "webhook_url": REDACTED}},
        )
        assert "webhook_url" not in sensor_config["alert_methods"]["slack"]
