"""Tests for the configuration loader."""

import logging
import os
import pathlib
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from squirrelops_home_sensor.config import (
    AlertConfig,
    ClassifierConfig,
    DecoyConfig,
    FingerprintConfig,
    HomeAssistantConfig,
    NetworkConfig,
    PairingConfig,
    SensorConfig,
    Settings,
    _normalize_flat_keys,
    load_settings,
)

SENSOR_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULTS_PATH = SENSOR_ROOT / "config" / "home_defaults.yaml"


class TestSettingsModels:
    """Verify that Pydantic config models have correct defaults."""

    def test_sensor_config_defaults(self) -> None:
        cfg = SensorConfig()
        assert cfg.name == "SquirrelOps Home Sensor"
        assert cfg.data_dir == "./data"
        assert cfg.port == 8443
        assert cfg.tls.enabled is True

    def test_pairing_config_fails_closed_by_default(self) -> None:
        cfg = PairingConfig()
        assert cfg.allow_unsigned_local is False
        assert cfg.socket_path is None

    @pytest.mark.parametrize("port", [0, 65536])
    def test_sensor_port_is_bounded(self, port: int) -> None:
        with pytest.raises(ValueError):
            SensorConfig(port=port)

    def test_network_config_defaults(self) -> None:
        cfg = NetworkConfig()
        assert cfg.scan_interval == 300
        assert cfg.interface == "auto"
        assert cfg.subnet == "auto"
        assert cfg.learning_duration_hours == 48

    def test_decoy_config_defaults(self) -> None:
        cfg = DecoyConfig()
        assert cfg.max_decoys == 3
        assert cfg.health_check_interval == 1800
        assert cfg.restart_max_attempts == 3
        assert cfg.restart_window_seconds == 300

    def test_nested_models_reject_unknown_fields(self) -> None:
        with pytest.raises(ValueError):
            HomeAssistantConfig(
                enabled=True,
                url="http://192.168.1.2:8123",
                token="token",
                tls=False,
            )

    @pytest.mark.parametrize("max_concurrent", [0, 65])
    def test_scout_concurrency_is_bounded(self, max_concurrent: int) -> None:
        with pytest.raises(ValueError):
            Settings(scouts={"max_concurrent_probes": max_concurrent})

    def test_alert_config_defaults(self) -> None:
        cfg = AlertConfig()
        assert cfg.retention_days == 90
        assert cfg.incident_window_minutes == 15
        assert cfg.incident_close_window_minutes == 30

    @pytest.mark.parametrize("retention_days", [0, -1, 3651])
    def test_alert_config_rejects_destructive_retention_bounds(
        self,
        retention_days: int,
    ) -> None:
        with pytest.raises(ValueError):
            AlertConfig(retention_days=retention_days)

    def test_classifier_config_defaults(self) -> None:
        cfg = ClassifierConfig()
        assert cfg.mode == "local"
        assert cfg.confidence_threshold == 0.70
        assert cfg.llm_provider is None

    def test_fingerprint_config_defaults(self) -> None:
        cfg = FingerprintConfig()
        assert cfg.auto_approve_threshold == 0.75
        assert cfg.verify_threshold == 0.50
        assert cfg.signal_weights.mdns == 0.30


class TestLoadDefaults:
    """Verify loading from the default YAML file."""

    def test_load_from_defaults_file(self) -> None:
        settings = load_settings(config_path=DEFAULTS_PATH)
        assert settings.sensor.name == "SquirrelOps Home Sensor"
        assert settings.profile == "standard"
        assert settings.network.scan_interval == 300
        assert settings.decoys.max_decoys == 3

    def test_load_returns_settings_instance(self) -> None:
        settings = load_settings(config_path=DEFAULTS_PATH)
        assert isinstance(settings, Settings)


class TestLoadFromCustomFile:
    """Verify loading overrides from a custom YAML file."""

    def test_override_scan_interval(self, tmp_path: pathlib.Path) -> None:
        custom = tmp_path / "custom.yaml"
        custom.write_text(yaml.dump({
            "network": {"scan_interval": 60},
        }))
        settings = load_settings(config_path=custom)
        assert settings.network.scan_interval == 60
        # Other defaults should still be present
        assert settings.sensor.name == "SquirrelOps Home Sensor"

    def test_override_nested_alert_methods(self, tmp_path: pathlib.Path) -> None:
        custom = tmp_path / "custom.yaml"
        custom.write_text(yaml.dump({
            "alerts": {
                "methods": {
                    "slack": True,
                    "fullscreen": True,
                },
            },
        }))
        settings = load_settings(config_path=custom)
        assert settings.alerts.methods.slack is True
        assert settings.alerts.methods.fullscreen is True
        # Defaults preserved
        assert settings.alerts.methods.notification is True

    def test_override_sensor_name(self, tmp_path: pathlib.Path) -> None:
        custom = tmp_path / "custom.yaml"
        custom.write_text(yaml.dump({
            "sensor": {"name": "My Custom Sensor"},
        }))
        settings = load_settings(config_path=custom)
        assert settings.sensor.name == "My Custom Sensor"

    def test_explicit_config_still_loads_private_persisted_overrides(
        self, tmp_path: pathlib.Path
    ) -> None:
        data_dir = tmp_path / "runtime-data"
        data_dir.mkdir()
        custom = tmp_path / "custom.yaml"
        custom.write_text(
            yaml.safe_dump({"sensor": {"data_dir": str(data_dir), "name": "Original"}})
        )
        (data_dir / "config.yaml").write_text(
            yaml.safe_dump({"sensor": {"name": "Persisted"}, "profile": "full"})
        )

        settings = load_settings(config_path=custom)

        assert settings.sensor.name == "Persisted"
        assert settings.profile == "full"

    def test_legacy_dns_canary_config_is_removed_with_warning(
        self,
        tmp_path: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        custom = tmp_path / "custom.yaml"
        custom.write_text(
            yaml.safe_dump(
                {
                    "decoys": {
                        "dns_canaries": {
                            "enabled": True,
                            "domain": "canary.example.com",
                        }
                    }
                }
            )
        )

        with caplog.at_level(logging.WARNING):
            settings = load_settings(config_path=custom)

        assert not hasattr(settings.decoys, "dns_canaries")
        assert "DNS canaries are not supported" in caplog.text


class TestLoadFromEnvVars:
    """Verify environment variable overrides with SQUIRRELOPS_ prefix."""

    def test_env_override_scan_interval(self) -> None:
        with patch.dict(os.environ, {"SQUIRRELOPS_NETWORK__SCAN_INTERVAL": "120"}):
            settings = load_settings(config_path=DEFAULTS_PATH)
            assert settings.network.scan_interval == 120

    def test_env_override_sensor_name(self) -> None:
        with patch.dict(os.environ, {"SQUIRRELOPS_SENSOR__NAME": "EnvSensor"}):
            settings = load_settings(config_path=DEFAULTS_PATH)
            assert settings.sensor.name == "EnvSensor"

    def test_env_override_max_decoys(self) -> None:
        with patch.dict(os.environ, {"SQUIRRELOPS_DECOYS__MAX_DECOYS": "3"}):
            settings = load_settings(config_path=DEFAULTS_PATH)
            assert settings.decoys.max_decoys == 3

    def test_env_flat_runtime_keys_are_mapped(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SQUIRRELOPS_PORT": "9443",
                "SQUIRRELOPS_DATA_DIR": "/app/data",
                "SQUIRRELOPS_PROFILE": "lite",
            },
        ):
            settings = load_settings(config_path=DEFAULTS_PATH)
            assert settings.sensor.port == 9443
            assert settings.sensor.data_dir == "/app/data"
            assert settings.profile == "lite"

    def test_env_override_takes_precedence_over_file(
        self, tmp_path: pathlib.Path
    ) -> None:
        custom = tmp_path / "custom.yaml"
        custom.write_text(yaml.dump({
            "network": {"scan_interval": 60},
        }))
        with patch.dict(os.environ, {"SQUIRRELOPS_NETWORK__SCAN_INTERVAL": "15"}):
            settings = load_settings(config_path=custom)
            assert settings.network.scan_interval == 15


class TestMissingFileFallback:
    """Verify graceful handling of missing config file."""

    def test_missing_file_returns_defaults(self) -> None:
        missing = pathlib.Path("/nonexistent/config.yaml")
        settings = load_settings(config_path=missing)
        assert isinstance(settings, Settings)
        assert settings.sensor.name == "SquirrelOps Home Sensor"
        assert settings.network.scan_interval == 300

    def test_none_path_returns_defaults(self, tmp_path: pathlib.Path) -> None:
        # Run from a tmp directory so we don't pick up the local
        # data/config.yaml which would override defaults.
        orig_cwd = pathlib.Path.cwd()
        os.chdir(tmp_path)
        try:
            settings = load_settings(config_path=None)
            assert isinstance(settings, Settings)
            assert settings.network.scan_interval == 300
        finally:
            os.chdir(orig_cwd)


class TestHomeAssistantConfig:
    """Verify HomeAssistantConfig sub-model defaults and construction."""

    def test_default_ha_config_disabled(self) -> None:
        """Settings() should have home_assistant disabled with empty url/token."""
        settings = Settings()
        assert settings.home_assistant.enabled is False
        assert settings.home_assistant.url == ""
        assert settings.home_assistant.token == ""

    def test_ha_config_from_dict(self) -> None:
        """Settings should accept home_assistant as a dict and populate the sub-model."""
        settings = Settings(
            home_assistant={
                "enabled": True,
                "url": "http://ha.local:8123",
                "token": "abc123",
            }
        )
        assert settings.home_assistant.enabled is True
        assert settings.home_assistant.url == "http://ha.local:8123"
        assert settings.home_assistant.token == "abc123"

    def test_ha_config_treats_empty_as_disabled(self) -> None:
        """enabled=True with empty url/token should be loadable (scan loop handles this)."""
        cfg = HomeAssistantConfig(enabled=True, url="", token="")
        assert cfg.enabled is True
        assert cfg.url == ""
        assert cfg.token == ""


class TestFlatKeyNormalization:
    """Verify that legacy flat config keys are mapped to nested model paths."""

    def test_subnet_maps_to_network(self) -> None:
        data: dict[str, Any] = {"subnet": "10.0.0.0/24"}
        _normalize_flat_keys(data)
        assert data["network"]["subnet"] == "10.0.0.0/24"
        assert "subnet" not in data

    def test_scan_interval_maps_to_network(self) -> None:
        data: dict[str, Any] = {"scan_interval_seconds": 120}
        _normalize_flat_keys(data)
        assert data["network"]["scan_interval"] == 120
        assert "scan_interval_seconds" not in data

    def test_max_decoys_maps_to_decoys(self) -> None:
        data: dict[str, Any] = {"max_decoys": 16}
        _normalize_flat_keys(data)
        assert data["decoys"]["max_decoys"] == 16
        assert "max_decoys" not in data

    def test_sensor_name_maps_to_sensor(self) -> None:
        data: dict[str, Any] = {"sensor_name": "TestSensor"}
        _normalize_flat_keys(data)
        assert data["sensor"]["name"] == "TestSensor"
        assert "sensor_name" not in data

    def test_preserves_existing_nested_keys(self) -> None:
        data = {
            "subnet": "10.0.0.0/24",
            "network": {"interface": "en0"},
        }
        _normalize_flat_keys(data)
        assert data["network"]["subnet"] == "10.0.0.0/24"
        assert data["network"]["interface"] == "en0"

    def test_no_flat_keys_is_noop(self) -> None:
        data = {"network": {"subnet": "10.0.0.0/24"}}
        original = dict(data)
        _normalize_flat_keys(data)
        assert data == original

    def test_flat_key_applied_to_settings(self, tmp_path: pathlib.Path) -> None:
        """Flat subnet key in a config file should reach Settings.network.subnet."""
        config = tmp_path / "config.yaml"
        config.write_text(yaml.dump({"subnet": "10.0.0.0/24"}))
        settings = load_settings(config_path=config)
        assert settings.network.subnet == "10.0.0.0/24"
