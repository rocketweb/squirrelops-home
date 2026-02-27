"""Tests for the configuration loader."""

import os
import pathlib
import tempfile
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
    SensorConfig,
    Settings,
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

    def test_network_config_defaults(self) -> None:
        cfg = NetworkConfig()
        assert cfg.scan_interval == 300
        assert cfg.interface == "auto"
        assert cfg.subnet == "auto"
        assert cfg.learning_duration_hours == 48

    def test_decoy_config_defaults(self) -> None:
        cfg = DecoyConfig()
        assert cfg.max_decoys == 8
        assert cfg.health_check_interval == 1800
        assert cfg.restart_max_attempts == 3
        assert cfg.restart_window_seconds == 300

    def test_alert_config_defaults(self) -> None:
        cfg = AlertConfig()
        assert cfg.retention_days == 90
        assert cfg.incident_window_minutes == 15
        assert cfg.incident_close_window_minutes == 30

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
        assert settings.network.scan_interval == 300
        assert settings.decoys.max_decoys == 8

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

    def test_none_path_returns_defaults(self) -> None:
        settings = load_settings(config_path=None)
        assert isinstance(settings, Settings)
        assert settings.network.scan_interval == 300


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
