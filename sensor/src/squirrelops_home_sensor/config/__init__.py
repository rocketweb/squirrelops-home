"""Configuration loader for SquirrelOps Home Sensor.

Loads settings from a YAML file with built-in defaults. Supports environment
variable overrides using the SQUIRRELOPS_ prefix with double-underscore
nesting (e.g., SQUIRRELOPS_NETWORK__SCAN_INTERVAL=120).
"""

from __future__ import annotations

import os
import pathlib
from typing import Any

import yaml
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Config sub-models
# ---------------------------------------------------------------------------

class SensorConfig(BaseModel):
    name: str = "SquirrelOps Home Sensor"
    data_dir: str = "./data"
    port: int = 8443


class NetworkConfig(BaseModel):
    scan_interval: int = 300
    interface: str = "auto"
    subnet: str = "auto"
    learning_duration_hours: int = 48


class DNSCanaryConfig(BaseModel):
    enabled: bool = False
    domain: str = "canary.local"


class DecoyConfig(BaseModel):
    max_decoys: int = 8
    health_check_interval: int = 1800
    restart_max_attempts: int = 3
    restart_window_seconds: int = 300
    dns_canaries: DNSCanaryConfig = Field(default_factory=DNSCanaryConfig)


class AlertMethodsConfig(BaseModel):
    notification: bool = True
    menubar: bool = True
    fullscreen: bool = False
    slack: bool = False


class AlertConfig(BaseModel):
    retention_days: int = 90
    incident_window_minutes: int = 15
    incident_close_window_minutes: int = 30
    methods: AlertMethodsConfig = Field(default_factory=AlertMethodsConfig)


class ClassifierConfig(BaseModel):
    mode: str = "local"
    confidence_threshold: float = 0.70
    llm_provider: str | None = None
    llm_endpoint: str | None = None
    llm_model: str | None = None
    llm_api_key: str | None = None


class SignalWeightsConfig(BaseModel):
    mdns: float = 0.30
    dhcp: float = 0.25
    connections: float = 0.25
    mac: float = 0.10
    ports: float = 0.10


class FingerprintConfig(BaseModel):
    auto_approve_threshold: float = 0.75
    verify_threshold: float = 0.50
    signal_weights: SignalWeightsConfig = Field(default_factory=SignalWeightsConfig)


class ScoutsConfig(BaseModel):
    enabled: bool = True
    interval_minutes: int = 30
    max_concurrent_probes: int = 20
    max_mimic_decoys: int = 10
    max_virtual_ips: int = 15
    virtual_ip_range_start: int = 200
    virtual_ip_range_end: int = 250


class HomeAssistantConfig(BaseModel):
    enabled: bool = False
    url: str = ""
    token: str = ""


class ProfileLimits(BaseModel):
    scan_interval: int = 300
    max_decoys: int = 8
    llm_mode: str = "none"


class ProfilesConfig(BaseModel):
    default: str = "standard"
    lite: ProfileLimits = Field(
        default_factory=lambda: ProfileLimits(scan_interval=900, max_decoys=3, llm_mode="none")
    )
    standard: ProfileLimits = Field(
        default_factory=lambda: ProfileLimits(scan_interval=300, max_decoys=8, llm_mode="cloud")
    )
    full: ProfileLimits = Field(
        default_factory=lambda: ProfileLimits(scan_interval=60, max_decoys=16, llm_mode="local")
    )


# ---------------------------------------------------------------------------
# Top-level settings
# ---------------------------------------------------------------------------

class Settings(BaseModel):
    profile: str = "standard"
    credential_filename: str = "passwords.txt"
    sensor: SensorConfig = Field(default_factory=SensorConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    decoys: DecoyConfig = Field(default_factory=DecoyConfig)
    alerts: AlertConfig = Field(default_factory=AlertConfig)
    classifier: ClassifierConfig = Field(default_factory=ClassifierConfig)
    fingerprint: FingerprintConfig = Field(default_factory=FingerprintConfig)
    profiles: ProfilesConfig = Field(default_factory=ProfilesConfig)
    home_assistant: HomeAssistantConfig = Field(default_factory=HomeAssistantConfig)
    scouts: ScoutsConfig = Field(default_factory=ScoutsConfig)


# ---------------------------------------------------------------------------
# Deep merge helper
# ---------------------------------------------------------------------------

def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *override* into *base*, returning a new dict."""
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


# ---------------------------------------------------------------------------
# Environment variable overrides
# ---------------------------------------------------------------------------

_ENV_PREFIX = "SQUIRRELOPS_"


def _collect_env_overrides() -> dict[str, Any]:
    """Collect SQUIRRELOPS_* env vars and build a nested dict.

    Double-underscore separates nesting levels.
    Example: SQUIRRELOPS_NETWORK__SCAN_INTERVAL=120
    becomes  {"network": {"scan_interval": "120"}}
    """
    overrides: dict[str, Any] = {}
    for key, value in os.environ.items():
        if not key.startswith(_ENV_PREFIX):
            continue
        parts = key[len(_ENV_PREFIX) :].lower().split("__")
        current = overrides
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        # Attempt numeric coercion
        final_value: Any = value
        try:
            final_value = int(value)
        except ValueError:
            try:
                final_value = float(value)
            except ValueError:
                if value.lower() in ("true", "false"):
                    final_value = value.lower() == "true"
        current[parts[-1]] = final_value
    return overrides


# ---------------------------------------------------------------------------
# Flat → nested key migration
# ---------------------------------------------------------------------------

# Maps legacy flat config keys (from data/config.yaml written by PUT /config)
# to their nested equivalents in the Settings model.  Without this mapping
# the flat keys are silently ignored by Pydantic, so e.g. a top-level
# ``subnet: 192.168.1.0/24`` never reaches ``NetworkConfig.subnet``.
_FLAT_KEY_MAP: dict[str, tuple[str, str]] = {
    "data_dir": ("sensor", "data_dir"),
    "port": ("sensor", "port"),
    "subnet": ("network", "subnet"),
    "scan_interval_seconds": ("network", "scan_interval"),
    "max_decoys": ("decoys", "max_decoys"),
    "sensor_name": ("sensor", "name"),
}


def _normalize_flat_keys(data: dict[str, Any]) -> dict[str, Any]:
    """Migrate known flat config keys into their nested model paths.

    Flat keys take precedence over existing nested defaults when present,
    because the persisted config represents explicit user overrides.
    After migration the flat key is removed from the top level.
    """
    for flat_key, (section, nested_key) in _FLAT_KEY_MAP.items():
        if flat_key not in data:
            continue
        value = data.pop(flat_key)
        # Only apply if the nested section doesn't already have an explicit
        # user-provided value (i.e. it's still at the default).  If the user
        # provided BOTH flat and nested, the nested value wins.
        section_dict = data.setdefault(section, {})
        if isinstance(section_dict, dict):
            # Set the nested value — this overrides the default
            section_dict[nested_key] = value
    return data


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_BUILTIN_DEFAULTS_PATH = pathlib.Path(__file__).resolve().parents[3] / "config" / "home_defaults.yaml"


def load_settings(
    config_path: pathlib.Path | None = None,
) -> Settings:
    """Load settings with layered precedence: defaults < file < persisted < env vars.

    Parameters
    ----------
    config_path:
        Path to a YAML config file. If ``None`` or the file does not exist,
        built-in defaults are used.
    """
    # Layer 1: built-in defaults (always loaded from the model defaults)
    base: dict[str, Any] = {}

    # Layer 2: YAML config file
    path = config_path if config_path is not None else _BUILTIN_DEFAULTS_PATH
    if path.exists():
        with open(path) as fh:
            file_data = yaml.safe_load(fh)
        if isinstance(file_data, dict):
            base = _deep_merge(base, file_data)

    env_overrides = _collect_env_overrides()
    if env_overrides:
        _normalize_flat_keys(env_overrides)

    # Layer 3: persisted runtime config (written by PUT /config)
    # Only loaded in daemon mode (no explicit config_path) so that tests
    # passing a custom file aren't polluted by ./data/config.yaml.
    if config_path is None:
        config_for_data_dir = _deep_merge(dict(base), env_overrides)
        _normalize_flat_keys(config_for_data_dir)
        data_dir = config_for_data_dir.get("sensor", {}).get("data_dir", "./data")
        persisted_path = pathlib.Path(data_dir) / "config.yaml"
        if persisted_path.exists():
            with open(persisted_path) as fh:
                persisted_data = yaml.safe_load(fh)
            if isinstance(persisted_data, dict):
                base = _deep_merge(base, persisted_data)

    # Migrate flat keys written by older versions of PUT /config into
    # the nested structure expected by the Settings model.
    _normalize_flat_keys(base)

    # Layer 4: environment variable overrides
    if env_overrides:
        base = _deep_merge(base, env_overrides)
        _normalize_flat_keys(base)

    return Settings(**base)
