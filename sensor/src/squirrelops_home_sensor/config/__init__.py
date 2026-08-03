"""Configuration loader for SquirrelOps Home Sensor.

Loads settings from a YAML file with built-in defaults. Supports environment
variable overrides using the SQUIRRELOPS_ prefix with double-underscore
nesting (e.g., SQUIRRELOPS_NETWORK__SCAN_INTERVAL=120).
"""

from __future__ import annotations

import logging
import os
import pathlib
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sub-models
# ---------------------------------------------------------------------------

class StrictConfigModel(BaseModel):
    """Reject unknown nested configuration keys.

    Top-level legacy compatibility remains on ``Settings``. Nested sections
    are strict so a misspelled or attacker-supplied runtime option cannot be
    silently persisted and then interpreted differently by another release.
    """

    model_config = ConfigDict(extra="forbid")


class TLSConfig(StrictConfigModel):
    enabled: bool = True


class SensorConfig(StrictConfigModel):
    id: str = ""
    name: str = Field(default="SquirrelOps Home Sensor", min_length=1, max_length=128)
    data_dir: str = "./data"
    port: int = Field(default=8443, ge=1, le=65535)
    tls: TLSConfig = Field(default_factory=TLSConfig)
    secret_passphrase: str | None = None


class NetworkConfig(StrictConfigModel):
    scan_interval: int = Field(default=300, ge=1, le=86400)
    interface: str = Field(default="auto", min_length=1, max_length=32)
    subnet: str = Field(default="auto", min_length=1, max_length=64)
    learning_duration_hours: int = Field(default=48, ge=1, le=8760)


class DecoyConfig(StrictConfigModel):
    max_decoys: int = Field(default=3, ge=0, le=64)
    health_check_interval: int = Field(default=1800, ge=1, le=86400)
    restart_max_attempts: int = Field(default=3, ge=0, le=20)
    restart_window_seconds: int = Field(default=300, ge=1, le=86400)


class AlertMethodsConfig(StrictConfigModel):
    notification: bool = True
    menubar: bool = True
    fullscreen: bool = False
    slack: bool = False


class AlertConfig(StrictConfigModel):
    retention_days: int = Field(default=90, ge=1, le=3650)
    incident_window_minutes: int = Field(default=15, ge=1, le=1440)
    incident_close_window_minutes: int = Field(default=30, ge=1, le=1440)
    methods: AlertMethodsConfig = Field(default_factory=AlertMethodsConfig)


class ClassifierConfig(StrictConfigModel):
    mode: str = "local"
    confidence_threshold: float = Field(default=0.70, ge=0.0, le=1.0)
    llm_provider: str | None = Field(default=None, max_length=32)
    llm_endpoint: str | None = Field(default=None, max_length=2048)
    llm_model: str | None = Field(default=None, max_length=512)
    llm_api_key: str | None = Field(default=None, max_length=8192)


class SignalWeightsConfig(StrictConfigModel):
    mdns: float = Field(default=0.30, ge=0.0, le=1.0)
    dhcp: float = Field(default=0.25, ge=0.0, le=1.0)
    connections: float = Field(default=0.25, ge=0.0, le=1.0)
    mac: float = Field(default=0.10, ge=0.0, le=1.0)
    ports: float = Field(default=0.10, ge=0.0, le=1.0)


class FingerprintConfig(StrictConfigModel):
    auto_approve_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    verify_threshold: float = Field(default=0.50, ge=0.0, le=1.0)
    signal_weights: SignalWeightsConfig = Field(default_factory=SignalWeightsConfig)


class ScoutsConfig(StrictConfigModel):
    enabled: bool = True
    interval_minutes: int = Field(default=30, ge=1, le=1440)
    max_concurrent_probes: int = Field(default=20, ge=1, le=64)
    max_mimic_decoys: int = Field(default=5, ge=0, le=64)
    max_virtual_ips: int = Field(default=5, ge=0, le=51)
    virtual_ip_range_start: int = Field(default=200, ge=1, le=254)
    virtual_ip_range_end: int = Field(default=250, ge=1, le=254)

    @model_validator(mode="after")
    def validate_virtual_ip_pool(self) -> ScoutsConfig:
        if self.virtual_ip_range_start > self.virtual_ip_range_end:
            raise ValueError("virtual IP range start must not exceed its end")
        pool_size = self.virtual_ip_range_end - self.virtual_ip_range_start + 1
        if self.max_virtual_ips > pool_size:
            raise ValueError("max_virtual_ips exceeds the configured candidate pool")
        return self


class HomeAssistantConfig(StrictConfigModel):
    enabled: bool = False
    url: str = Field(default="", max_length=2048)
    token: str = Field(default="", max_length=8192)


class LearningModeConfig(StrictConfigModel):
    enabled: bool = False
    started_at: str | None = None
    duration_hours: int = Field(default=48, ge=1, le=8760)


class PairingConfig(StrictConfigModel):
    """Development-only local pairing transport settings.

    Production never starts the local setup-key socket because file-descriptor
    passing can separate the process using a connected stream from the process
    identity captured by peer-credential checks. ``allow_unsigned_local`` is an
    explicit source-development escape hatch only.
    """

    socket_path: str | None = None
    allowed_app_requirement: str = (
        'identifier "com.squirrelops.home" and anchor apple generic and '
        'certificate leaf[subject.OU] = "PSQ5HK5U65"'
    )
    allow_unsigned_local: bool = False


class ProfileLimits(StrictConfigModel):
    scan_interval: int = Field(default=300, ge=1, le=86400)
    max_decoys: int = Field(default=3, ge=0, le=64)
    llm_mode: str = "none"


class ProfilesConfig(StrictConfigModel):
    default: str = "standard"
    lite: ProfileLimits = Field(
        default_factory=lambda: ProfileLimits(scan_interval=900, max_decoys=3, llm_mode="none")
    )
    standard: ProfileLimits = Field(
        default_factory=lambda: ProfileLimits(scan_interval=300, max_decoys=3, llm_mode="cloud")
    )
    full: ProfileLimits = Field(
        default_factory=lambda: ProfileLimits(scan_interval=60, max_decoys=3, llm_mode="local")
    )


# ---------------------------------------------------------------------------
# Top-level settings
# ---------------------------------------------------------------------------

class Settings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    profile: str = "standard"
    version: str = ""
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
    learning_mode: LearningModeConfig = Field(default_factory=LearningModeConfig)
    pairing: PairingConfig = Field(default_factory=PairingConfig)
    alert_methods: dict[str, Any] = Field(default_factory=dict)


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
_INTERNAL_RUNTIME_ENV = {
    "SQUIRRELOPS_LAN_SUBNET",
    "SQUIRRELOPS_NETWORK_HELPER_SOCKET",
    "SQUIRRELOPS_NETWORK_INTERFACE",
    "SQUIRRELOPS_SENSOR_BRIDGE_IP",
    "SQUIRRELOPS_SENSOR_UID",
}


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
        if key in _INTERNAL_RUNTIME_ENV:
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
    "sensor_id": ("sensor", "id"),
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


def _remove_unsupported_dns_canary_config(data: dict[str, Any]) -> None:
    """Remove the legacy DNS-canary surface with an explicit operator warning."""
    decoys = data.get("decoys")
    if not isinstance(decoys, dict) or "dns_canaries" not in decoys:
        return

    decoys.pop("dns_canaries")
    logger.warning(
        "DNS canaries are not supported in this release; ignoring "
        "decoys.dns_canaries. No DNS canary hostnames will be planted or monitored."
    )


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

    # Layer 3: persisted runtime config (written by PUT /config). Resolve a
    # relative data directory beside an explicit config file, not against the
    # caller's working directory. This keeps package installs deterministic and
    # prevents tests/custom configs from accidentally loading ./data/config.yaml
    # from the repository.
    config_for_data_dir = _deep_merge(dict(base), env_overrides)
    _normalize_flat_keys(config_for_data_dir)
    data_dir = pathlib.Path(
        config_for_data_dir.get("sensor", {}).get("data_dir", "./data")
    ).expanduser()
    if not data_dir.is_absolute() and config_path is not None:
        data_dir = config_path.resolve().parent / data_dir
    persisted_path = data_dir / "config.yaml"
    if persisted_path.exists() and persisted_path.resolve() != path.resolve():
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

    _remove_unsupported_dns_canary_config(base)

    known_fields = set(Settings.model_fields)
    unknown_fields = sorted(set(base) - known_fields)
    if unknown_fields:
        logger.warning("Ignoring unknown top-level config keys: %s", unknown_fields)

    return Settings(**base)
