"""Config routes: get/set sensor config, alert methods, HA status."""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, status

from squirrelops_home_sensor.api.deps import get_config, verify_client_cert
from squirrelops_home_sensor.config import _FLAT_KEY_MAP
from squirrelops_home_sensor.integrations.home_assistant import HomeAssistantClient
from squirrelops_home_sensor.netvalidation import is_safe_lan_url
from squirrelops_home_sensor.secure_io import atomic_write_private_text

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/config", tags=["config"])

# Fields that cannot be overwritten by PUT /config
PROTECTED_FIELDS = {"sensor_id", "version"}

# Keys inside the "sensor" section that are immutable at runtime: they decide
# where the DB, CA, and encrypted secret store live (data_dir) or are the secret
# key material itself (secret_passphrase). Allowing a paired client to change
# them would relocate or expose trust state.
IMMUTABLE_SENSOR_KEYS = {"id", "data_dir", "secret_passphrase", "sensor_id"}

# Allowed top-level config keys (Settings model fields + legacy flat keys).
# Any key not in this set is silently rejected to prevent injection of
# arbitrary config entries that could affect business logic.
ALLOWED_CONFIG_KEYS = {
    # Settings model sections
    "sensor", "network", "decoys", "alerts", "classifier",
    "fingerprint", "profiles", "home_assistant", "scouts",
    # Legacy flat keys (from config.yaml)
    "sensor_name", "profile", "learning_mode", "scan_interval_seconds",
    "max_decoys", "alert_methods", "subnet", "credential_filename",
}


def _safe_filename(value: Any) -> str:
    """Reduce a user-supplied value to a bare filename (no path components)."""
    base = os.path.basename(str(value))
    if not base or base in (".", "..") or "/" in base or "\\" in base:
        return "passwords.txt"
    return base


def _persist_config(config: dict[str, Any]) -> None:
    """Write user-modified config keys to data_dir/config.yaml.

    Only persists keys that differ from defaults and are not runtime-only.
    This file is loaded on next startup as a config override layer.
    """
    data_dir = Path(config.get("sensor", {}).get("data_dir", "./data"))
    persist_path = data_dir / "config.yaml"

    # Persist canonical model sections, excluding runtime identity, storage
    # paths, and secret-store material. The file itself is private because HA,
    # LLM, webhook, and relay settings may contain credentials.
    to_save = {
        key: value
        for key, value in config.items()
        if key in ALLOWED_CONFIG_KEYS and key not in _FLAT_KEY_MAP
    }
    sensor = config.get("sensor")
    if isinstance(sensor, dict):
        to_save["sensor"] = {
            key: value
            for key, value in sensor.items()
            if key not in IMMUTABLE_SENSOR_KEYS
        }

    try:
        serialized = yaml.safe_dump(
            to_save, default_flow_style=False, sort_keys=False
        )
        atomic_write_private_text(persist_path, serialized)
        logger.debug("Config persisted to %s", persist_path)
    except Exception as exc:
        logger.error("Failed to persist config to %s", persist_path, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Configuration changed in memory but could not be saved.",
        ) from exc


# ---------- Routes ----------


@router.get("")
async def get_full_config(
    config: dict = Depends(get_config),
    _auth: dict = Depends(verify_client_cert),
) -> dict:
    """Return the full sensor configuration."""
    return config


@router.put("")
async def update_config(
    body: dict,
    config: dict = Depends(get_config),
    _auth: dict = Depends(verify_client_cert),
) -> dict:
    """Partial update of sensor configuration (merge semantics).

    Protected fields (sensor_id, version) are silently ignored.
    Top-level keys are merged; nested dicts are replaced entirely.
    Changes are persisted to data_dir/config.yaml for restart survival.
    """
    decoy_update = body.get("decoys")
    if isinstance(decoy_update, dict) and "dns_canaries" in decoy_update:
        logger.warning("Rejected unsupported DNS-canary configuration update")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                "DNS canaries are not supported in this release; "
                "no DNS canary hostnames are planted or monitored."
            ),
        )

    rejected = [k for k in body if k not in ALLOWED_CONFIG_KEYS]
    if rejected:
        logger.warning("Config update rejected unknown keys: %s", rejected)

    for key, value in body.items():
        if key in PROTECTED_FIELDS or key not in ALLOWED_CONFIG_KEYS:
            continue
        # Merge the "sensor" section sub-key by sub-key (never whole-replace) and
        # drop immutable path/secret fields, so data_dir and secret_passphrase
        # cannot be changed at runtime.
        if key == "sensor":
            if isinstance(value, dict):
                section = config.setdefault("sensor", {})
                for sub_key, sub_val in value.items():
                    if sub_key in IMMUTABLE_SENSOR_KEYS:
                        continue
                    section[sub_key] = sub_val
            continue
        # The credential filename is planted on disk by decoys; force it to a
        # bare filename so it cannot become a path-traversal write target.
        if key == "credential_filename":
            value = _safe_filename(value)
        # Map legacy flat keys into the nested config structure so they
        # actually take effect at runtime (the Settings model only reads
        # nested keys like network.subnet, not top-level "subnet").
        if key in _FLAT_KEY_MAP:
            section, nested_key = _FLAT_KEY_MAP[key]
            config.setdefault(section, {})[nested_key] = value
        else:
            config[key] = value

    _persist_config(config)
    return config


@router.get("/alert-methods")
async def get_alert_methods(
    config: dict = Depends(get_config),
    _auth: dict = Depends(verify_client_cert),
) -> dict:
    """Return configured alert/notification methods."""
    return config.get("alert_methods", {})


@router.put("/alert-methods")
async def update_alert_methods(
    body: dict,
    config: dict = Depends(get_config),
    _auth: dict = Depends(verify_client_cert),
) -> dict:
    """Update alert/notification methods. Merges with existing methods."""
    if "alert_methods" not in config:
        config["alert_methods"] = {}

    for method_name, method_config in body.items():
        config["alert_methods"][method_name] = method_config

    _persist_config(config)
    return config["alert_methods"]


@router.get("/ha-status")
async def get_ha_status(
    config: dict = Depends(get_config),
    _auth: dict = Depends(verify_client_cert),
) -> dict:
    """Return Home Assistant connection status."""
    ha_cfg = config.get("home_assistant", {})
    if not ha_cfg.get("enabled") or not ha_cfg.get("url") or not ha_cfg.get("token"):
        return {"connected": False, "device_count": 0}

    # SSRF guard: only fetch from a private LAN host. A config-supplied URL must
    # never let the sensor reach public or cloud-metadata endpoints.
    if not is_safe_lan_url(ha_cfg["url"]):
        logger.warning("Blocked Home Assistant status fetch to non-LAN URL: %s", ha_cfg["url"])
        return {"connected": False, "device_count": 0}

    client = HomeAssistantClient(url=ha_cfg["url"], token=ha_cfg["token"])
    connected = await client.test_connection()
    device_count = 0
    if connected:
        devices = await client.get_devices()
        device_count = len(devices)
    return {"connected": connected, "device_count": device_count}
