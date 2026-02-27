"""Config routes: get/set sensor config, alert methods, HA status."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from squirrelops_home_sensor.api.deps import get_config, verify_client_cert
from squirrelops_home_sensor.integrations.home_assistant import HomeAssistantClient

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/config", tags=["config"])

# Fields that cannot be overwritten by PUT /config
PROTECTED_FIELDS = {"sensor_id", "version"}

# Keys that are runtime-only and should not be persisted
RUNTIME_ONLY_FIELDS = {"sensor"}


def _persist_config(config: dict[str, Any]) -> None:
    """Write user-modified config keys to data_dir/config.yaml.

    Only persists keys that differ from defaults and are not runtime-only.
    This file is loaded on next startup as a config override layer.
    """
    data_dir = Path(config.get("sensor", {}).get("data_dir", "./data"))
    persist_path = data_dir / "config.yaml"

    # Filter out runtime-only and protected keys
    to_save = {
        k: v for k, v in config.items()
        if k not in PROTECTED_FIELDS and k not in RUNTIME_ONLY_FIELDS
    }

    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        with open(persist_path, "w") as fh:
            yaml.safe_dump(to_save, fh, default_flow_style=False, sort_keys=False)
        logger.debug("Config persisted to %s", persist_path)
    except Exception:
        logger.warning("Failed to persist config to %s", persist_path, exc_info=True)


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
    for key, value in body.items():
        if key in PROTECTED_FIELDS:
            continue
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

    client = HomeAssistantClient(url=ha_cfg["url"], token=ha_cfg["token"])
    connected = await client.test_connection()
    device_count = 0
    if connected:
        devices = await client.get_devices()
        device_count = len(devices)
    return {"connected": connected, "device_count": device_count}
