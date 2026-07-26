"""Config routes: get/set sensor config, alert methods, HA status."""
from __future__ import annotations

import inspect
import logging
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import ValidationError

from squirrelops_home_sensor.api.deps import get_config, verify_client_cert
from squirrelops_home_sensor.api.routes_system import get_scan_loop
from squirrelops_home_sensor.config import _FLAT_KEY_MAP, Settings, _deep_merge
from squirrelops_home_sensor.integrations.home_assistant import HomeAssistantClient
from squirrelops_home_sensor.netvalidation import is_safe_lan_url
from squirrelops_home_sensor.secure_io import atomic_write_private_text

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/config", tags=["config"])

# Fields that cannot be overwritten by PUT /config.
PROTECTED_FIELDS = {
    "sensor_id",
    "version",
    "profile",
    "profiles",
    "pairing",
    "update_manifest_url",
}

# Keys inside the "sensor" section that are immutable at runtime: they decide
# where the DB, CA, and encrypted secret store live (data_dir) or are the secret
# key material itself (secret_passphrase). Allowing a paired client to change
# them would relocate or expose trust state.
IMMUTABLE_SENSOR_KEYS = {
    "id",
    "data_dir",
    "port",
    "tls",
    "secret_passphrase",
    "sensor_id",
}
MUTABLE_SENSOR_KEYS = {"name"}

# Allowed top-level config keys (Settings model fields + legacy flat keys).
# Any key not in this set is silently rejected to prevent injection of
# arbitrary config entries that could affect business logic.
ALLOWED_CONFIG_KEYS = {
    # Settings model sections
    "sensor", "network", "decoys", "alerts", "classifier",
    "fingerprint", "profiles", "home_assistant", "scouts", "learning_mode",
    # Legacy flat keys (from config.yaml)
    "sensor_name", "profile", "scan_interval_seconds",
    "max_decoys", "alert_methods", "subnet", "credential_filename",
}

MUTABLE_CONFIG_KEYS = ALLOWED_CONFIG_KEYS - PROTECTED_FIELDS


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
            detail="Configuration was not saved.",
        ) from exc


def _unprocessable(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail=detail,
    )


def _canonical_settings_input(config: dict[str, Any]) -> dict[str, Any]:
    """Return one canonical Settings-shaped copy of the runtime dictionary.

    The live dictionary intentionally carries legacy flat aliases for older
    API clients. When both forms exist, the canonical nested value is
    authoritative so a stale flat mirror cannot undo a validated update.
    """
    canonical = deepcopy(config)
    for flat_key, (section_name, nested_key) in _FLAT_KEY_MAP.items():
        marker = object()
        flat_value = canonical.pop(flat_key, marker)
        section = canonical.setdefault(section_name, {})
        if not isinstance(section, dict):
            raise _unprocessable(
                f"Configuration section {section_name!r} must be an object."
            )
        if nested_key not in section and flat_value is not marker:
            section[nested_key] = flat_value
    return canonical


def _apply_update(
    body: dict[str, Any],
    config: dict[str, Any],
) -> tuple[dict[str, Any], set[str]]:
    """Apply a partial request to a copy and return touched canonical sections."""
    rejected = sorted(
        key
        for key in body
        if key in PROTECTED_FIELDS or key not in MUTABLE_CONFIG_KEYS
    )
    if rejected:
        logger.warning("Config update rejected immutable or unknown keys: %s", rejected)
        raise _unprocessable(
            "Unknown or immutable configuration fields: "
            + ", ".join(rejected)
        )

    candidate = deepcopy(config)
    touched_sections: set[str] = set()
    for key, value in body.items():
        if key == "sensor":
            if not isinstance(value, dict):
                raise _unprocessable("Configuration section 'sensor' must be an object.")
            immutable = sorted(set(value) - MUTABLE_SENSOR_KEYS)
            if immutable:
                raise _unprocessable(
                    "Unknown or immutable sensor fields: "
                    + ", ".join(immutable)
                )
            sensor = candidate.setdefault("sensor", {})
            if not isinstance(sensor, dict):
                raise _unprocessable("Configuration section 'sensor' must be an object.")
            sensor.update(value)
            touched_sections.add("sensor")
            continue

        if key == "credential_filename":
            candidate[key] = _safe_filename(value)
            touched_sections.add(key)
            continue

        if key in _FLAT_KEY_MAP:
            section_name, nested_key = _FLAT_KEY_MAP[key]
            section = candidate.setdefault(section_name, {})
            if not isinstance(section, dict):
                raise _unprocessable(
                    f"Configuration section {section_name!r} must be an object."
                )
            section[nested_key] = value
            touched_sections.add(section_name)
            continue

        if isinstance(value, dict):
            existing = candidate.get(key, {})
            if not isinstance(existing, dict):
                raise _unprocessable(f"Configuration section {key!r} must be an object.")
            candidate[key] = _deep_merge(existing, value)
        else:
            candidate[key] = value
        touched_sections.add(key)

    return candidate, touched_sections


def _validated_runtime_update(
    body: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    """Validate a partial update without mutating the live configuration."""
    candidate, touched_sections = _apply_update(body, config)
    classifier_update = body.get("classifier")
    if isinstance(classifier_update, dict) and "llm_provider" in classifier_update:
        previous_classifier = config.get("classifier", {})
        candidate_classifier = candidate.get("classifier", {})
        if (
            isinstance(previous_classifier, dict)
            and isinstance(candidate_classifier, dict)
            and str(previous_classifier.get("llm_provider") or "").lower()
            != str(candidate_classifier.get("llm_provider") or "").lower()
            and "llm_api_key" not in classifier_update
        ):
            # Credentials belong to one provider. A partial provider switch
            # must not carry the old secret into the replacement client.
            candidate_classifier["llm_api_key"] = None
    try:
        validated = Settings.model_validate(
            _canonical_settings_input(candidate),
            strict=True,
        ).model_dump(mode="python")
    except ValidationError as exc:
        logger.warning(
            "Rejected invalid config update with %d schema error(s)",
            exc.error_count(),
        )
        raise _unprocessable("Invalid configuration update.") from exc

    if "classifier" in touched_sections:
        from squirrelops_home_sensor.devices.llm_classifier import (
            resolve_llm_endpoint,
        )

        classifier = validated["classifier"]
        endpoint = resolve_llm_endpoint(
            classifier.get("llm_provider"),
            classifier.get("llm_endpoint"),
        )
        if endpoint is not None:
            classifier["llm_endpoint"] = endpoint

    # Copy only sections named in the request back into the runtime shape.
    # This avoids materializing unrelated defaults and keeps compatibility
    # mirrors synchronized without trusting unvalidated request bytes.
    updated = deepcopy(config)
    for section_name in touched_sections:
        updated[section_name] = deepcopy(validated[section_name])

    if "sensor" in touched_sections:
        updated["sensor_name"] = validated["sensor"]["name"]
    if "network" in touched_sections:
        updated["scan_interval_seconds"] = validated["network"]["scan_interval"]
        updated["subnet"] = validated["network"]["subnet"]
    if "decoys" in touched_sections:
        updated["max_decoys"] = validated["decoys"]["max_decoys"]
    return updated


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
    scan_loop=Depends(get_scan_loop),
    _auth: dict = Depends(verify_client_cert),
) -> dict:
    """Partial update of sensor configuration (merge semantics).

    Immutable and unknown fields are rejected.
    Top-level and nested sections use partial deep-merge semantics.
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

    if not body:
        return config

    updated = _validated_runtime_update(body, config)
    previous = deepcopy(config)
    apply_classifier = None
    if "classifier" in body and scan_loop is not None:
        apply_classifier = getattr(scan_loop, "set_classifier_config", None)
        if apply_classifier is not None:
            try:
                applied = apply_classifier(updated)
                if inspect.isawaitable(applied):
                    await applied
            except Exception as exc:
                logger.exception("Failed to apply classifier configuration")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Classifier configuration was not applied.",
                ) from exc
    try:
        _persist_config(updated)
    except Exception:
        if apply_classifier is not None:
            try:
                rolled_back = apply_classifier(previous)
                if inspect.isawaitable(rolled_back):
                    await rolled_back
            except Exception:
                logger.exception(
                    "Failed to roll back live classifier configuration"
                )
        raise
    config.clear()
    config.update(updated)
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
    updated = deepcopy(config)
    methods = updated.setdefault("alert_methods", {})
    if not isinstance(methods, dict):
        raise _unprocessable("Configuration section 'alert_methods' must be an object.")
    for method_name, method_config in body.items():
        if not isinstance(method_name, str) or not method_name or len(method_name) > 64:
            raise _unprocessable("Invalid alert method name.")
        if not isinstance(method_config, dict):
            raise _unprocessable("Alert method configuration must be an object.")
        methods[method_name] = method_config

    _persist_config(updated)
    config.clear()
    config.update(updated)
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
