"""System routes: health, status, profile switching, learning progress."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import aiosqlite
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, field_validator

from squirrelops_home_sensor import __version__
from squirrelops_home_sensor.api.deps import get_db, get_config, verify_client_cert

router = APIRouter(prefix="/system", tags=["system"])

# ---------- Profile definitions ----------

PROFILE_SETTINGS = {
    "lite": {
        "scan_interval_seconds": 900,  # 15 min
        "max_decoys": 3,
        "llm_classification": "local_signature_db",
    },
    "standard": {
        "scan_interval_seconds": 300,  # 5 min
        "max_decoys": 8,
        "llm_classification": "cloud_llm",
    },
    "full": {
        "scan_interval_seconds": 60,  # 1 min
        "max_decoys": 16,
        "llm_classification": "local_llm",
    },
}


# ---------- Request/Response models ----------

class ProfileName(str, Enum):
    lite = "lite"
    standard = "standard"
    full = "full"


class ProfileUpdateRequest(BaseModel):
    profile: ProfileName


class HealthResponse(BaseModel):
    version: str
    sensor_id: str
    uptime_seconds: float


class StatusResponse(BaseModel):
    profile: str
    learning_mode: bool
    device_count: int
    decoy_count: int
    alert_count: int


class ProfileResponse(BaseModel):
    profile: str
    scan_interval_seconds: int
    max_decoys: int
    llm_classification: str


class LearningResponse(BaseModel):
    enabled: bool
    hours_elapsed: float
    hours_total: int
    phase: str  # "learning" or "complete"


class UpdateCheckResponse(BaseModel):
    current_version: str
    latest_version: str | None = None
    update_available: bool = False
    message: str = ""


# ---------- Routes ----------

@router.get("/health", response_model=HealthResponse)
async def health(request: Request, config: dict = Depends(get_config)):
    """Health check endpoint. No authentication required."""
    start_time = getattr(request.app.state, "start_time", time.time())
    uptime = time.time() - start_time
    return HealthResponse(
        version=__version__,
        sensor_id=config.get("sensor_id", "unknown"),
        uptime_seconds=round(uptime, 2),
    )


@router.get("/status", response_model=StatusResponse)
async def status(
    db: aiosqlite.Connection = Depends(get_db),
    config: dict = Depends(get_config),
    _auth: dict = Depends(verify_client_cert),
):
    """System status with counts. Requires authentication."""
    device_count = 0
    decoy_count = 0
    alert_count = 0

    cursor = await db.execute("SELECT COUNT(*) FROM devices")
    row = await cursor.fetchone()
    if row:
        device_count = row[0]

    cursor = await db.execute(
        "SELECT COUNT(*) FROM decoys WHERE status = 'active' AND decoy_type != 'mimic'"
    )
    row = await cursor.fetchone()
    if row:
        decoy_count = row[0]

    cursor = await db.execute("SELECT COUNT(*) FROM home_alerts")
    row = await cursor.fetchone()
    if row:
        alert_count = row[0]

    return StatusResponse(
        profile=config.get("profile", "standard"),
        learning_mode=config.get("learning_mode", {}).get("enabled", False),
        device_count=device_count,
        decoy_count=decoy_count,
        alert_count=alert_count,
    )


@router.get("/profile", response_model=ProfileResponse)
async def get_profile(
    config: dict = Depends(get_config),
    _auth: dict = Depends(verify_client_cert),
):
    """Get current resource profile and its settings."""
    profile_name = config.get("profile", "standard")
    settings = PROFILE_SETTINGS.get(profile_name, PROFILE_SETTINGS["standard"])
    return ProfileResponse(
        profile=profile_name,
        **settings,
    )


@router.put("/profile", response_model=ProfileResponse)
async def set_profile(
    body: ProfileUpdateRequest,
    config: dict = Depends(get_config),
    _auth: dict = Depends(verify_client_cert),
):
    """Switch resource profile. Updates config and persists to disk."""
    from squirrelops_home_sensor.api.routes_config import _persist_config

    profile_name = body.profile.value
    settings = PROFILE_SETTINGS[profile_name]

    # Update the live config dict
    config["profile"] = profile_name
    config["scan_interval_seconds"] = settings["scan_interval_seconds"]
    config["max_decoys"] = settings["max_decoys"]

    _persist_config(config)

    return ProfileResponse(
        profile=profile_name,
        **settings,
    )


@router.get("/learning", response_model=LearningResponse)
async def get_learning(
    config: dict = Depends(get_config),
    _auth: dict = Depends(verify_client_cert),
):
    """Get learning mode progress."""
    learning = config.get("learning_mode", {})
    enabled = learning.get("enabled", False)
    duration_hours = learning.get("duration_hours", 48)

    if not enabled:
        return LearningResponse(
            enabled=False,
            hours_elapsed=duration_hours,
            hours_total=duration_hours,
            phase="complete",
        )

    started_at_str = learning.get("started_at", "")
    if not started_at_str:
        return LearningResponse(
            enabled=True,
            hours_elapsed=0,
            hours_total=duration_hours,
            phase="learning",
        )

    started_at = datetime.fromisoformat(started_at_str)
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    elapsed = (now - started_at).total_seconds() / 3600.0

    if elapsed >= duration_hours:
        phase = "complete"
    else:
        phase = "learning"

    return LearningResponse(
        enabled=True,
        hours_elapsed=round(elapsed, 2),
        hours_total=duration_hours,
        phase=phase,
    )


@router.get("/updates", response_model=UpdateCheckResponse)
async def check_updates(
    config: dict = Depends(get_config),
    _auth: dict = Depends(verify_client_cert),
):
    """Check for available sensor updates.

    Compares current version against a remote manifest if configured.
    Returns gracefully if no manifest URL is set or URL is unreachable.
    """
    current = __version__
    manifest_url = config.get("update_manifest_url", "")

    if not manifest_url:
        return UpdateCheckResponse(
            current_version=current,
            message="No update source configured.",
        )

    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                manifest_url,
                params={"current_version": current, "platform": "sensor"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    return UpdateCheckResponse(
                        current_version=current,
                        message="Update check failed.",
                    )
                data = await resp.json()
                latest = data.get("latest_version", current)
                return UpdateCheckResponse(
                    current_version=current,
                    latest_version=latest,
                    update_available=latest != current,
                    message="Update available!" if latest != current else "Up to date.",
                )
    except Exception:
        return UpdateCheckResponse(
            current_version=current,
            message="Could not reach update server.",
        )
