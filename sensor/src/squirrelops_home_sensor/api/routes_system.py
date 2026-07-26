"""System routes: health, status, profile switching, learning progress."""
from __future__ import annotations

import copy
import logging
import time
from datetime import UTC, datetime
from enum import Enum

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from squirrelops_home_sensor import __version__
from squirrelops_home_sensor.api.deps import get_config, get_db, verify_client_cert
from squirrelops_home_sensor.api.routes_decoys import get_decoy_orchestrator
from squirrelops_home_sensor.api.routes_scouts import (
    get_mimic_orchestrator,
    get_scout_scheduler,
)
from squirrelops_home_sensor.compatibility import SENSOR_API_PROTOCOL_VERSION
from squirrelops_home_sensor.devices.decoy_filter import DECOY_DEVICE_FILTER
from squirrelops_home_sensor.profiles import (
    PROFILE_SETTINGS,
    ResourceProfile,
)

router = APIRouter(prefix="/system", tags=["system"])
logger = logging.getLogger(__name__)


async def get_scan_loop():
    """Return the live ScanLoop. Overridden by the production entry point."""
    return None


# ---------- Request/Response models ----------

class ProfileName(str, Enum):
    lite = "lite"
    standard = "standard"
    full = "full"


class ProfileUpdateRequest(BaseModel):
    profile: ProfileName


class HealthResponse(BaseModel):
    # Unauthenticated liveness probe. Deliberately omits version and sensor_id
    # so a LAN host cannot fingerprint the sensor before authenticating; the
    # app reads sensor identity from the (authenticated) pairing challenge.
    status: str = "ok"
    uptime_seconds: float


class StatusResponse(BaseModel):
    version: str
    api_protocol_version: int
    profile: str
    learning_mode: bool
    device_count: int
    decoy_count: int
    alert_count: int
    event_seq: int


class ProfileResponse(BaseModel):
    profile: str
    scan_interval_seconds: int
    max_decoys: int
    llm_classification: str
    scout_interval_minutes: int
    max_mimic_decoys: int
    max_virtual_ips: int
    total_decoy_capacity: int


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
async def health(request: Request):
    """Unauthenticated liveness probe. Returns status and uptime only."""
    start_time = getattr(request.app.state, "start_time", time.time())
    uptime = time.time() - start_time
    return HealthResponse(status="ok", uptime_seconds=round(uptime, 2))


@router.get("/status", response_model=StatusResponse)
async def status(
    db: aiosqlite.Connection = Depends(get_db),
    config: dict = Depends(get_config),
    mimic_orchestrator=Depends(get_mimic_orchestrator),
    _auth: dict = Depends(verify_client_cert),
):
    """System status with counts. Requires authentication."""
    device_count = 0
    decoy_count = 0
    alert_count = 0

    cursor = await db.execute(f"SELECT COUNT(*) FROM devices d WHERE {DECOY_DEVICE_FILTER}")
    row = await cursor.fetchone()
    if row:
        device_count = row[0]

    decoy_query = "SELECT COUNT(*) FROM decoys WHERE status = 'active'"
    if mimic_orchestrator is not None:
        decoy_query += " AND decoy_type != 'mimic'"
    cursor = await db.execute(decoy_query)
    row = await cursor.fetchone()
    if row:
        decoy_count = row[0]
    if mimic_orchestrator is not None:
        decoy_count += mimic_orchestrator.active_count

    cursor = await db.execute("SELECT COUNT(*) FROM home_alerts")
    row = await cursor.fetchone()
    if row:
        alert_count = row[0]

    # This high-water mark is captured before the client fetches its
    # authoritative REST collections. Replaying only events after this point
    # closes the REST-to-WebSocket race without streaming the full historical
    # event log into a freshly launched dashboard.
    cursor = await db.execute("SELECT COALESCE(MAX(seq), 0) FROM events")
    row = await cursor.fetchone()
    event_seq = row[0] if row else 0

    return StatusResponse(
        version=__version__,
        api_protocol_version=SENSOR_API_PROTOCOL_VERSION,
        profile=config.get("profile", "standard"),
        learning_mode=config.get("learning_mode", {}).get("enabled", False),
        device_count=device_count,
        decoy_count=decoy_count,
        alert_count=alert_count,
        event_seq=event_seq,
    )


def _classification_mode(config: dict, profile: ResourceProfile) -> str:
    """Describe the classifier that can actually run with current settings."""
    import ipaddress
    from urllib.parse import urlparse

    classifier = config.get("classifier", {})
    provider = str(classifier.get("llm_provider") or "").strip().lower()
    if provider in {"none", "off", "disabled"}:
        return "local_signatures"
    from squirrelops_home_sensor.devices.llm_classifier import (
        CLOUD_LLM_PROVIDERS,
        resolve_llm_endpoint,
    )

    endpoint = resolve_llm_endpoint(
        provider,
        classifier.get("llm_endpoint"),
    )
    model = str(classifier.get("llm_model") or "").strip()
    if not endpoint or not model:
        return "local_signatures"
    if provider in CLOUD_LLM_PROVIDERS and not classifier.get("llm_api_key"):
        return "local_signatures"
    if profile is ResourceProfile.LITE:
        return "local_signatures"
    if provider in CLOUD_LLM_PROVIDERS:
        return "cloud_llm"

    host = (urlparse(endpoint).hostname or "").lower().rstrip(".")
    address_host = host.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(address_host)
    except ValueError:
        address = None
    is_local_destination = (
        host == "localhost"
        or host.endswith(".local")
        or host.endswith(".localdomain")
        or ("." not in host and ":" not in host)
        or (
            address is not None
            and (
                address.is_private
                or address.is_loopback
                or address.is_link_local
            )
        )
    )
    if is_local_destination:
        return "local_llm"
    return "cloud_llm"


def _profile_response(profile: ResourceProfile, config: dict) -> ProfileResponse:
    """Build the API representation from the canonical profile settings."""
    settings = PROFILE_SETTINGS[profile]
    return ProfileResponse(
        profile=profile.value,
        scan_interval_seconds=settings.scan_interval,
        max_decoys=settings.max_decoys,
        llm_classification=_classification_mode(config, profile),
        scout_interval_minutes=settings.scout_interval_minutes,
        max_mimic_decoys=settings.max_mimic_decoys,
        max_virtual_ips=settings.max_virtual_ips,
        total_decoy_capacity=settings.total_decoy_capacity,
    )


@router.get("/profile", response_model=ProfileResponse)
async def get_profile(
    config: dict = Depends(get_config),
    _auth: dict = Depends(verify_client_cert),
):
    """Get current resource profile and its settings."""
    try:
        profile = ResourceProfile(config.get("profile", ResourceProfile.STANDARD.value))
    except ValueError:
        profile = ResourceProfile.STANDARD
    return _profile_response(profile, config)


@router.put("/profile", response_model=ProfileResponse)
async def set_profile(
    body: ProfileUpdateRequest,
    config: dict = Depends(get_config),
    decoy_orchestrator=Depends(get_decoy_orchestrator),
    scout_scheduler=Depends(get_scout_scheduler),
    mimic_orchestrator=Depends(get_mimic_orchestrator),
    scan_loop=Depends(get_scan_loop),
    _auth: dict = Depends(verify_client_cert),
):
    """Switch resource profile and reconcile every live governed subsystem."""
    from squirrelops_home_sensor.api.routes_config import _persist_config

    profile = ResourceProfile(body.profile.value)
    settings = PROFILE_SETTINGS[profile]
    old_config = copy.deepcopy(config)

    old_scan_interval = (
        scan_loop.scan_interval
        if scan_loop is not None
        else config.get("network", {}).get("scan_interval", 300)
    )
    old_scout_interval = (
        scout_scheduler.interval_minutes
        if scout_scheduler is not None
        else config.get("scouts", {}).get("interval_minutes", 30)
    )
    old_decoy_limit = (
        decoy_orchestrator.max_decoys
        if decoy_orchestrator is not None
        else config.get("decoys", {}).get("max_decoys", 8)
    )
    old_mimic_limit = (
        mimic_orchestrator.max_mimics
        if mimic_orchestrator is not None
        else config.get("scouts", {}).get("max_mimic_decoys", 5)
    )
    stopped_decoys: list[int] = []
    stopped_mimics: list[int] = []

    async def rollback_runtime() -> None:
        """Best-effort rollback to the exact pre-request live limits."""
        if mimic_orchestrator is not None:
            await mimic_orchestrator.reconfigure(old_mimic_limit)
            for decoy_id in stopped_mimics:
                await mimic_orchestrator.enable_mimic(decoy_id)
        if decoy_orchestrator is not None:
            await decoy_orchestrator.reconfigure(old_decoy_limit)
            for decoy_id in stopped_decoys:
                await decoy_orchestrator.enable_decoy(decoy_id)
        if scout_scheduler is not None:
            await scout_scheduler.reconfigure(old_scout_interval)
        if scan_loop is not None:
            scan_loop.set_scan_interval(old_scan_interval)
            set_classifier_mode = getattr(scan_loop, "set_classifier_mode", None)
            if set_classifier_mode is not None:
                set_classifier_mode(
                    old_config.get("classifier", {}).get(
                        "mode", "local_signatures"
                    ),
                    old_config,
                )

    # Reconfigure objects that otherwise retain the startup profile forever.
    # The persisted config is not touched until every live change succeeds.
    try:
        if scan_loop is not None:
            scan_loop.set_scan_interval(settings.scan_interval)
            set_classifier_mode = getattr(scan_loop, "set_classifier_mode", None)
            if set_classifier_mode is not None:
                set_classifier_mode(settings.llm_mode.value, config)
        if scout_scheduler is not None:
            await scout_scheduler.reconfigure(settings.scout_interval_minutes)
        if decoy_orchestrator is not None:
            stopped_decoys = await decoy_orchestrator.reconfigure(settings.max_decoys)
        if mimic_orchestrator is not None:
            stopped_mimics = await mimic_orchestrator.reconfigure(
                settings.max_mimic_decoys
            )
    except Exception as exc:
        logger.exception("Failed to apply resource profile %s", profile.value)
        try:
            await rollback_runtime()
        except Exception:
            logger.exception("Failed to fully roll back resource profile change")
        raise HTTPException(
            status_code=500,
            detail=f"Could not apply {profile.value} resource profile",
        ) from exc

    # Keep both canonical nested settings and the legacy flat aliases in sync.
    config["profile"] = profile.value
    config["scan_interval_seconds"] = settings.scan_interval
    config["max_decoys"] = settings.max_decoys
    config.setdefault("network", {})["scan_interval"] = settings.scan_interval
    config.setdefault("decoys", {})["max_decoys"] = settings.max_decoys
    config.setdefault("classifier", {})["mode"] = settings.llm_mode.value
    scouts = config.setdefault("scouts", {})
    scouts["interval_minutes"] = settings.scout_interval_minutes
    scouts["max_mimic_decoys"] = settings.max_mimic_decoys
    scouts["max_virtual_ips"] = settings.max_virtual_ips

    try:
        _persist_config(config)
    except Exception as exc:
        config.clear()
        config.update(old_config)
        try:
            await rollback_runtime()
        except Exception:
            logger.exception(
                "Failed to fully roll back profile after persistence failure"
            )
        raise HTTPException(
            status_code=500,
            detail=(
                f"Could not save {profile.value} resource profile; "
                "the previous profile remains active"
            ),
        ) from exc

    return _profile_response(profile, config)


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
        started_at = started_at.replace(tzinfo=UTC)

    now = datetime.now(UTC)
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
        async with aiohttp.ClientSession() as session, session.get(
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
