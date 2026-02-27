"""Squirrel Scouts API routes: status, profiles, mimic management."""
from __future__ import annotations

import json
from typing import Optional

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from squirrelops_home_sensor.api.deps import get_db, verify_client_cert

router = APIRouter(prefix="/scouts", tags=["scouts"])


# ---------- Response models ----------


class ScoutStatusResponse(BaseModel):
    enabled: bool
    is_running: bool
    last_scout_at: Optional[str] = None
    last_scout_duration_ms: Optional[int] = None
    total_profiles: int
    interval_minutes: int
    active_mimics: int
    max_mimics: int


class ServiceProfileSummary(BaseModel):
    id: int
    device_id: int
    ip_address: str
    port: int
    protocol: str
    service_name: Optional[str] = None
    http_status: Optional[int] = None
    http_server_header: Optional[str] = None
    tls_cn: Optional[str] = None
    protocol_version: Optional[str] = None
    scouted_at: str


class ServiceProfileDetail(ServiceProfileSummary):
    http_headers: Optional[dict] = None
    http_body_snippet: Optional[str] = None
    favicon_hash: Optional[str] = None
    tls_issuer: Optional[str] = None
    tls_not_after: Optional[str] = None


class MimicDecoySummary(BaseModel):
    id: int
    name: str
    bind_address: str
    port: int
    status: str
    source_device_id: Optional[int] = None
    device_category: Optional[str] = None
    connection_count: int = 0
    created_at: str
    mdns_hostname: Optional[str] = None


# ---------- Dependency stubs ----------
# These are overridden in __main__.py to point to the real instances


async def get_scout_scheduler():
    """Return the ScoutScheduler instance. Overridden in production."""
    return None


async def get_mimic_orchestrator():
    """Return the MimicOrchestrator instance. Overridden in production."""
    return None


# ---------- Routes ----------


@router.get("/status", response_model=ScoutStatusResponse)
async def get_scout_status(
    scheduler=Depends(get_scout_scheduler),
    orchestrator=Depends(get_mimic_orchestrator),
    _auth: dict = Depends(verify_client_cert),
):
    """Get scout engine status: last run, next run, profile count."""
    if scheduler is None:
        return ScoutStatusResponse(
            enabled=False,
            is_running=False,
            total_profiles=0,
            interval_minutes=0,
            active_mimics=0,
            max_mimics=0,
        )

    active_mimics = orchestrator.active_count if orchestrator else 0
    max_mimics = orchestrator.max_mimics if orchestrator else 0

    return ScoutStatusResponse(
        enabled=True,
        is_running=scheduler.is_running,
        last_scout_at=scheduler.last_scout_at.isoformat() if scheduler.last_scout_at else None,
        last_scout_duration_ms=scheduler.last_scout_duration_ms,
        total_profiles=scheduler.total_profiles,
        interval_minutes=scheduler.interval_minutes,
        active_mimics=active_mimics,
        max_mimics=max_mimics,
    )


@router.post("/run")
async def run_scout(
    scheduler=Depends(get_scout_scheduler),
    _auth: dict = Depends(verify_client_cert),
):
    """Trigger an immediate scout cycle."""
    if scheduler is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scout engine not enabled",
        )
    count = await scheduler.run_now()
    return {"profiles_created": count}


@router.get("/profiles", response_model=list[ServiceProfileSummary])
async def list_profiles(
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """List all service profiles with device info."""
    cursor = await db.execute(
        """SELECT sp.*, d.hostname, d.device_type
           FROM service_profiles sp
           JOIN devices d ON d.id = sp.device_id
           ORDER BY sp.device_id, sp.port"""
    )
    rows = await cursor.fetchall()
    return [
        ServiceProfileSummary(
            id=row["id"],
            device_id=row["device_id"],
            ip_address=row["ip_address"],
            port=row["port"],
            protocol=row["protocol"],
            service_name=row["service_name"],
            http_status=row["http_status"],
            http_server_header=row["http_server_header"],
            tls_cn=row["tls_cn"],
            protocol_version=row["protocol_version"],
            scouted_at=row["scouted_at"],
        )
        for row in rows
    ]


@router.get("/profiles/{profile_id}", response_model=ServiceProfileDetail)
async def get_profile(
    profile_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Get a single service profile with full detail."""
    cursor = await db.execute(
        "SELECT * FROM service_profiles WHERE id = ?", (profile_id,),
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Profile not found")

    return ServiceProfileDetail(
        id=row["id"],
        device_id=row["device_id"],
        ip_address=row["ip_address"],
        port=row["port"],
        protocol=row["protocol"],
        service_name=row["service_name"],
        http_status=row["http_status"],
        http_server_header=row["http_server_header"],
        http_headers=json.loads(row["http_headers"]) if row["http_headers"] else None,
        http_body_snippet=row["http_body_snippet"],
        favicon_hash=row["favicon_hash"],
        tls_cn=row["tls_cn"],
        tls_issuer=row["tls_issuer"],
        tls_not_after=row["tls_not_after"],
        protocol_version=row["protocol_version"],
        scouted_at=row["scouted_at"],
    )


@router.get("/mimics", response_model=list[MimicDecoySummary])
async def list_mimics(
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """List all deployed mimic decoys with virtual IPs."""
    cursor = await db.execute(
        """SELECT d.*,
                  mt.source_device_id,
                  mt.device_category,
                  json_extract(d.config, '$.mdns_hostname') AS mdns_hostname
           FROM decoys d
           LEFT JOIN mimic_templates mt ON mt.id = CAST(
               json_extract(d.config, '$.template_id') AS INTEGER
           )
           WHERE d.decoy_type = 'mimic'
           ORDER BY d.created_at DESC"""
    )
    rows = await cursor.fetchall()
    return [
        MimicDecoySummary(
            id=row["id"],
            name=row["name"],
            bind_address=row["bind_address"],
            port=row["port"],
            status=row["status"],
            source_device_id=row["source_device_id"],
            device_category=row["device_category"],
            connection_count=row["connection_count"],
            created_at=row["created_at"],
            mdns_hostname=row["mdns_hostname"],
        )
        for row in rows
    ]


@router.post("/mimics/deploy")
async def deploy_mimics(
    orchestrator=Depends(get_mimic_orchestrator),
    _auth: dict = Depends(verify_client_cert),
):
    """Manually trigger evaluate_and_deploy."""
    if orchestrator is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Mimic orchestrator not enabled",
        )
    count = await orchestrator.evaluate_and_deploy()
    return {"deployed": count}


@router.post("/mimics/{decoy_id}/restart")
async def restart_mimic(
    decoy_id: int,
    orchestrator=Depends(get_mimic_orchestrator),
    _auth: dict = Depends(verify_client_cert),
):
    """Restart a stopped mimic decoy."""
    if orchestrator is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Mimic orchestrator not enabled",
        )
    ok = await orchestrator.restart_mimic(decoy_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Mimic decoy not found or could not restart")
    return {"restarted": True}


@router.delete("/mimics/{decoy_id}")
async def remove_mimic(
    decoy_id: int,
    orchestrator=Depends(get_mimic_orchestrator),
    _auth: dict = Depends(verify_client_cert),
):
    """Stop and remove a mimic decoy, releasing its virtual IP."""
    if orchestrator is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Mimic orchestrator not enabled",
        )
    ok = await orchestrator.remove_mimic(decoy_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Mimic decoy not found")
    return {"removed": True}
