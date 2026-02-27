"""Pydantic domain models for SquirrelOps Home Sensor.

These models define the data structures used across the sensor: devices,
fingerprints, alerts, incidents, decoys, credentials, events, and system
status. All models support ``from_attributes=True`` for ORM-style loading
from database rows.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TrustStatus(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AlertType(str, Enum):
    NEW_DEVICE = "new_device"
    DEVICE_VERIFICATION = "device_verification"
    DECOY_TRIP = "decoy_trip"
    CREDENTIAL_TRIP = "credential_trip"
    CANARY_HIT = "canary_hit"
    SENSOR_OFFLINE = "sensor_offline"


class DecoyType(str, Enum):
    DEV_SERVER = "dev_server"
    HOME_ASSISTANT = "home_assistant"
    FILE_SHARE = "file_share"


class DecoyStatus(str, Enum):
    ACTIVE = "active"
    DEGRADED = "degraded"
    STOPPED = "stopped"


class CredentialType(str, Enum):
    AWS_KEY = "aws_key"
    DB_CONNECTION = "db_connection"
    SSH_KEY = "ssh_key"
    HA_TOKEN = "ha_token"
    GITHUB_PAT = "github_pat"
    ENV_FILE = "env_file"
    GENERIC_PASSWORD = "generic_password"


class IncidentStatus(str, Enum):
    ACTIVE = "active"
    CLOSED = "closed"


class ResourceProfile(str, Enum):
    LITE = "lite"
    STANDARD = "standard"
    FULL = "full"


class LLMMode(str, Enum):
    NONE = "none"
    CLOUD = "cloud"
    LOCAL = "local"


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------

class Device(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    first_seen: datetime
    last_seen: datetime


class DeviceFingerprint(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_id: int
    mac_address: str | None = None
    mdns_hostname: str | None = None
    dhcp_fingerprint_hash: str | None = None
    connection_pattern_hash: str | None = None
    open_ports_hash: str | None = None
    composite_hash: str | None = None
    signal_count: int
    confidence: float | None = None
    first_seen: datetime
    last_seen: datetime


class DeviceTrust(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    device_id: int
    status: TrustStatus
    approved_by: str | None = None
    updated_at: datetime


class Alert(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int | None = None
    alert_type: AlertType
    severity: AlertSeverity
    title: str
    detail: str
    source_ip: str | None = None
    source_mac: str | None = None
    device_id: int | None = None
    decoy_id: int | None = None
    read_at: datetime | None = None
    actioned_at: datetime | None = None
    event_seq: int | None = None
    created_at: datetime


class Incident(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_ip: str
    source_mac: str | None = None
    status: IncidentStatus
    severity: AlertSeverity
    alert_count: int = 1
    first_alert_at: datetime
    last_alert_at: datetime
    closed_at: datetime | None = None
    summary: str | None = None


class Decoy(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    decoy_type: DecoyType
    bind_address: str
    port: int
    status: DecoyStatus
    config: str | None = None
    connection_count: int = 0
    credential_trip_count: int = 0
    failure_count: int = 0
    last_failure_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class DecoyConnection(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    decoy_id: int
    source_ip: str
    source_mac: str | None = None
    port: int
    protocol: str | None = None
    request_path: str | None = None
    credential_used: str | None = None
    credential_id: int | None = None
    event_seq: int | None = None
    timestamp: datetime


class PlantedCredential(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    credential_type: CredentialType
    credential_value: str
    canary_hostname: str | None = None
    planted_location: str
    decoy_id: int | None = None
    tripped: bool = False
    first_tripped_at: datetime | None = None
    created_at: datetime


class CanaryObservation(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    credential_id: int
    canary_hostname: str
    queried_by_ip: str
    queried_by_mac: str | None = None
    event_seq: int | None = None
    observed_at: datetime


class PairingInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    client_name: str
    client_cert_fingerprint: str
    is_local: bool = False
    paired_at: datetime
    last_connected_at: datetime | None = None


class Event(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    seq: int
    event_type: str
    payload: dict[str, Any]
    source_id: str | None = None
    created_at: datetime


class SystemStatus(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    version: str
    profile: ResourceProfile
    llm_mode: LLMMode
    learning_mode: bool
    learning_progress: float
    device_count: int
    active_decoy_count: int
    uptime_seconds: int
    last_scan_at: datetime | None = None
