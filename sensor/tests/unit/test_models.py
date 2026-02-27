"""Tests for Pydantic domain models and enums."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from squirrelops_home_sensor.models import (
    Alert,
    AlertSeverity,
    AlertType,
    CanaryObservation,
    CredentialType,
    Decoy,
    DecoyConnection,
    DecoyStatus,
    DecoyType,
    Device,
    DeviceFingerprint,
    DeviceTrust,
    Event,
    Incident,
    IncidentStatus,
    LLMMode,
    PairingInfo,
    PlantedCredential,
    ResourceProfile,
    SystemStatus,
    TrustStatus,
)


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------

class TestEnums:
    """Verify all enums have expected members."""

    def test_trust_status_values(self) -> None:
        assert TrustStatus.APPROVED.value == "approved"
        assert TrustStatus.REJECTED.value == "rejected"
        assert TrustStatus.UNKNOWN.value == "unknown"
        assert len(TrustStatus) == 3

    def test_alert_severity_values(self) -> None:
        assert AlertSeverity.CRITICAL.value == "critical"
        assert AlertSeverity.HIGH.value == "high"
        assert AlertSeverity.MEDIUM.value == "medium"
        assert AlertSeverity.LOW.value == "low"
        assert len(AlertSeverity) == 4

    def test_alert_type_values(self) -> None:
        expected = {
            "new_device", "device_verification", "decoy_trip",
            "credential_trip", "canary_hit", "sensor_offline",
        }
        actual = {member.value for member in AlertType}
        assert expected == actual

    def test_decoy_type_values(self) -> None:
        assert DecoyType.DEV_SERVER.value == "dev_server"
        assert DecoyType.HOME_ASSISTANT.value == "home_assistant"
        assert DecoyType.FILE_SHARE.value == "file_share"
        assert len(DecoyType) == 3

    def test_decoy_status_values(self) -> None:
        assert DecoyStatus.ACTIVE.value == "active"
        assert DecoyStatus.DEGRADED.value == "degraded"
        assert DecoyStatus.STOPPED.value == "stopped"
        assert len(DecoyStatus) == 3

    def test_credential_type_values(self) -> None:
        expected = {
            "aws_key", "db_connection", "ssh_key", "ha_token",
            "github_pat", "env_file", "generic_password",
        }
        actual = {member.value for member in CredentialType}
        assert expected == actual

    def test_incident_status_values(self) -> None:
        assert IncidentStatus.ACTIVE.value == "active"
        assert IncidentStatus.CLOSED.value == "closed"
        assert len(IncidentStatus) == 2

    def test_resource_profile_values(self) -> None:
        assert ResourceProfile.LITE.value == "lite"
        assert ResourceProfile.STANDARD.value == "standard"
        assert ResourceProfile.FULL.value == "full"
        assert len(ResourceProfile) == 3

    def test_llm_mode_values(self) -> None:
        assert LLMMode.NONE.value == "none"
        assert LLMMode.CLOUD.value == "cloud"
        assert LLMMode.LOCAL.value == "local"
        assert len(LLMMode) == 3


# ---------------------------------------------------------------------------
# Model serialization round-trips
# ---------------------------------------------------------------------------

class TestDeviceModel:
    """Test Device model serialization."""

    def test_roundtrip(self) -> None:
        now = datetime.now(timezone.utc)
        device = Device(
            id=1,
            ip_address="192.168.1.100",
            mac_address="AA:BB:CC:DD:EE:FF",
            hostname="macbook-pro",
            first_seen=now,
            last_seen=now,
        )
        data = device.model_dump(mode="json")
        restored = Device.model_validate(data)
        assert restored.id == 1
        assert restored.ip_address == "192.168.1.100"
        assert restored.mac_address == "AA:BB:CC:DD:EE:FF"

    def test_optional_fields_default_none(self) -> None:
        now = datetime.now(timezone.utc)
        device = Device(
            id=1,
            ip_address="10.0.0.1",
            first_seen=now,
            last_seen=now,
        )
        assert device.mac_address is None
        assert device.hostname is None
        assert device.vendor is None


class TestDeviceFingerprintModel:
    """Test DeviceFingerprint model serialization."""

    def test_roundtrip(self) -> None:
        now = datetime.now(timezone.utc)
        fp = DeviceFingerprint(
            id=1,
            device_id=10,
            mac_address="AA:BB:CC:DD:EE:FF",
            composite_hash="abc123",
            signal_count=3,
            confidence=0.85,
            first_seen=now,
            last_seen=now,
        )
        data = fp.model_dump(mode="json")
        restored = DeviceFingerprint.model_validate(data)
        assert restored.signal_count == 3
        assert restored.confidence == 0.85

    def test_optional_signal_fields(self) -> None:
        now = datetime.now(timezone.utc)
        fp = DeviceFingerprint(
            id=1,
            device_id=10,
            signal_count=1,
            first_seen=now,
            last_seen=now,
        )
        assert fp.mdns_hostname is None
        assert fp.dhcp_fingerprint_hash is None
        assert fp.connection_pattern_hash is None
        assert fp.open_ports_hash is None


class TestDeviceTrustModel:
    """Test DeviceTrust model serialization."""

    def test_roundtrip(self) -> None:
        now = datetime.now(timezone.utc)
        trust = DeviceTrust(
            device_id=1,
            status=TrustStatus.APPROVED,
            approved_by="user",
            updated_at=now,
        )
        data = trust.model_dump(mode="json")
        restored = DeviceTrust.model_validate(data)
        assert restored.status == TrustStatus.APPROVED
        assert restored.approved_by == "user"

    def test_status_validation(self) -> None:
        now = datetime.now(timezone.utc)
        trust = DeviceTrust(
            device_id=1,
            status="approved",
            updated_at=now,
        )
        assert trust.status == TrustStatus.APPROVED


class TestAlertModel:
    """Test Alert model serialization."""

    def test_roundtrip(self) -> None:
        now = datetime.now(timezone.utc)
        alert = Alert(
            id=1,
            alert_type=AlertType.DECOY_TRIP,
            severity=AlertSeverity.HIGH,
            title="Decoy tripped",
            detail='{"decoy_id": 1}',
            source_ip="192.168.1.50",
            created_at=now,
        )
        data = alert.model_dump(mode="json")
        restored = Alert.model_validate(data)
        assert restored.severity == AlertSeverity.HIGH
        assert restored.alert_type == AlertType.DECOY_TRIP

    def test_optional_fields(self) -> None:
        now = datetime.now(timezone.utc)
        alert = Alert(
            id=1,
            alert_type=AlertType.NEW_DEVICE,
            severity=AlertSeverity.MEDIUM,
            title="New device",
            detail="{}",
            created_at=now,
        )
        assert alert.incident_id is None
        assert alert.source_ip is None
        assert alert.device_id is None
        assert alert.decoy_id is None
        assert alert.read_at is None
        assert alert.actioned_at is None
        assert alert.event_seq is None


class TestIncidentModel:
    """Test Incident model serialization."""

    def test_roundtrip(self) -> None:
        now = datetime.now(timezone.utc)
        incident = Incident(
            id=1,
            source_ip="192.168.1.50",
            status=IncidentStatus.ACTIVE,
            severity=AlertSeverity.HIGH,
            alert_count=3,
            first_alert_at=now,
            last_alert_at=now,
        )
        data = incident.model_dump(mode="json")
        restored = Incident.model_validate(data)
        assert restored.alert_count == 3
        assert restored.status == IncidentStatus.ACTIVE


class TestDecoyModel:
    """Test Decoy model serialization."""

    def test_roundtrip(self) -> None:
        now = datetime.now(timezone.utc)
        decoy = Decoy(
            id=1,
            name="Dev Server Trap",
            decoy_type=DecoyType.DEV_SERVER,
            bind_address="0.0.0.0",
            port=3000,
            status=DecoyStatus.ACTIVE,
            connection_count=5,
            credential_trip_count=0,
            failure_count=0,
            created_at=now,
            updated_at=now,
        )
        data = decoy.model_dump(mode="json")
        restored = Decoy.model_validate(data)
        assert restored.decoy_type == DecoyType.DEV_SERVER
        assert restored.port == 3000

    def test_optional_config_field(self) -> None:
        now = datetime.now(timezone.utc)
        decoy = Decoy(
            id=1,
            name="Test",
            decoy_type=DecoyType.FILE_SHARE,
            bind_address="0.0.0.0",
            port=9445,
            status=DecoyStatus.ACTIVE,
            connection_count=0,
            credential_trip_count=0,
            failure_count=0,
            created_at=now,
            updated_at=now,
        )
        assert decoy.config is None


class TestDecoyConnectionModel:
    """Test DecoyConnection model serialization."""

    def test_roundtrip(self) -> None:
        now = datetime.now(timezone.utc)
        conn = DecoyConnection(
            id=1,
            decoy_id=1,
            source_ip="192.168.1.50",
            port=3000,
            timestamp=now,
        )
        data = conn.model_dump(mode="json")
        restored = DecoyConnection.model_validate(data)
        assert restored.source_ip == "192.168.1.50"


class TestPlantedCredentialModel:
    """Test PlantedCredential model serialization."""

    def test_roundtrip(self) -> None:
        now = datetime.now(timezone.utc)
        cred = PlantedCredential(
            id=1,
            credential_type=CredentialType.AWS_KEY,
            credential_value="AKIAIOSFODNN7EXAMPLE",
            planted_location="passwords.txt",
            tripped=False,
            created_at=now,
        )
        data = cred.model_dump(mode="json")
        restored = PlantedCredential.model_validate(data)
        assert restored.credential_type == CredentialType.AWS_KEY

    def test_optional_canary_hostname(self) -> None:
        now = datetime.now(timezone.utc)
        cred = PlantedCredential(
            id=1,
            credential_type=CredentialType.DB_CONNECTION,
            credential_value="postgresql://fake:pass@host/db",
            planted_location="passwords.txt",
            tripped=False,
            created_at=now,
        )
        assert cred.canary_hostname is None
        assert cred.decoy_id is None


class TestCanaryObservationModel:
    """Test CanaryObservation model serialization."""

    def test_roundtrip(self) -> None:
        now = datetime.now(timezone.utc)
        obs = CanaryObservation(
            id=1,
            credential_id=5,
            canary_hostname="abc123.canary.squirrelops.io",
            queried_by_ip="192.168.1.50",
            observed_at=now,
        )
        data = obs.model_dump(mode="json")
        restored = CanaryObservation.model_validate(data)
        assert restored.canary_hostname == "abc123.canary.squirrelops.io"


class TestPairingInfoModel:
    """Test PairingInfo model serialization."""

    def test_roundtrip(self) -> None:
        now = datetime.now(timezone.utc)
        pairing = PairingInfo(
            id=1,
            client_name="Matt's MacBook Pro",
            client_cert_fingerprint="sha256:abcdef1234567890",
            is_local=False,
            paired_at=now,
        )
        data = pairing.model_dump(mode="json")
        restored = PairingInfo.model_validate(data)
        assert restored.client_name == "Matt's MacBook Pro"
        assert restored.is_local is False


class TestEventModel:
    """Test Event model serialization."""

    def test_roundtrip(self) -> None:
        now = datetime.now(timezone.utc)
        event = Event(
            seq=42,
            event_type="device.discovered",
            payload={"device_id": 1, "ip": "192.168.1.100"},
            created_at=now,
        )
        data = event.model_dump(mode="json")
        restored = Event.model_validate(data)
        assert restored.seq == 42
        assert restored.event_type == "device.discovered"
        assert restored.payload["device_id"] == 1

    def test_optional_source_id(self) -> None:
        now = datetime.now(timezone.utc)
        event = Event(
            seq=1,
            event_type="system.scan_complete",
            payload={},
            created_at=now,
        )
        assert event.source_id is None


class TestSystemStatusModel:
    """Test SystemStatus model serialization."""

    def test_roundtrip(self) -> None:
        now = datetime.now(timezone.utc)
        status = SystemStatus(
            version="0.1.0",
            profile=ResourceProfile.STANDARD,
            llm_mode=LLMMode.CLOUD,
            learning_mode=True,
            learning_progress=0.45,
            device_count=12,
            active_decoy_count=3,
            uptime_seconds=3600,
            last_scan_at=now,
        )
        data = status.model_dump(mode="json")
        restored = SystemStatus.model_validate(data)
        assert restored.profile == ResourceProfile.STANDARD
        assert restored.learning_progress == 0.45
        assert restored.device_count == 12

    def test_optional_last_scan(self) -> None:
        status = SystemStatus(
            version="0.1.0",
            profile=ResourceProfile.LITE,
            llm_mode=LLMMode.NONE,
            learning_mode=True,
            learning_progress=0.0,
            device_count=0,
            active_decoy_count=0,
            uptime_seconds=0,
        )
        assert status.last_scan_at is None


# ---------------------------------------------------------------------------
# from_attributes config test
# ---------------------------------------------------------------------------

class TestFromAttributes:
    """Verify models can be loaded from ORM-style attribute objects."""

    def test_device_from_attributes(self) -> None:
        class FakeRow:
            id = 1
            ip_address = "10.0.0.1"
            mac_address = None
            hostname = None
            vendor = None
            first_seen = "2025-01-01T00:00:00Z"
            last_seen = "2025-01-01T00:00:00Z"

        device = Device.model_validate(FakeRow(), from_attributes=True)
        assert device.id == 1
        assert device.ip_address == "10.0.0.1"
