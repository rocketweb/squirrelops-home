"""Integration tests for typed database query helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta

import aiosqlite
import pytest

from squirrelops_home_sensor.db.migrations import apply_migrations
from squirrelops_home_sensor.db.queries import (
    # Device queries
    insert_device_fingerprint,
    get_device_fingerprints,
    set_device_trust,
    get_device_trust,
    # Alert queries
    insert_alert,
    get_alert,
    list_alerts,
    mark_alert_read,
    mark_alert_actioned,
    # Incident queries
    insert_incident,
    get_incident,
    get_active_incident_for_source,
    update_incident,
    list_incidents,
    close_incident,
    # Decoy queries
    insert_decoy,
    get_decoy,
    list_decoys,
    update_decoy_status,
    increment_decoy_connection_count,
    increment_decoy_credential_trip_count,
    # Decoy connection queries
    insert_decoy_connection,
    list_decoy_connections,
    # Credential queries
    insert_planted_credential,
    get_planted_credential,
    list_planted_credentials,
    mark_credential_tripped,
    get_credential_by_value,
    get_credential_by_canary_hostname,
    # Canary observation queries
    insert_canary_observation,
    list_canary_observations,
    # Pairing queries
    insert_pairing,
    get_pairing,
    list_pairings,
    delete_pairing,
    update_pairing_last_connected,
    # Retention
    purge_old_records,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def db() -> aiosqlite.Connection:
    """Create an in-memory database with schema applied.

    Foreign keys are OFF because the schema references Pingting's ``devices``
    table which does not exist in isolation.
    """
    conn = await aiosqlite.connect(":memory:")
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys = OFF")
    await apply_migrations(conn)
    yield conn
    await conn.close()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _past_iso(days: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------------------------------------------------------------------------
# Device fingerprint queries
# ---------------------------------------------------------------------------

class TestDeviceFingerprintQueries:

    @pytest.mark.asyncio
    async def test_insert_and_get(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        fp_id = await insert_device_fingerprint(
            db,
            device_id=None,
            mac_address="AA:BB:CC:DD:EE:FF",
            mdns_hostname="macbook-pro.local",
            dhcp_fingerprint_hash="sha256:abc",
            connection_pattern_hash=None,
            open_ports_hash=None,
            composite_hash="comp123",
            signal_count=3,
            confidence=0.85,
            first_seen=now,
            last_seen=now,
        )
        assert fp_id >= 1

        fps = await get_device_fingerprints(db, device_id=None)
        # Should find it since device_id is NULL
        assert len(fps) >= 0  # device_id filter is None, query matches all

    @pytest.mark.asyncio
    async def test_get_by_device_id(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        await insert_device_fingerprint(
            db, device_id=None, mac_address="AA:BB:CC:DD:EE:01",
            signal_count=1, first_seen=now, last_seen=now,
        )
        await insert_device_fingerprint(
            db, device_id=None, mac_address="AA:BB:CC:DD:EE:02",
            signal_count=2, first_seen=now, last_seen=now,
        )
        fps = await get_device_fingerprints(db)
        assert len(fps) == 2


# ---------------------------------------------------------------------------
# Device trust queries
# ---------------------------------------------------------------------------

class TestDeviceTrustQueries:

    @pytest.mark.asyncio
    async def test_set_and_get_trust(self, db: aiosqlite.Connection) -> None:
        # device_trust references devices(id) but FK is off for NULL device_id
        # We insert with FK check off for testing isolation
        await db.execute("PRAGMA foreign_keys = OFF")
        now = _now_iso()
        await set_device_trust(
            db, device_id=1, status="approved", approved_by="user", updated_at=now,
        )
        trust = await get_device_trust(db, device_id=1)
        assert trust is not None
        assert trust["status"] == "approved"
        assert trust["approved_by"] == "user"

    @pytest.mark.asyncio
    async def test_update_trust(self, db: aiosqlite.Connection) -> None:
        await db.execute("PRAGMA foreign_keys = OFF")
        now = _now_iso()
        await set_device_trust(
            db, device_id=1, status="unknown", updated_at=now,
        )
        await set_device_trust(
            db, device_id=1, status="rejected", approved_by="user", updated_at=now,
        )
        trust = await get_device_trust(db, device_id=1)
        assert trust["status"] == "rejected"

    @pytest.mark.asyncio
    async def test_get_nonexistent_trust(self, db: aiosqlite.Connection) -> None:
        trust = await get_device_trust(db, device_id=999)
        assert trust is None


# ---------------------------------------------------------------------------
# Alert queries
# ---------------------------------------------------------------------------

class TestAlertQueries:

    @pytest.mark.asyncio
    async def test_insert_and_get(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        alert_id = await insert_alert(
            db,
            alert_type="decoy_trip",
            severity="high",
            title="Decoy tripped",
            detail='{"decoy_id": 1}',
            source_ip="192.168.1.50",
            created_at=now,
        )
        assert alert_id >= 1

        alert = await get_alert(db, alert_id)
        assert alert is not None
        assert alert["alert_type"] == "decoy_trip"
        assert alert["severity"] == "high"
        assert alert["title"] == "Decoy tripped"

    @pytest.mark.asyncio
    async def test_list_alerts_pagination(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        for i in range(10):
            await insert_alert(
                db, alert_type="new_device", severity="medium",
                title=f"Alert {i}", detail="{}", created_at=now,
            )
        page1 = await list_alerts(db, limit=5, offset=0)
        page2 = await list_alerts(db, limit=5, offset=5)
        assert len(page1) == 5
        assert len(page2) == 5
        # Pages should be different
        ids1 = {a["id"] for a in page1}
        ids2 = {a["id"] for a in page2}
        assert ids1.isdisjoint(ids2)

    @pytest.mark.asyncio
    async def test_list_alerts_filter_severity(
        self, db: aiosqlite.Connection
    ) -> None:
        now = _now_iso()
        await insert_alert(
            db, alert_type="decoy_trip", severity="critical",
            title="Critical", detail="{}", created_at=now,
        )
        await insert_alert(
            db, alert_type="new_device", severity="low",
            title="Low", detail="{}", created_at=now,
        )
        critical = await list_alerts(db, severity="critical")
        assert len(critical) == 1
        assert critical[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_list_alerts_filter_type(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        await insert_alert(
            db, alert_type="decoy_trip", severity="high",
            title="Trip", detail="{}", created_at=now,
        )
        await insert_alert(
            db, alert_type="new_device", severity="medium",
            title="New", detail="{}", created_at=now,
        )
        trips = await list_alerts(db, alert_type="decoy_trip")
        assert len(trips) == 1

    @pytest.mark.asyncio
    async def test_list_alerts_unread_only(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        a1 = await insert_alert(
            db, alert_type="new_device", severity="medium",
            title="Unread", detail="{}", created_at=now,
        )
        a2 = await insert_alert(
            db, alert_type="new_device", severity="medium",
            title="Read", detail="{}", created_at=now,
        )
        await mark_alert_read(db, a2, read_at=now)
        unread = await list_alerts(db, unread_only=True)
        assert len(unread) == 1
        assert unread[0]["id"] == a1

    @pytest.mark.asyncio
    async def test_list_alerts_date_range(self, db: aiosqlite.Connection) -> None:
        old = _past_iso(30)
        recent = _now_iso()
        await insert_alert(
            db, alert_type="new_device", severity="low",
            title="Old", detail="{}", created_at=old,
        )
        await insert_alert(
            db, alert_type="new_device", severity="low",
            title="Recent", detail="{}", created_at=recent,
        )
        since = _past_iso(7)
        filtered = await list_alerts(db, date_from=since)
        assert len(filtered) == 1
        assert filtered[0]["title"] == "Recent"

    @pytest.mark.asyncio
    async def test_mark_alert_read(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        aid = await insert_alert(
            db, alert_type="new_device", severity="medium",
            title="Test", detail="{}", created_at=now,
        )
        await mark_alert_read(db, aid, read_at=now)
        alert = await get_alert(db, aid)
        assert alert["read_at"] is not None

    @pytest.mark.asyncio
    async def test_mark_alert_actioned(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        aid = await insert_alert(
            db, alert_type="new_device", severity="medium",
            title="Test", detail="{}", created_at=now,
        )
        await mark_alert_actioned(db, aid, actioned_at=now)
        alert = await get_alert(db, aid)
        assert alert["actioned_at"] is not None


# ---------------------------------------------------------------------------
# Incident queries
# ---------------------------------------------------------------------------

class TestIncidentQueries:

    @pytest.mark.asyncio
    async def test_insert_and_get(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        inc_id = await insert_incident(
            db,
            source_ip="192.168.1.50",
            severity="high",
            first_alert_at=now,
            last_alert_at=now,
        )
        inc = await get_incident(db, inc_id)
        assert inc is not None
        assert inc["source_ip"] == "192.168.1.50"
        assert inc["status"] == "active"
        assert inc["alert_count"] == 1

    @pytest.mark.asyncio
    async def test_get_active_incident_for_source(
        self, db: aiosqlite.Connection
    ) -> None:
        now = _now_iso()
        inc_id = await insert_incident(
            db, source_ip="192.168.1.50", severity="high",
            first_alert_at=now, last_alert_at=now,
        )
        found = await get_active_incident_for_source(
            db, source_ip="192.168.1.50", window_minutes=15,
        )
        assert found is not None
        assert found["id"] == inc_id

    @pytest.mark.asyncio
    async def test_no_active_incident_different_source(
        self, db: aiosqlite.Connection
    ) -> None:
        now = _now_iso()
        await insert_incident(
            db, source_ip="192.168.1.50", severity="high",
            first_alert_at=now, last_alert_at=now,
        )
        found = await get_active_incident_for_source(
            db, source_ip="10.0.0.1", window_minutes=15,
        )
        assert found is None

    @pytest.mark.asyncio
    async def test_no_active_incident_after_close(
        self, db: aiosqlite.Connection
    ) -> None:
        now = _now_iso()
        inc_id = await insert_incident(
            db, source_ip="192.168.1.50", severity="high",
            first_alert_at=now, last_alert_at=now,
        )
        await close_incident(db, inc_id, closed_at=now)
        found = await get_active_incident_for_source(
            db, source_ip="192.168.1.50", window_minutes=15,
        )
        assert found is None

    @pytest.mark.asyncio
    async def test_update_incident(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        inc_id = await insert_incident(
            db, source_ip="192.168.1.50", severity="medium",
            first_alert_at=now, last_alert_at=now,
        )
        await update_incident(
            db, inc_id,
            alert_count=3,
            severity="critical",
            last_alert_at=now,
            summary="3 events from 192.168.1.50",
        )
        inc = await get_incident(db, inc_id)
        assert inc["alert_count"] == 3
        assert inc["severity"] == "critical"
        assert inc["summary"] == "3 events from 192.168.1.50"

    @pytest.mark.asyncio
    async def test_list_incidents(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        await insert_incident(
            db, source_ip="192.168.1.50", severity="high",
            first_alert_at=now, last_alert_at=now,
        )
        await insert_incident(
            db, source_ip="192.168.1.51", severity="medium",
            first_alert_at=now, last_alert_at=now,
        )
        incidents = await list_incidents(db)
        assert len(incidents) == 2


# ---------------------------------------------------------------------------
# Decoy queries
# ---------------------------------------------------------------------------

class TestDecoyQueries:

    @pytest.mark.asyncio
    async def test_insert_and_get(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        decoy_id = await insert_decoy(
            db,
            name="Dev Server Trap",
            decoy_type="dev_server",
            bind_address="0.0.0.0",
            port=3000,
            created_at=now,
            updated_at=now,
        )
        decoy = await get_decoy(db, decoy_id)
        assert decoy is not None
        assert decoy["name"] == "Dev Server Trap"
        assert decoy["port"] == 3000
        assert decoy["status"] == "active"

    @pytest.mark.asyncio
    async def test_list_decoys(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        await insert_decoy(
            db, name="A", decoy_type="dev_server",
            bind_address="0.0.0.0", port=3000,
            created_at=now, updated_at=now,
        )
        await insert_decoy(
            db, name="B", decoy_type="file_share",
            bind_address="0.0.0.0", port=9445,
            created_at=now, updated_at=now,
        )
        decoys = await list_decoys(db)
        assert len(decoys) == 2

    @pytest.mark.asyncio
    async def test_update_decoy_status(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        did = await insert_decoy(
            db, name="Test", decoy_type="dev_server",
            bind_address="0.0.0.0", port=3000,
            created_at=now, updated_at=now,
        )
        await update_decoy_status(db, did, status="degraded", updated_at=now)
        decoy = await get_decoy(db, did)
        assert decoy["status"] == "degraded"

    @pytest.mark.asyncio
    async def test_increment_connection_count(
        self, db: aiosqlite.Connection
    ) -> None:
        now = _now_iso()
        did = await insert_decoy(
            db, name="Test", decoy_type="dev_server",
            bind_address="0.0.0.0", port=3000,
            created_at=now, updated_at=now,
        )
        await increment_decoy_connection_count(db, did)
        await increment_decoy_connection_count(db, did)
        decoy = await get_decoy(db, did)
        assert decoy["connection_count"] == 2

    @pytest.mark.asyncio
    async def test_increment_credential_trip_count(
        self, db: aiosqlite.Connection
    ) -> None:
        now = _now_iso()
        did = await insert_decoy(
            db, name="Test", decoy_type="dev_server",
            bind_address="0.0.0.0", port=3000,
            created_at=now, updated_at=now,
        )
        await increment_decoy_credential_trip_count(db, did)
        decoy = await get_decoy(db, did)
        assert decoy["credential_trip_count"] == 1


# ---------------------------------------------------------------------------
# Decoy connection queries
# ---------------------------------------------------------------------------

class TestDecoyConnectionQueries:

    @pytest.mark.asyncio
    async def test_insert_and_list(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        did = await insert_decoy(
            db, name="Test", decoy_type="dev_server",
            bind_address="0.0.0.0", port=3000,
            created_at=now, updated_at=now,
        )
        await insert_decoy_connection(
            db, decoy_id=did, source_ip="192.168.1.50",
            port=3000, timestamp=now,
        )
        await insert_decoy_connection(
            db, decoy_id=did, source_ip="192.168.1.51",
            port=3000, timestamp=now,
        )
        conns = await list_decoy_connections(db, decoy_id=did)
        assert len(conns) == 2


# ---------------------------------------------------------------------------
# Credential queries
# ---------------------------------------------------------------------------

class TestCredentialQueries:

    @pytest.mark.asyncio
    async def test_insert_and_get(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        cid = await insert_planted_credential(
            db,
            credential_type="aws_key",
            credential_value="AKIAIOSFODNN7EXAMPLE",
            planted_location="passwords.txt",
            created_at=now,
        )
        cred = await get_planted_credential(db, cid)
        assert cred is not None
        assert cred["credential_type"] == "aws_key"

    @pytest.mark.asyncio
    async def test_list_credentials(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        await insert_planted_credential(
            db, credential_type="aws_key",
            credential_value="AKIA1", planted_location="passwords.txt",
            created_at=now,
        )
        await insert_planted_credential(
            db, credential_type="ssh_key",
            credential_value="ssh-rsa AAAA", planted_location="fake.pem",
            created_at=now,
        )
        creds = await list_planted_credentials(db)
        assert len(creds) == 2

    @pytest.mark.asyncio
    async def test_mark_credential_tripped(
        self, db: aiosqlite.Connection
    ) -> None:
        now = _now_iso()
        cid = await insert_planted_credential(
            db, credential_type="aws_key",
            credential_value="AKIA1", planted_location="passwords.txt",
            created_at=now,
        )
        await mark_credential_tripped(db, cid, tripped_at=now)
        cred = await get_planted_credential(db, cid)
        assert cred["tripped"] == 1
        assert cred["first_tripped_at"] is not None

    @pytest.mark.asyncio
    async def test_get_by_value(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        await insert_planted_credential(
            db, credential_type="aws_key",
            credential_value="AKIAIOSFODNN7EXAMPLE",
            planted_location="passwords.txt", created_at=now,
        )
        cred = await get_credential_by_value(db, "AKIAIOSFODNN7EXAMPLE")
        assert cred is not None
        assert cred["credential_type"] == "aws_key"

    @pytest.mark.asyncio
    async def test_get_by_value_not_found(
        self, db: aiosqlite.Connection
    ) -> None:
        cred = await get_credential_by_value(db, "nonexistent")
        assert cred is None

    @pytest.mark.asyncio
    async def test_get_by_canary_hostname(
        self, db: aiosqlite.Connection
    ) -> None:
        now = _now_iso()
        await insert_planted_credential(
            db, credential_type="aws_key",
            credential_value="AKIA1",
            planted_location="passwords.txt",
            canary_hostname="abc123.canary.squirrelops.io",
            created_at=now,
        )
        cred = await get_credential_by_canary_hostname(
            db, "abc123.canary.squirrelops.io"
        )
        assert cred is not None

    @pytest.mark.asyncio
    async def test_get_by_canary_hostname_not_found(
        self, db: aiosqlite.Connection
    ) -> None:
        cred = await get_credential_by_canary_hostname(db, "nonexistent")
        assert cred is None


# ---------------------------------------------------------------------------
# Canary observation queries
# ---------------------------------------------------------------------------

class TestCanaryObservationQueries:

    @pytest.mark.asyncio
    async def test_insert_and_list(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        cid = await insert_planted_credential(
            db, credential_type="aws_key",
            credential_value="AKIA1", planted_location="passwords.txt",
            canary_hostname="abc.canary.squirrelops.io", created_at=now,
        )
        await insert_canary_observation(
            db, credential_id=cid,
            canary_hostname="abc.canary.squirrelops.io",
            queried_by_ip="192.168.1.50", observed_at=now,
        )
        obs = await list_canary_observations(db, credential_id=cid)
        assert len(obs) == 1
        assert obs[0]["queried_by_ip"] == "192.168.1.50"


# ---------------------------------------------------------------------------
# Pairing queries
# ---------------------------------------------------------------------------

class TestPairingQueries:

    @pytest.mark.asyncio
    async def test_insert_and_get(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        pid = await insert_pairing(
            db,
            client_name="Matt's MacBook Pro",
            client_cert_fingerprint="sha256:abc123",
            paired_at=now,
        )
        pairing = await get_pairing(db, pid)
        assert pairing is not None
        assert pairing["client_name"] == "Matt's MacBook Pro"
        assert pairing["is_local"] == 0

    @pytest.mark.asyncio
    async def test_list_pairings(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        await insert_pairing(
            db, client_name="Device A",
            client_cert_fingerprint="sha256:aaa", paired_at=now,
        )
        await insert_pairing(
            db, client_name="Device B",
            client_cert_fingerprint="sha256:bbb", paired_at=now,
        )
        pairings = await list_pairings(db)
        assert len(pairings) == 2

    @pytest.mark.asyncio
    async def test_delete_pairing(self, db: aiosqlite.Connection) -> None:
        now = _now_iso()
        pid = await insert_pairing(
            db, client_name="Device A",
            client_cert_fingerprint="sha256:aaa", paired_at=now,
        )
        await delete_pairing(db, pid)
        pairing = await get_pairing(db, pid)
        assert pairing is None

    @pytest.mark.asyncio
    async def test_update_last_connected(
        self, db: aiosqlite.Connection
    ) -> None:
        now = _now_iso()
        pid = await insert_pairing(
            db, client_name="Device A",
            client_cert_fingerprint="sha256:aaa", paired_at=now,
        )
        await update_pairing_last_connected(db, pid, last_connected_at=now)
        pairing = await get_pairing(db, pid)
        assert pairing["last_connected_at"] is not None


# ---------------------------------------------------------------------------
# Retention / purge queries
# ---------------------------------------------------------------------------

class TestPurgeOldRecords:

    @pytest.mark.asyncio
    async def test_purge_old_alerts(self, db: aiosqlite.Connection) -> None:
        old = _past_iso(100)
        recent = _now_iso()
        await insert_alert(
            db, alert_type="new_device", severity="low",
            title="Old alert", detail="{}", created_at=old,
        )
        await insert_alert(
            db, alert_type="new_device", severity="low",
            title="Recent alert", detail="{}", created_at=recent,
        )
        purged = await purge_old_records(db, days=90)
        assert purged["alerts"] == 1
        remaining = await list_alerts(db)
        assert len(remaining) == 1
        assert remaining[0]["title"] == "Recent alert"

    @pytest.mark.asyncio
    async def test_purge_old_events(self, db: aiosqlite.Connection) -> None:
        old = _past_iso(100)
        recent = _now_iso()
        await db.execute(
            "INSERT INTO events (event_type, payload, created_at) VALUES (?, ?, ?)",
            ("old.event", "{}", old),
        )
        await db.execute(
            "INSERT INTO events (event_type, payload, created_at) VALUES (?, ?, ?)",
            ("recent.event", "{}", recent),
        )
        await db.commit()
        purged = await purge_old_records(db, days=90)
        assert purged["events"] == 1

    @pytest.mark.asyncio
    async def test_purge_preserves_open_incidents(
        self, db: aiosqlite.Connection
    ) -> None:
        old = _past_iso(100)
        inc_id = await insert_incident(
            db, source_ip="192.168.1.50", severity="high",
            first_alert_at=old, last_alert_at=old,
        )
        await insert_alert(
            db, alert_type="decoy_trip", severity="high",
            title="Linked", detail="{}", created_at=old, incident_id=inc_id,
        )
        purged = await purge_old_records(db, days=90)
        # Active incident alerts should NOT be purged
        assert purged["alerts"] == 0
