"""Integration tests for device routes: list, get, update, trust actions, fingerprint history."""
import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from tests.integration.conftest import seed_devices


class TestListDevices:
    """GET /devices -- paginated device list with filters and search."""

    def test_list_returns_200(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_devices(db, count=3))
        response = client.get("/devices")
        assert response.status_code == 200

    def test_list_returns_all_devices(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_devices(db, count=3))
        response = client.get("/devices")
        data = response.json()
        assert len(data["items"]) == 3

    def test_list_pagination_limit(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_devices(db, count=5))
        response = client.get("/devices?limit=2")
        data = response.json()
        assert len(data["items"]) == 2
        assert data["total"] == 5

    def test_list_pagination_offset(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_devices(db, count=5))
        response = client.get("/devices?limit=2&offset=3")
        data = response.json()
        assert len(data["items"]) == 2
        assert data["total"] == 5

    def test_list_pagination_offset_past_end(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_devices(db, count=3))
        response = client.get("/devices?offset=10")
        data = response.json()
        assert len(data["items"]) == 0
        assert data["total"] == 3

    def test_list_filter_by_trust_status(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=3))
        # Approve one device
        asyncio.get_event_loop().run_until_complete(
            db.execute(
                "UPDATE device_trust SET status = 'approved' WHERE device_id = ?",
                (ids[0],),
            )
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        response = client.get("/devices?trust_status=approved")
        data = response.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["id"] == ids[0]

    def test_list_filter_by_online(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=3))
        # Take one device offline
        asyncio.get_event_loop().run_until_complete(
            db.execute("UPDATE devices SET is_online = 0 WHERE id = ?", (ids[0],))
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        response = client.get("/devices?online=true")
        data = response.json()
        assert len(data["items"]) == 2

    def test_list_search_by_hostname(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_devices(db, count=3))
        response = client.get("/devices?search=device-2")
        data = response.json()
        assert len(data["items"]) == 1
        assert "device-2" in data["items"][0]["hostname"]

    def test_list_search_by_ip(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_devices(db, count=3))
        response = client.get("/devices?search=192.168.1.101")
        data = response.json()
        assert len(data["items"]) == 1

    def test_list_search_by_mac(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_devices(db, count=3))
        response = client.get("/devices?search=AA:BB:CC:DD:EE:02")
        data = response.json()
        assert len(data["items"]) == 1

    def test_list_empty_database(self, client, db):
        response = client.get("/devices")
        data = response.json()
        assert len(data["items"]) == 0
        assert data["total"] == 0


class TestGetDevice:
    """GET /devices/{id} -- device detail with latest fingerprint and trust."""

    def test_get_returns_200(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.get(f"/devices/{ids[0]}")
        assert response.status_code == 200

    def test_get_returns_device_fields(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.get(f"/devices/{ids[0]}")
        data = response.json()
        assert data["id"] == ids[0]
        assert "ip_address" in data
        assert "mac_address" in data
        assert "hostname" in data
        assert "vendor" in data
        assert "trust_status" in data
        assert "first_seen" in data
        assert "last_seen" in data
        assert "is_online" in data

    def test_get_includes_trust_status(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.get(f"/devices/{ids[0]}")
        data = response.json()
        assert data["trust_status"] == "unknown"

    def test_get_includes_latest_fingerprint(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        # Insert a fingerprint
        asyncio.get_event_loop().run_until_complete(
            db.execute(
                """INSERT INTO device_fingerprints
                   (device_id, mac_address, open_ports_hash, composite_hash,
                    signal_count, confidence, first_seen, last_seen)
                   VALUES (?, 'AA:BB:CC:DD:EE:01', 'hash1', 'comp1', 2, 0.85,
                   '2026-02-22T00:00:00Z', '2026-02-22T01:00:00Z')""",
                (ids[0],),
            )
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        response = client.get(f"/devices/{ids[0]}")
        data = response.json()
        assert data["latest_fingerprint"] is not None
        assert data["latest_fingerprint"]["confidence"] == 0.85

    def test_get_nonexistent_returns_404(self, client, db):
        response = client.get("/devices/9999")
        assert response.status_code == 404


class TestUpdateDevice:
    """PUT /devices/{id} -- update custom name and notes."""

    def test_update_custom_name(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.put(
            f"/devices/{ids[0]}", json={"custom_name": "Living Room Hub"}
        )
        assert response.status_code == 200
        assert response.json()["custom_name"] == "Living Room Hub"

    def test_update_notes(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.put(
            f"/devices/{ids[0]}", json={"notes": "Main router for upstairs"}
        )
        assert response.status_code == 200
        assert response.json()["notes"] == "Main router for upstairs"

    def test_update_preserves_other_fields(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.put(
            f"/devices/{ids[0]}", json={"custom_name": "Test Name"}
        )
        data = response.json()
        assert data["ip_address"] == "192.168.1.101"
        assert data["mac_address"] == "AA:BB:CC:DD:EE:01"

    def test_update_nonexistent_returns_404(self, client, db):
        response = client.put("/devices/9999", json={"custom_name": "Nope"})
        assert response.status_code == 404

    def test_update_device_type(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.put(
            f"/devices/{ids[0]}", json={"device_type": "smart_home"}
        )
        assert response.status_code == 200
        assert response.json()["device_type"] == "smart_home"

    def test_update_name_and_type_together(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.put(
            f"/devices/{ids[0]}",
            json={"custom_name": "Kitchen Speaker", "device_type": "smart_home"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["custom_name"] == "Kitchen Speaker"
        assert data["device_type"] == "smart_home"


class TestDeviceTrustActions:
    """POST /devices/{id}/approve|reject|ignore|verify -- trust state transitions."""

    def test_approve_device(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.post(f"/devices/{ids[0]}/approve")
        assert response.status_code == 200
        assert response.json()["trust_status"] == "approved"

    def test_reject_device(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.post(f"/devices/{ids[0]}/reject")
        assert response.status_code == 200
        assert response.json()["trust_status"] == "rejected"

    def test_ignore_device(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.post(f"/devices/{ids[0]}/ignore")
        assert response.status_code == 200
        assert response.json()["trust_status"] == "unknown"

    def test_verify_device(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        # First approve, then verify triggers re-fingerprint
        client.post(f"/devices/{ids[0]}/approve")
        response = client.post(f"/devices/{ids[0]}/verify")
        assert response.status_code == 200
        assert response.json()["trust_status"] == "approved"
        assert response.json()["verification_requested"] is True

    def test_trust_action_nonexistent_returns_404(self, client, db):
        response = client.post("/devices/9999/approve")
        assert response.status_code == 404

    def test_trust_action_updates_timestamp(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.post(f"/devices/{ids[0]}/approve")
        data = response.json()
        assert "trust_updated_at" in data


class TestFingerprintHistory:
    """GET /devices/{id}/fingerprints -- fingerprint change history."""

    def test_fingerprint_history_returns_200(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.get(f"/devices/{ids[0]}/fingerprints")
        assert response.status_code == 200

    def test_fingerprint_history_empty(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.get(f"/devices/{ids[0]}/fingerprints")
        data = response.json()
        assert data["items"] == []

    def test_fingerprint_history_returns_entries(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        for i in range(3):
            asyncio.get_event_loop().run_until_complete(
                db.execute(
                    """INSERT INTO device_fingerprints
                       (device_id, mac_address, composite_hash, signal_count,
                        confidence, first_seen, last_seen)
                       VALUES (?, 'AA:BB:CC:DD:EE:01', ?, 2, ?,
                       '2026-02-22T00:00:00Z', ?)""",
                    (ids[0], f"hash-{i}", 0.7 + i * 0.1, f"2026-02-22T{i:02d}:00:00Z"),
                )
            )
        asyncio.get_event_loop().run_until_complete(db.commit())
        response = client.get(f"/devices/{ids[0]}/fingerprints")
        data = response.json()
        assert len(data["items"]) == 3

    def test_fingerprint_history_ordered_by_last_seen_desc(self, client, db):
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        for i in range(3):
            asyncio.get_event_loop().run_until_complete(
                db.execute(
                    """INSERT INTO device_fingerprints
                       (device_id, mac_address, composite_hash, signal_count,
                        confidence, first_seen, last_seen)
                       VALUES (?, 'AA:BB:CC:DD:EE:01', ?, 2, 0.8,
                       '2026-02-20T00:00:00Z', ?)""",
                    (ids[0], f"hash-{i}", f"2026-02-22T{i:02d}:00:00Z"),
                )
            )
        asyncio.get_event_loop().run_until_complete(db.commit())
        response = client.get(f"/devices/{ids[0]}/fingerprints")
        data = response.json()
        # Most recent last_seen first
        assert data["items"][0]["last_seen"] >= data["items"][1]["last_seen"]

    def test_fingerprint_history_nonexistent_device_returns_404(self, client, db):
        response = client.get("/devices/9999/fingerprints")
        assert response.status_code == 404


class TestDeviceArea:
    """Area field in device summary and detail responses."""

    def test_device_summary_includes_area(self, client, db):
        """GET /devices returns area field in device summary."""
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        # Set area on the device
        asyncio.get_event_loop().run_until_complete(
            db.execute("UPDATE devices SET area = ? WHERE id = ?", ("Living Room", ids[0]))
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        response = client.get("/devices")
        data = response.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["area"] == "Living Room"

    def test_device_summary_area_null_by_default(self, client, db):
        """GET /devices returns area=null when not set."""
        asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.get("/devices")
        data = response.json()
        assert data["items"][0]["area"] is None

    def test_device_detail_includes_area(self, client, db):
        """GET /devices/{id} returns area field in device detail."""
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        # Set area on the device
        asyncio.get_event_loop().run_until_complete(
            db.execute("UPDATE devices SET area = ? WHERE id = ?", ("Kitchen", ids[0]))
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        response = client.get(f"/devices/{ids[0]}")
        data = response.json()
        assert data["area"] == "Kitchen"

    def test_device_detail_area_null_by_default(self, client, db):
        """GET /devices/{id} returns area=null when not set."""
        ids = asyncio.get_event_loop().run_until_complete(seed_devices(db, count=1))
        response = client.get(f"/devices/{ids[0]}")
        data = response.json()
        assert data["area"] is None
