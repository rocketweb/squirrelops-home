"""Integration tests for alert routes: list, get, incident detail, mark read/actioned, export."""
import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from tests.integration.conftest import seed_alerts, seed_incidents


class TestListAlerts:
    """GET /alerts -- paginated alert list with filters. Incidents appear as single items."""

    def test_list_returns_200(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=3))
        response = client.get("/alerts")
        assert response.status_code == 200

    def test_list_returns_all_alerts(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=3))
        response = client.get("/alerts")
        data = response.json()
        assert data["total"] == 3

    def test_list_pagination_limit(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=5))
        response = client.get("/alerts?limit=2")
        data = response.json()
        assert len(data["items"]) == 2
        assert data["total"] == 5

    def test_list_pagination_offset(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=5))
        response = client.get("/alerts?limit=2&offset=3")
        data = response.json()
        assert len(data["items"]) == 2

    def test_list_filter_by_severity(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=4))
        response = client.get("/alerts?severity=high")
        data = response.json()
        for item in data["items"]:
            assert item["severity"] == "high"

    def test_list_filter_by_alert_type(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=4))
        response = client.get("/alerts?alert_type=decoy_trip")
        data = response.json()
        for item in data["items"]:
            assert item["alert_type"] == "decoy_trip"

    def test_list_filter_by_unread(self, client, db):
        alert_ids = asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=3))
        # Mark one as read
        asyncio.get_event_loop().run_until_complete(
            db.execute(
                "UPDATE home_alerts SET read_at = '2026-02-22T12:00:00Z' WHERE id = ?",
                (alert_ids[0],),
            )
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        response = client.get("/alerts?unread=true")
        data = response.json()
        assert data["total"] == 2

    def test_list_filter_by_date_range(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=3))
        response = client.get(
            "/alerts?date_from=2026-02-22T02:00:00Z&date_to=2026-02-22T03:30:00Z"
        )
        data = response.json()
        # Only alerts at 02:00 and 03:00 should match
        assert data["total"] >= 1

    def test_list_incidents_appear_as_single_items(self, client, db):
        incident_id, alert_ids = asyncio.get_event_loop().run_until_complete(
            seed_incidents(db)
        )
        # Also add a standalone alert
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=1))
        response = client.get("/alerts")
        data = response.json()
        # Should see the incident as one item + the standalone alert
        incident_items = [i for i in data["items"] if i.get("incident_id") is not None]
        standalone_items = [i for i in data["items"] if i.get("incident_id") is None]
        # The incident's child alerts should be collapsed into one incident entry
        assert len(incident_items) <= 1 or any(
            i.get("alert_count", 0) > 1 for i in data["items"]
        )

    def test_list_empty_database(self, client, db):
        response = client.get("/alerts")
        data = response.json()
        assert data["total"] == 0
        assert data["items"] == []


class TestGetAlert:
    """GET /alerts/{id} -- standalone alert detail."""

    def test_get_returns_200(self, client, db):
        alert_ids = asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=1))
        response = client.get(f"/alerts/{alert_ids[0]}")
        assert response.status_code == 200

    def test_get_returns_alert_fields(self, client, db):
        alert_ids = asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=1))
        response = client.get(f"/alerts/{alert_ids[0]}")
        data = response.json()
        assert "id" in data
        assert "alert_type" in data
        assert "severity" in data
        assert "title" in data
        assert "detail" in data
        assert "source_ip" in data
        assert "created_at" in data

    def test_get_nonexistent_returns_404(self, client, db):
        response = client.get("/alerts/9999")
        assert response.status_code == 404


class TestGetIncident:
    """GET /incidents/{id} -- incident with all child alerts chronologically."""

    def test_get_incident_returns_200(self, client, db):
        incident_id, _ = asyncio.get_event_loop().run_until_complete(seed_incidents(db))
        response = client.get(f"/incidents/{incident_id}")
        assert response.status_code == 200

    def test_get_incident_includes_child_alerts(self, client, db):
        incident_id, alert_ids = asyncio.get_event_loop().run_until_complete(
            seed_incidents(db)
        )
        response = client.get(f"/incidents/{incident_id}")
        data = response.json()
        assert "alerts" in data
        assert len(data["alerts"]) == 3

    def test_get_incident_child_alerts_chronological(self, client, db):
        incident_id, _ = asyncio.get_event_loop().run_until_complete(seed_incidents(db))
        response = client.get(f"/incidents/{incident_id}")
        data = response.json()
        alerts = data["alerts"]
        for i in range(len(alerts) - 1):
            assert alerts[i]["created_at"] <= alerts[i + 1]["created_at"]

    def test_get_incident_includes_summary(self, client, db):
        incident_id, _ = asyncio.get_event_loop().run_until_complete(seed_incidents(db))
        response = client.get(f"/incidents/{incident_id}")
        data = response.json()
        assert "summary" in data
        assert data["summary"] is not None

    def test_get_incident_includes_severity(self, client, db):
        incident_id, _ = asyncio.get_event_loop().run_until_complete(seed_incidents(db))
        response = client.get(f"/incidents/{incident_id}")
        data = response.json()
        assert data["severity"] == "high"

    def test_get_incident_nonexistent_returns_404(self, client, db):
        response = client.get("/incidents/9999")
        assert response.status_code == 404


class TestMarkRead:
    """PUT /alerts/{id}/read and PUT /incidents/{id}/read."""

    def test_mark_alert_read(self, client, db):
        alert_ids = asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=1))
        response = client.put(f"/alerts/{alert_ids[0]}/read")
        assert response.status_code == 200
        data = response.json()
        assert data["read_at"] is not None

    def test_mark_alert_read_idempotent(self, client, db):
        alert_ids = asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=1))
        client.put(f"/alerts/{alert_ids[0]}/read")
        response = client.put(f"/alerts/{alert_ids[0]}/read")
        assert response.status_code == 200

    def test_mark_alert_read_nonexistent_returns_404(self, client, db):
        response = client.put("/alerts/9999/read")
        assert response.status_code == 404

    def test_mark_incident_read(self, client, db):
        incident_id, alert_ids = asyncio.get_event_loop().run_until_complete(
            seed_incidents(db)
        )
        response = client.put(f"/incidents/{incident_id}/read")
        assert response.status_code == 200

    def test_mark_incident_read_marks_all_children(self, client, db):
        incident_id, alert_ids = asyncio.get_event_loop().run_until_complete(
            seed_incidents(db)
        )
        client.put(f"/incidents/{incident_id}/read")
        # Verify all child alerts are marked read
        for aid in alert_ids:
            response = client.get(f"/alerts/{aid}")
            assert response.json()["read_at"] is not None

    def test_mark_incident_read_nonexistent_returns_404(self, client, db):
        response = client.put("/incidents/9999/read")
        assert response.status_code == 404


class TestMarkActioned:
    """PUT /alerts/{id}/action -- mark alert as actioned with optional note."""

    def test_mark_actioned(self, client, db):
        alert_ids = asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=1))
        response = client.put(f"/alerts/{alert_ids[0]}/action", json={})
        assert response.status_code == 200
        data = response.json()
        assert data["actioned_at"] is not None

    def test_mark_actioned_with_note(self, client, db):
        alert_ids = asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=1))
        response = client.put(
            f"/alerts/{alert_ids[0]}/action",
            json={"note": "Investigated -- benign scanner"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["actioned_at"] is not None
        assert data["action_note"] == "Investigated -- benign scanner"

    def test_mark_actioned_nonexistent_returns_404(self, client, db):
        response = client.put("/alerts/9999/action", json={})
        assert response.status_code == 404


class TestExportAlerts:
    """GET /alerts/export -- JSON export with date range."""

    def test_export_returns_200(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=3))
        response = client.get("/alerts/export")
        assert response.status_code == 200

    def test_export_returns_all_alerts_as_json(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=3))
        response = client.get("/alerts/export")
        data = response.json()
        assert "alerts" in data
        assert len(data["alerts"]) == 3

    def test_export_with_date_range(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=3))
        response = client.get(
            "/alerts/export?date_from=2026-02-22T02:00:00Z&date_to=2026-02-22T03:30:00Z"
        )
        data = response.json()
        assert len(data["alerts"]) >= 1

    def test_export_includes_incidents(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_incidents(db))
        response = client.get("/alerts/export")
        data = response.json()
        assert "incidents" in data
        assert len(data["incidents"]) >= 1

    def test_export_empty_database(self, client, db):
        response = client.get("/alerts/export")
        data = response.json()
        assert data["alerts"] == []
