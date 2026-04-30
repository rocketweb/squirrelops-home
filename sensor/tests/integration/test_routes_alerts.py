"""Integration tests for alert routes: list, get, incident detail, mark read/actioned, export."""
import asyncio

from tests.integration.conftest import seed_alerts, seed_grouped_alerts, seed_incidents


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


class TestGroupedAlerts:
    """Tests for grouped alerts (security.port_risk with issue_key)."""

    def test_list_returns_device_count_on_grouped_alerts(self, client, db):
        """GET /alerts should include device_count for grouped alerts."""
        asyncio.get_event_loop().run_until_complete(seed_grouped_alerts(db, count=1))
        response = client.get("/alerts")
        data = response.json()
        assert data["total"] == 1
        item = data["items"][0]
        assert item["device_count"] == 3
        assert item["issue_key"] == "port_risk:ssh:22"

    def test_list_returns_issue_key_on_grouped_alerts(self, client, db):
        """GET /alerts should include issue_key for grouped alerts."""
        asyncio.get_event_loop().run_until_complete(seed_grouped_alerts(db, count=2))
        response = client.get("/alerts")
        data = response.json()
        issue_keys = {item["issue_key"] for item in data["items"] if item.get("issue_key")}
        assert "port_risk:ssh:22" in issue_keys
        assert "port_risk:telnet:23" in issue_keys

    def test_list_non_grouped_alerts_have_null_issue_key(self, client, db):
        """Non-grouped alerts should have issue_key = None (device_count defaults to 1)."""
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=1))
        response = client.get("/alerts")
        data = response.json()
        item = data["items"][0]
        assert item.get("issue_key") is None

    def test_get_grouped_alert_returns_full_detail(self, client, db):
        """GET /alerts/{id} for a grouped alert should return all grouped fields."""
        alert_ids = asyncio.get_event_loop().run_until_complete(
            seed_grouped_alerts(db, count=1)
        )
        response = client.get(f"/alerts/{alert_ids[0]}")
        assert response.status_code == 200
        data = response.json()

        # Core grouped fields
        assert data["issue_key"] == "port_risk:ssh:22"
        assert data["device_count"] == 3
        assert data["risk_description"] is not None
        assert "default credentials" in data["risk_description"]
        assert data["remediation"] is not None
        assert "Disable SSH" in data["remediation"]

        # Affected devices list
        assert data["affected_devices"] is not None
        assert len(data["affected_devices"]) == 3
        device_ids = {d["device_id"] for d in data["affected_devices"]}
        assert device_ids == {1, 2, 3}
        # Verify device fields
        first_device = data["affected_devices"][0]
        assert "ip_address" in first_device
        assert "mac_address" in first_device
        assert "display_name" in first_device
        assert "port" in first_device

    def test_get_non_grouped_alert_has_null_grouped_fields(self, client, db):
        """GET /alerts/{id} for a non-grouped alert should have null grouped fields."""
        alert_ids = asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=1))
        response = client.get(f"/alerts/{alert_ids[0]}")
        data = response.json()
        assert data.get("issue_key") is None
        assert data.get("affected_devices") is None
        assert data.get("risk_description") is None
        assert data.get("remediation") is None

    def test_mark_grouped_alert_read(self, client, db):
        """PUT /alerts/{id}/read should work on grouped alerts."""
        alert_ids = asyncio.get_event_loop().run_until_complete(
            seed_grouped_alerts(db, count=1)
        )
        response = client.put(f"/alerts/{alert_ids[0]}/read")
        assert response.status_code == 200
        data = response.json()
        assert data["read_at"] is not None

    def test_mark_grouped_alert_actioned(self, client, db):
        """PUT /alerts/{id}/action should work on grouped alerts."""
        alert_ids = asyncio.get_event_loop().run_until_complete(
            seed_grouped_alerts(db, count=1)
        )
        response = client.put(
            f"/alerts/{alert_ids[0]}/action",
            json={"note": "SSH is intentional on these devices"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["actioned_at"] is not None
        assert data["action_note"] == "SSH is intentional on these devices"

    def test_mixed_grouped_and_regular_alerts_in_list(self, client, db):
        """GET /alerts should correctly handle a mix of grouped and regular alerts."""
        asyncio.get_event_loop().run_until_complete(seed_grouped_alerts(db, count=2))
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=2))
        response = client.get("/alerts")
        data = response.json()
        assert data["total"] == 4
        grouped = [i for i in data["items"] if i.get("issue_key") is not None]
        regular = [i for i in data["items"] if i.get("issue_key") is None]
        assert len(grouped) == 2
        assert len(regular) == 2
