"""Group D: alert pipeline.

Covers D-01 through D-05 and D-08 through D-14. D-06 and D-07 live in
test_known_defects.py because they reproduce KD-3.

Asserts the behavior the product should have. A failure is a finding, and gets
written up in qa/FINDINGS.md rather than fixed.
"""

import json

import pytest

from squirrelops_home_sensor.alerts.decoy_handler import DecoyAlertHandler
from squirrelops_home_sensor.db import queries as q


class RecordingBus:
    """Captures publications and hands out monotonic sequences."""

    def __init__(self):
        self.published = []

    async def publish(self, event_type, payload, source_id=None):
        self.published.append((event_type, payload))
        return len(self.published)

    def subscribe(self, event_types, callback):
        pass

    def kinds(self):
        return [event_type for event_type, _ in self.published]


async def seed_decoy(db, *, name="office.local", port=22, ip="192.168.1.212"):
    return await q.insert_decoy(
        db,
        name=name,
        decoy_type="mimic",
        bind_address=ip,
        port=port,
        created_at="2026-08-07T00:00:00Z",
        updated_at="2026-08-07T00:00:00Z",
    )


async def seed_event_seqs(db, count):
    """home_alerts.event_seq references events(seq)."""
    for seq in range(1, count + 1):
        await db.execute(
            "INSERT INTO events (seq, event_type, payload, created_at) "
            "VALUES (?, 'decoy.trip', '{}', '2026-08-07T00:00:00Z')",
            (seq,),
        )
    await db.commit()


async def trip(handler, *, seq, decoy_id, port, source="192.168.1.101", **extra):
    payload = {
        "source_ip": source,
        "dest_port": port,
        "decoy_id": decoy_id,
        "decoy_name": "office.local",
        "timestamp": "2026-08-07T00:00:00.000000Z",
    }
    payload.update(extra)
    await handler._on_decoy_event(
        {"event_type": extra.pop("event_type", "decoy.trip"), "seq": seq, "payload": payload}
    )


async def alerts_in(db):
    cursor = await db.execute("SELECT * FROM home_alerts ORDER BY id")
    return await cursor.fetchall()


class TestD01ForensicRecord:
    @pytest.mark.asyncio
    async def test_trip_writes_one_connection_row_and_increments_counter(self, db):
        bus = RecordingBus()
        h = DecoyAlertHandler(db=db, event_bus=bus, incident_grouper=None)
        decoy_id = await seed_decoy(db)
        await seed_event_seqs(db, 1)

        await trip(h, seq=1, decoy_id=decoy_id, port=22)

        cursor = await db.execute("SELECT COUNT(*) FROM decoy_connections")
        assert (await cursor.fetchone())[0] == 1
        cursor = await db.execute(
            "SELECT connection_count FROM decoys WHERE id = ?", (decoy_id,)
        )
        assert (await cursor.fetchone())[0] == 1


class TestD02FirstTripCreatesOneAlert:
    @pytest.mark.asyncio
    async def test_single_alert_and_alert_new_published(self, db):
        bus = RecordingBus()
        h = DecoyAlertHandler(db=db, event_bus=bus, incident_grouper=None)
        decoy_id = await seed_decoy(db)
        await seed_event_seqs(db, 1)

        await trip(h, seq=1, decoy_id=decoy_id, port=22)

        assert len(await alerts_in(db)) == 1
        assert bus.kinds().count("alert.new") == 1


class TestD03RepeatTripsFold:
    @pytest.mark.asyncio
    async def test_burst_from_one_source_stays_one_alert(self, db):
        bus = RecordingBus()
        h = DecoyAlertHandler(db=db, event_bus=bus, incident_grouper=None)
        decoy_id = await seed_decoy(db)
        await seed_event_seqs(db, 6)

        for seq, port in enumerate((22, 80, 443, 445, 631, 8080), start=1):
            await trip(h, seq=seq, decoy_id=decoy_id, port=port)

        rows = await alerts_in(db)
        assert len(rows) == 1, f"expected one folded alert, got {len(rows)}"
        detail = json.loads(rows[0]["detail"])
        assert detail["connection_count"] == 6

    @pytest.mark.asyncio
    async def test_distinct_sources_get_distinct_alerts(self, db):
        bus = RecordingBus()
        h = DecoyAlertHandler(db=db, event_bus=bus, incident_grouper=None)
        decoy_id = await seed_decoy(db)
        await seed_event_seqs(db, 2)

        await trip(h, seq=1, decoy_id=decoy_id, port=22, source="192.168.1.101")
        await trip(h, seq=2, decoy_id=decoy_id, port=22, source="192.168.1.102")

        assert len(await alerts_in(db)) == 2


class TestD04PortScanPromotion:
    @pytest.mark.asyncio
    async def test_two_endpoints_promote_to_port_scan(self, db):
        bus = RecordingBus()
        h = DecoyAlertHandler(db=db, event_bus=bus, incident_grouper=None)
        decoy_id = await seed_decoy(db)
        await seed_event_seqs(db, 2)

        await trip(h, seq=1, decoy_id=decoy_id, port=22)
        await trip(h, seq=2, decoy_id=decoy_id, port=80)

        row = (await alerts_in(db))[0]
        detail = json.loads(row["detail"])
        assert "Port scan detected" in row["title"]
        assert detail["detection_method"] == "decoy_port_scan"
        assert sorted(detail["ports"]) == [22, 80]

    @pytest.mark.asyncio
    async def test_single_endpoint_is_not_called_a_port_scan(self, db):
        bus = RecordingBus()
        h = DecoyAlertHandler(db=db, event_bus=bus, incident_grouper=None)
        decoy_id = await seed_decoy(db)
        await seed_event_seqs(db, 1)

        await trip(h, seq=1, decoy_id=decoy_id, port=22)

        row = (await alerts_in(db))[0]
        assert "Port scan detected" not in row["title"]


class TestD05DiscoveryProbeIsNotAnAlert:
    @pytest.mark.asyncio
    async def test_ipp_discovery_records_without_alerting(self, db):
        bus = RecordingBus()
        h = DecoyAlertHandler(db=db, event_bus=bus, incident_grouper=None)
        decoy_id = await seed_decoy(db, port=631)
        await seed_event_seqs(db, 1)

        await trip(
            h, seq=1, decoy_id=decoy_id, port=631, request_path="/ipp/print"
        )

        assert len(await alerts_in(db)) == 0, "IPP discovery must not raise an alert"
        cursor = await db.execute("SELECT COUNT(*) FROM decoy_connections")
        assert (await cursor.fetchone())[0] == 1, "but must still be recorded"

    @pytest.mark.asyncio
    async def test_other_path_on_631_still_alerts(self, db):
        bus = RecordingBus()
        h = DecoyAlertHandler(db=db, event_bus=bus, incident_grouper=None)
        decoy_id = await seed_decoy(db, port=631)
        await seed_event_seqs(db, 1)

        await trip(h, seq=1, decoy_id=decoy_id, port=631, request_path="/admin")

        assert len(await alerts_in(db)) == 1


class TestD08ClearingReArms:
    @pytest.mark.asyncio
    async def test_reading_an_alert_lets_the_next_trip_create_a_new_one(self, db):
        bus = RecordingBus()
        h = DecoyAlertHandler(db=db, event_bus=bus, incident_grouper=None)
        decoy_id = await seed_decoy(db)
        await seed_event_seqs(db, 3)

        await trip(h, seq=1, decoy_id=decoy_id, port=22)
        await db.execute(
            "UPDATE home_alerts SET read_at = '2026-08-07T01:00:00Z'"
        )
        await db.commit()
        await trip(h, seq=2, decoy_id=decoy_id, port=80)

        assert len(await alerts_in(db)) == 2
        assert bus.kinds().count("alert.new") == 2


class TestD09CredentialTrip:
    @pytest.mark.asyncio
    async def test_credential_trip_is_critical_and_not_duplicated(self, db):
        bus = RecordingBus()
        h = DecoyAlertHandler(db=db, event_bus=bus, incident_grouper=None)
        decoy_id = await seed_decoy(db)
        await seed_event_seqs(db, 2)

        await trip(
            h,
            seq=1,
            decoy_id=decoy_id,
            port=22,
            credential_used="hunter2",
            event_type="decoy.credential_trip",
        )
        # The paired decoy.trip for the same connection must not add an alert.
        await trip(h, seq=2, decoy_id=decoy_id, port=22, credential_used="hunter2")

        rows = await alerts_in(db)
        assert len(rows) == 1, "credential trip and its paired trip are one event"
        assert rows[0]["severity"] == "critical"


class TestD10IncidentGrouping:
    @pytest.mark.asyncio
    async def test_alerts_from_one_source_share_an_incident(self, db):
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        bus = RecordingBus()
        grouper = IncidentGrouper(db=db, event_bus=bus)
        h = DecoyAlertHandler(db=db, event_bus=bus, incident_grouper=grouper)
        decoy_id = await seed_decoy(db)
        await seed_event_seqs(db, 3)

        await trip(h, seq=1, decoy_id=decoy_id, port=22)
        await db.execute("UPDATE home_alerts SET read_at = '2026-08-07T01:00:00Z'")
        await db.commit()
        await trip(h, seq=2, decoy_id=decoy_id, port=80)

        rows = await alerts_in(db)
        incident_ids = {row["incident_id"] for row in rows}
        assert len(rows) == 2
        assert None not in incident_ids, "both alerts should be grouped"
        assert len(incident_ids) == 1, "same source IP belongs to one incident"


class TestD13SlackFormatting:
    def test_block_kit_payload_shape(self):
        from squirrelops_home_sensor.alerts.dispatcher import format_slack_payload

        payload = format_slack_payload(
            {
                "severity": "high",
                "title": "Port scan detected from 192.168.1.101",
                "detail": "6 connections across 6 decoy services",
                "source_ip": "192.168.1.101",
                "created_at": "2026-08-07T00:00:00Z",
                "alert_type": "decoy.trip",
            }
        )
        assert payload["text"].startswith(("\U0001f7e0", "\U0001f534", "⚠", "\U0001f7e1"))
        assert payload["blocks"][0]["type"] == "header"
        assert any("192.168.1.101" in json.dumps(b) for b in payload["blocks"])

    def test_device_identifiers_are_opt_in(self):
        from squirrelops_home_sensor.alerts.dispatcher import format_slack_payload

        alert = {
            "severity": "high",
            "title": "t",
            "detail": "d",
            "source_ip": "192.168.1.101",
            "source_mac": "AE:29:0A:E5:CC:C5",
            "device_id": 21,
            "created_at": "2026-08-07T00:00:00Z",
            "alert_type": "decoy.trip",
        }
        without = json.dumps(format_slack_payload(alert))
        with_info = json.dumps(format_slack_payload(alert, include_device_info=True))
        assert "AE:29:0A:E5:CC:C5" not in without
        assert "AE:29:0A:E5:CC:C5" in with_info


class TestD14DeliveryFailureKeepsEvidence:
    @pytest.mark.asyncio
    async def test_alert_failure_does_not_discard_the_connection_record(self, db):
        bus = RecordingBus()
        h = DecoyAlertHandler(db=db, event_bus=bus, incident_grouper=None)
        decoy_id = await seed_decoy(db)
        await seed_event_seqs(db, 1)

        # No events row for seq 99, so alert creation fails on its FK while the
        # forensic write must still land.
        await trip(h, seq=99, decoy_id=decoy_id, port=22)

        cursor = await db.execute("SELECT COUNT(*) FROM decoy_connections")
        assert (await cursor.fetchone())[0] == 1, (
            "evidence must survive an alerting failure"
        )


class TestD15UpdatedAlertDelivery:
    """The DEF-002 fix: deliver material updates without notifying on every hit.

    These pin a behavior decision, not just a code path. If the rule changes,
    these should change with it deliberately.
    """

    @staticmethod
    def _dispatcher(cooldown=300.0):
        from squirrelops_home_sensor.alerts.dispatcher import AlertDispatcher

        delivered = []

        async def handler(payload):
            delivered.append(payload)

        dispatcher = AlertDispatcher(
            methods=[{"name": "test", "handler": handler, "min_severity": "low"}],
            renotify_cooldown=cooldown,
        )
        return dispatcher, delivered

    @staticmethod
    def _alert(**overrides):
        payload = {
            "id": 1,
            "alert_type": "decoy.trip",
            "severity": "high",
            "title": "1 decoy connection from 192.168.1.101",
            "source_ip": "192.168.1.101",
            "created_at": "2026-08-07T00:00:00Z",
        }
        payload.update(overrides)
        return payload

    @pytest.mark.asyncio
    async def test_a_repeat_hit_with_an_unchanged_summary_is_not_delivered(self):
        dispatcher, delivered = self._dispatcher()
        await dispatcher.dispatch(self._alert())
        for _ in range(50):
            await dispatcher._on_alert_updated({"payload": self._alert()})

        assert len(delivered) == 1, (
            "a scan burst must not produce one notification per connection"
        )

    @pytest.mark.asyncio
    async def test_a_promoted_title_is_delivered(self):
        dispatcher, delivered = self._dispatcher()
        await dispatcher.dispatch(self._alert())

        # The moment a second endpoint is touched the title promotes, which is
        # the moment the character of the event changed.
        await dispatcher._on_alert_updated(
            {"payload": self._alert(title="Port scan detected from 192.168.1.101")}
        )

        assert len(delivered) == 2
        assert "Port scan detected" in delivered[-1]["title"]

    @pytest.mark.asyncio
    async def test_an_escalated_severity_is_delivered(self):
        dispatcher, delivered = self._dispatcher()
        await dispatcher.dispatch(self._alert(severity="medium"))
        await dispatcher._on_alert_updated({"payload": self._alert(severity="critical")})

        assert len(delivered) == 2
        assert delivered[-1]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_a_second_material_change_inside_the_cooldown_is_held(self):
        dispatcher, delivered = self._dispatcher(cooldown=3600.0)
        await dispatcher.dispatch(self._alert())
        await dispatcher._on_alert_updated({"payload": self._alert(title="a")})
        await dispatcher._on_alert_updated({"payload": self._alert(title="b")})

        assert len(delivered) == 2, "the cooldown bounds re-notification"

    @pytest.mark.asyncio
    async def test_a_material_change_after_the_cooldown_is_delivered(self):
        dispatcher, delivered = self._dispatcher(cooldown=0.0)
        await dispatcher.dispatch(self._alert())
        await dispatcher._on_alert_updated({"payload": self._alert(title="a")})
        await dispatcher._on_alert_updated({"payload": self._alert(title="b")})

        assert len(delivered) == 3

    @pytest.mark.asyncio
    async def test_distinct_alerts_do_not_share_a_cooldown(self):
        dispatcher, delivered = self._dispatcher(cooldown=3600.0)
        await dispatcher.dispatch(self._alert(id=1))
        await dispatcher.dispatch(self._alert(id=2))
        await dispatcher._on_alert_updated({"payload": self._alert(id=1, title="x")})
        await dispatcher._on_alert_updated({"payload": self._alert(id=2, title="y")})

        assert len(delivered) == 4

    @pytest.mark.asyncio
    async def test_min_severity_still_applies_to_an_update(self):
        from squirrelops_home_sensor.alerts.dispatcher import AlertDispatcher

        delivered = []

        async def handler(payload):
            delivered.append(payload)

        dispatcher = AlertDispatcher(
            methods=[{"name": "test", "handler": handler, "min_severity": "critical"}]
        )
        await dispatcher._on_alert_updated({"payload": self._alert(severity="low")})

        assert delivered == [], "an update must respect the severity threshold"

    @pytest.mark.asyncio
    async def test_an_auto_resolved_alert_is_not_delivered(self):
        dispatcher, delivered = self._dispatcher()
        await dispatcher.dispatch(self._alert())

        await dispatcher._on_alert_updated({
            "payload": self._alert(
                title="Resolved: ARP identity claims are no longer ambiguous",
                read_at="2026-08-10T12:00:00Z",
                actioned_at="2026-08-10T12:00:00Z",
                detail={"resolved_at": "2026-08-10T12:00:00Z"},
            )
        })

        assert len(delivered) == 1, "resolution must not page the user"

    @pytest.mark.asyncio
    async def test_a_dismissed_group_update_is_not_delivered(self):
        dispatcher, delivered = self._dispatcher()
        await dispatcher.dispatch(self._alert())

        await dispatcher._on_alert_updated({
            "payload": self._alert(
                title="Risky service now affects 2 devices",
                read_at="2026-08-10T12:00:00Z",
            )
        })

        assert len(delivered) == 1, "a dismissed alert must stay quiet"

    @pytest.mark.asyncio
    async def test_reactivation_starts_a_fresh_notification_episode(self):
        dispatcher, delivered = self._dispatcher()
        await dispatcher.dispatch(self._alert())
        await dispatcher._on_alert_updated({
            "payload": self._alert(read_at="2026-08-10T12:00:00Z")
        })

        # Grouped alerts can reactivate the same row by clearing lifecycle
        # timestamps. Even an unchanged title and severity must notify again.
        await dispatcher._on_alert_updated({"payload": self._alert(read_at=None)})

        assert len(delivered) == 2

    @pytest.mark.asyncio
    async def test_notification_baselines_are_bounded(self):
        from squirrelops_home_sensor.alerts.dispatcher import AlertDispatcher

        delivered = []

        async def handler(payload):
            delivered.append(payload)

        dispatcher = AlertDispatcher(
            methods=[{"name": "test", "handler": handler, "min_severity": "low"}],
            max_tracked_alerts=2,
        )
        await dispatcher.dispatch(self._alert(id=1))
        await dispatcher.dispatch(self._alert(id=2))
        await dispatcher.dispatch(self._alert(id=3))

        assert list(dispatcher._notified_summaries) == [2, 3]
