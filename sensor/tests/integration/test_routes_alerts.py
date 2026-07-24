"""Integration tests for alert routes: list, get, incident detail, mark read/actioned, export."""
import asyncio
import json
import sqlite3
import stat
from pathlib import Path

import aiosqlite
import pytest

from squirrelops_home_sensor.alerts.decoy_handler import DecoyAlertHandler
from squirrelops_home_sensor.alerts.history import clear_alert_history
from squirrelops_home_sensor.alerts.incidents import IncidentGrouper
from squirrelops_home_sensor.db.schema import create_all_tables
from squirrelops_home_sensor.events.bus import EventBus
from squirrelops_home_sensor.events.log import EventLog
from squirrelops_home_sensor.security.analyzer import SecurityInsightAnalyzer
from tests.integration.conftest import (
    seed_alerts,
    seed_decoys,
    seed_grouped_alerts,
    seed_incidents,
)


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


class TestDeleteAlertHistory:
    """DELETE /alerts -- backed-up destructive removal of alert history."""

    def test_requires_exact_confirmation(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_alerts(db, count=1))

        response = client.request(
            "DELETE",
            "/alerts",
            json={"confirmation": "yes"},
        )

        assert response.status_code == 422
        remaining = asyncio.get_event_loop().run_until_complete(
            db.execute("SELECT COUNT(*) FROM home_alerts")
        )
        assert asyncio.get_event_loop().run_until_complete(remaining.fetchone())[0] == 1

    def test_backs_up_and_clears_alert_history(
        self, client, db, sensor_config,
    ):
        loop = asyncio.get_event_loop()
        standalone_ids = loop.run_until_complete(seed_alerts(db, count=2))
        _incident_id, incident_alert_ids = loop.run_until_complete(seed_incidents(db))
        loop.run_until_complete(
            db.executemany(
                "INSERT INTO events (event_type, payload) VALUES (?, '{}')",
                [
                    ("alert.new",),
                    ("alert.updated",),
                    ("incident.new",),
                    ("incident.updated",),
                    ("device.updated",),
                ],
            )
        )
        decoy_id = loop.run_until_complete(seed_decoys(db, count=1))[0]
        event_cursor = loop.run_until_complete(
            db.execute(
                "SELECT seq FROM events WHERE event_type = 'alert.new' LIMIT 1"
            )
        )
        alert_event_seq = loop.run_until_complete(event_cursor.fetchone())[0]
        loop.run_until_complete(
            db.execute(
                """INSERT INTO decoy_connections
                   (decoy_id, source_ip, port, event_seq, timestamp)
                   VALUES (?, '192.168.1.50', 80, ?, '2026-02-22T00:00:00Z')""",
                (decoy_id, alert_event_seq),
            )
        )
        loop.run_until_complete(
            db.execute(
                """INSERT OR IGNORE INTO devices
                   (id, ip_address, device_type, first_seen, last_seen)
                   VALUES (1, '192.168.1.10', 'unknown',
                           '2026-02-22T00:00:00Z', '2026-02-22T00:00:00Z')"""
            )
        )
        loop.run_until_complete(
            db.execute(
                """INSERT INTO security_insight_state
                   (device_id, insight_key, alert_id, created_at)
                   VALUES (1, 'port_risk:ssh:22', ?, '2026-02-22T00:00:00Z')""",
                (standalone_ids[0],),
            )
        )
        loop.run_until_complete(db.commit())

        response = client.request(
            "DELETE",
            "/alerts",
            json={"confirmation": "DELETE ALL ALERTS"},
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["alerts_deleted"] == len(standalone_ids) + len(incident_alert_ids)
        assert payload["incidents_deleted"] == 1
        assert payload["replay_events_deleted"] == 4

        for table in ("home_alerts", "incidents"):
            cursor = loop.run_until_complete(db.execute(f"SELECT COUNT(*) FROM {table}"))
            assert loop.run_until_complete(cursor.fetchone())[0] == 0

        cursor = loop.run_until_complete(
            db.execute("SELECT event_type FROM events ORDER BY seq")
        )
        assert [row[0] for row in loop.run_until_complete(cursor.fetchall())] == [
            "device.updated",
            "alerts.history_cleared",
        ]

        cursor = loop.run_until_complete(
            db.execute("SELECT event_seq FROM decoy_connections")
        )
        assert loop.run_until_complete(cursor.fetchone())[0] is None

        cursor = loop.run_until_complete(
            db.execute("SELECT alert_id FROM security_insight_state")
        )
        assert loop.run_until_complete(cursor.fetchone())[0] is None

        backup_path = (
            Path(sensor_config["sensor"]["data_dir"])
            / "backups"
            / payload["backup_file"]
        )
        assert backup_path.is_file()
        assert stat.S_IMODE(backup_path.stat().st_mode) == 0o600
        with sqlite3.connect(backup_path) as backup:
            assert backup.execute("PRAGMA quick_check").fetchone()[0] == "ok"
            assert backup.execute("SELECT COUNT(*) FROM home_alerts").fetchone()[0] == 5
            assert backup.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1

    @pytest.mark.asyncio
    async def test_file_clear_waits_for_pending_writer_without_deadlock(
        self,
        tmp_path: Path,
    ):
        database_path = tmp_path / "sensor.sqlite3"
        db = await aiosqlite.connect(database_path)
        db.row_factory = aiosqlite.Row
        await create_all_tables(db)
        try:
            await db.execute(
                """INSERT INTO home_alerts
                   (alert_type, severity, title, detail, created_at)
                   VALUES ('test', 'low', 'Old', '{}', '2026-01-01T00:00:00Z')"""
            )
            await db.commit()

            writer_started = asyncio.Event()

            async def pending_writer() -> None:
                await db.execute(
                    "INSERT INTO events (event_type, payload) "
                    "VALUES ('device.updated', '{}')"
                )
                writer_started.set()
                await asyncio.sleep(0.05)
                await db.commit()

            writer = asyncio.create_task(pending_writer())
            await writer_started.wait()
            result = await asyncio.wait_for(
                clear_alert_history(db, backup_dir=tmp_path / "backups"),
                timeout=5,
            )
            await writer

            assert result.alerts_deleted == 1
            assert (tmp_path / "backups" / result.backup_file).is_file()
        finally:
            await db.close()

    @pytest.mark.asyncio
    async def test_publish_after_clear_drops_deleted_alert_event(
        self,
        tmp_path: Path,
    ):
        database_path = tmp_path / "sensor.sqlite3"
        db = await aiosqlite.connect(database_path)
        db.row_factory = aiosqlite.Row
        await create_all_tables(db)
        bus = EventBus(EventLog(db))
        received: list[str] = []

        async def receive(event: dict) -> None:
            received.append(event["event_type"])

        bus.subscribe(["*"], receive)
        try:
            cursor = await db.execute(
                """INSERT INTO home_alerts
                   (alert_type, severity, title, detail, created_at)
                   VALUES ('test', 'low', 'Old', '{}', '2026-01-01T00:00:00Z')"""
            )
            await db.commit()
            alert_id = cursor.lastrowid
            assert alert_id is not None

            async with bus.serialized():
                delayed_publish = asyncio.create_task(
                    bus.publish(
                        "alert.new",
                        {
                            "id": alert_id,
                            "alert_type": "test",
                            "severity": "low",
                            "title": "Old",
                            "created_at": "2026-01-01T00:00:00Z",
                        },
                    )
                )
                await asyncio.sleep(0)
                result = await clear_alert_history(
                    db,
                    backup_dir=tmp_path / "backups",
                )
                await bus.broadcast_persisted(
                    seq=result.event_seq,
                    event_type="alerts.history_cleared",
                    payload={"alerts_deleted": result.alerts_deleted},
                )

            assert await delayed_publish == 0
            await asyncio.sleep(0)
            assert received == ["alerts.history_cleared"]
        finally:
            await db.close()

    @pytest.mark.asyncio
    async def test_clear_waits_until_grouped_alert_state_is_bound(
        self,
        tmp_path: Path,
    ):
        """A clear cannot land between a grouped alert commit and state binding."""
        database_path = tmp_path / "sensor.sqlite3"
        db = await aiosqlite.connect(database_path)
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA foreign_keys = ON")
        await create_all_tables(db)
        bus = EventBus(EventLog(db))
        alert_committed = asyncio.Event()
        release_analyzer = asyncio.Event()
        clear_entered = asyncio.Event()

        class PausingAnalyzer(SecurityInsightAnalyzer):
            async def _create_grouped_alert(self, *args, **kwargs):
                alert_id = await super()._create_grouped_alert(*args, **kwargs)
                alert_committed.set()
                await release_analyzer.wait()
                return alert_id

        analyzer = PausingAnalyzer(db=db, event_bus=bus)
        await db.execute(
            """INSERT INTO devices
               (id, ip_address, mac_address, hostname, device_type,
                first_seen, last_seen)
               VALUES (1, '192.168.1.10', 'AA:BB:CC:DD:EE:FF', 'camera',
                       'camera', '2026-01-01T00:00:00Z',
                       '2026-01-01T00:00:00Z')"""
        )
        await db.commit()

        analyze_task = asyncio.create_task(
            analyzer.analyze_all_devices(
                [
                    {
                        "device_id": 1,
                        "ip_address": "192.168.1.10",
                        "mac_address": "AA:BB:CC:DD:EE:FF",
                        "device_type": "camera",
                        "open_ports": frozenset({23}),
                        "display_name": "Camera",
                    }
                ]
            )
        )
        clear_task: asyncio.Task | None = None

        try:
            await asyncio.wait_for(alert_committed.wait(), timeout=1)

            async def clear_during_creation():
                async with bus.serialized():
                    clear_entered.set()
                    result = await clear_alert_history(
                        db,
                        backup_dir=tmp_path / "backups",
                    )
                    await bus.broadcast_persisted(
                        seq=result.event_seq,
                        event_type="alerts.history_cleared",
                        payload={"alerts_deleted": result.alerts_deleted},
                    )
                    return result

            clear_task = asyncio.create_task(clear_during_creation())
            for _ in range(10):
                await asyncio.sleep(0)

            assert not clear_entered.is_set()

            release_analyzer.set()
            assert await asyncio.wait_for(analyze_task, timeout=1) == 1
            result = await asyncio.wait_for(clear_task, timeout=5)
            assert result.alerts_deleted == 1

            cursor = await db.execute("SELECT COUNT(*) FROM home_alerts")
            assert (await cursor.fetchone())[0] == 0
            cursor = await db.execute(
                """SELECT alert_id, resolved_at
                   FROM security_insight_state
                   WHERE device_id = 1 AND insight_key = 'risky_port:23'"""
            )
            state = await cursor.fetchone()
            assert state is not None
            assert state["alert_id"] is None
            assert state["resolved_at"] is None
        finally:
            release_analyzer.set()
            await asyncio.gather(analyze_task, return_exceptions=True)
            if clear_task is not None:
                await asyncio.gather(clear_task, return_exceptions=True)
            await db.close()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("mutation", ["added_device", "ip_refresh"])
    async def test_clear_waits_for_existing_group_update_transaction(
        self,
        tmp_path: Path,
        mutation: str,
    ):
        """Clear cannot split an existing alert update from its state bindings."""
        database_path = tmp_path / "sensor.sqlite3"
        db = await aiosqlite.connect(database_path)
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA foreign_keys = ON")
        await create_all_tables(db)
        bus = EventBus(EventLog(db))
        mutation_written = asyncio.Event()
        release_analyzer = asyncio.Event()
        clear_entered = asyncio.Event()

        class PausingAnalyzer(SecurityInsightAnalyzer):
            async def _update_grouped_alert(self, *args, **kwargs):
                result = await super()._update_grouped_alert(*args, **kwargs)
                mutation_written.set()
                await release_analyzer.wait()
                return result

        await db.executemany(
            """INSERT INTO devices
               (id, ip_address, mac_address, hostname, device_type,
                first_seen, last_seen)
               VALUES (?, ?, ?, ?, 'smart_speaker',
                       '2026-01-01T00:00:00Z',
                       '2026-01-01T00:00:00Z')""",
            [
                (1, "192.168.1.10", "AA:BB:CC:DD:EE:01", "speaker-1"),
                (2, "192.168.1.11", "AA:BB:CC:DD:EE:02", "speaker-2"),
            ],
        )
        await db.commit()
        initial_device = {
            "device_id": 1,
            "ip_address": "192.168.1.10",
            "mac_address": "AA:BB:CC:DD:EE:01",
            "device_type": "smart_speaker",
            "open_ports": frozenset({23}),
            "display_name": "Speaker 1",
        }
        await SecurityInsightAnalyzer(db=db, event_bus=bus).analyze_all_devices(
            [initial_device]
        )

        if mutation == "added_device":
            next_devices = [
                initial_device,
                {
                    "device_id": 2,
                    "ip_address": "192.168.1.11",
                    "mac_address": "AA:BB:CC:DD:EE:02",
                    "device_type": "smart_speaker",
                    "open_ports": frozenset({23}),
                    "display_name": "Speaker 2",
                },
            ]
        else:
            next_devices = [
                {**initial_device, "ip_address": "192.168.1.99"}
            ]

        analyze_task = asyncio.create_task(
            PausingAnalyzer(db=db, event_bus=bus).analyze_all_devices(
                next_devices
            )
        )
        clear_task: asyncio.Task | None = None

        try:
            await asyncio.wait_for(mutation_written.wait(), timeout=1)

            async def clear_during_update():
                async with bus.serialized():
                    clear_entered.set()
                    result = await clear_alert_history(
                        db,
                        backup_dir=tmp_path / "backups",
                    )
                    await bus.broadcast_persisted(
                        seq=result.event_seq,
                        event_type="alerts.history_cleared",
                        payload={"alerts_deleted": result.alerts_deleted},
                    )
                    return result

            clear_task = asyncio.create_task(clear_during_update())
            for _ in range(10):
                await asyncio.sleep(0)

            assert not clear_entered.is_set()

            release_analyzer.set()
            assert await asyncio.wait_for(analyze_task, timeout=1) == 0
            result = await asyncio.wait_for(clear_task, timeout=5)
            assert result.alerts_deleted == 1

            cursor = await db.execute("SELECT COUNT(*) FROM home_alerts")
            assert (await cursor.fetchone())[0] == 0
            cursor = await db.execute(
                """SELECT device_id, alert_id, resolved_at
                   FROM security_insight_state
                   ORDER BY device_id"""
            )
            states = [tuple(row) for row in await cursor.fetchall()]
            expected_device_ids = (
                [1, 2] if mutation == "added_device" else [1]
            )
            assert states == [
                (device_id, None, None)
                for device_id in expected_device_ids
            ]
            cursor = await db.execute(
                "SELECT event_type FROM events ORDER BY seq"
            )
            assert [row[0] for row in await cursor.fetchall()] == [
                "alerts.history_cleared"
            ]
        finally:
            release_analyzer.set()
            await asyncio.gather(analyze_task, return_exceptions=True)
            if clear_task is not None:
                await asyncio.gather(clear_task, return_exceptions=True)
            await db.close()

    @pytest.mark.asyncio
    async def test_clear_waits_for_prune_and_resolution_transaction(
        self,
        tmp_path: Path,
    ):
        """Pruning an alert and resolving its state are atomic against clear."""
        database_path = tmp_path / "sensor.sqlite3"
        db = await aiosqlite.connect(database_path)
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA foreign_keys = ON")
        await create_all_tables(db)
        bus = EventBus(EventLog(db))
        prune_written = asyncio.Event()
        release_analyzer = asyncio.Event()
        clear_entered = asyncio.Event()

        class PausingAnalyzer(SecurityInsightAnalyzer):
            async def _prune_removed_devices(self, *args, **kwargs):
                result = await super()._prune_removed_devices(*args, **kwargs)
                prune_written.set()
                await release_analyzer.wait()
                return result

        await db.executemany(
            """INSERT INTO devices
               (id, ip_address, mac_address, hostname, device_type,
                first_seen, last_seen)
               VALUES (?, ?, ?, ?, 'smart_speaker',
                       '2026-01-01T00:00:00Z',
                       '2026-01-01T00:00:00Z')""",
            [
                (1, "192.168.1.10", "AA:BB:CC:DD:EE:01", "speaker-1"),
                (2, "192.168.1.11", "AA:BB:CC:DD:EE:02", "speaker-2"),
            ],
        )
        await db.commit()
        active_devices = [
            {
                "device_id": device_id,
                "ip_address": f"192.168.1.{9 + device_id}",
                "mac_address": f"AA:BB:CC:DD:EE:0{device_id}",
                "device_type": "smart_speaker",
                "open_ports": frozenset({21}),
                "display_name": f"Speaker {device_id}",
            }
            for device_id in (1, 2)
        ]
        await SecurityInsightAnalyzer(db=db, event_bus=bus).analyze_all_devices(
            active_devices
        )
        next_devices = [
            active_devices[0],
            {**active_devices[1], "open_ports": frozenset()},
        ]
        analyze_task = asyncio.create_task(
            PausingAnalyzer(db=db, event_bus=bus).analyze_all_devices(
                next_devices
            )
        )
        clear_task: asyncio.Task | None = None

        try:
            await asyncio.wait_for(prune_written.wait(), timeout=1)

            async def clear_during_prune():
                async with bus.serialized():
                    clear_entered.set()
                    result = await clear_alert_history(
                        db,
                        backup_dir=tmp_path / "backups",
                    )
                    await bus.broadcast_persisted(
                        seq=result.event_seq,
                        event_type="alerts.history_cleared",
                        payload={"alerts_deleted": result.alerts_deleted},
                    )
                    return result

            clear_task = asyncio.create_task(clear_during_prune())
            for _ in range(10):
                await asyncio.sleep(0)

            assert not clear_entered.is_set()

            release_analyzer.set()
            assert await asyncio.wait_for(analyze_task, timeout=1) == 0
            result = await asyncio.wait_for(clear_task, timeout=5)
            assert result.alerts_deleted == 1

            cursor = await db.execute(
                """SELECT device_id, alert_id, resolved_at
                   FROM security_insight_state
                   ORDER BY device_id"""
            )
            states = list(await cursor.fetchall())
            assert tuple(states[0]) == (1, None, None)
            assert states[1]["device_id"] == 2
            assert states[1]["alert_id"] is None
            assert states[1]["resolved_at"] is not None
        finally:
            release_analyzer.set()
            await asyncio.gather(analyze_task, return_exceptions=True)
            if clear_task is not None:
                await asyncio.gather(clear_task, return_exceptions=True)
            await db.close()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("file_backed", [False, True])
    async def test_clear_backfills_missing_port_risk_tombstones(
        self,
        tmp_path: Path,
        file_backed: bool,
    ):
        """Legacy grouped alerts stay cleared even when insight state is incomplete."""
        database_target: str | Path = (
            tmp_path / "sensor.sqlite3" if file_backed else ":memory:"
        )
        db = await aiosqlite.connect(database_target)
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA foreign_keys = ON")
        await create_all_tables(db)
        bus = EventBus(EventLog(db))
        affected = [
            {
                "device_id": 1,
                "ip_address": "192.168.1.10",
                "mac_address": "AA:BB:CC:DD:EE:01",
                "display_name": "Camera",
                "port": 23,
            },
            {
                "device_id": 2,
                "ip_address": "192.168.1.11",
                "mac_address": "AA:BB:CC:DD:EE:02",
                "display_name": "Speaker",
                "port": 23,
            },
        ]
        devices = [
            {
                "device_id": item["device_id"],
                "ip_address": item["ip_address"],
                "mac_address": item["mac_address"],
                "device_type": "smart_speaker",
                "open_ports": frozenset({23}),
                "display_name": item["display_name"],
            }
            for item in affected
        ]

        try:
            await db.executemany(
                """INSERT INTO devices
                   (id, ip_address, mac_address, hostname, device_type,
                    first_seen, last_seen)
                   VALUES (?, ?, ?, ?, 'smart_speaker',
                           '2026-01-01T00:00:00Z',
                           '2026-01-01T00:00:00Z')""",
                [
                    (1, "192.168.1.10", "AA:BB:CC:DD:EE:01", "camera"),
                    (2, "192.168.1.11", "AA:BB:CC:DD:EE:02", "speaker"),
                ],
            )
            alert = await db.execute(
                """INSERT INTO home_alerts
                   (alert_type, severity, title, detail, issue_key,
                    affected_devices, device_count, created_at)
                   VALUES ('security.port_risk', 'high',
                           'Telnet open on 2 devices', ?,
                           'port_risk:telnet:23', ?, 2,
                           '2026-01-01T00:00:00Z')""",
                (
                    json.dumps({"port": 23, "service_name": "Telnet"}),
                    json.dumps(affected),
                ),
            )
            assert alert.lastrowid is not None
            # Reproduce a legacy/incomplete database: only one affected device
            # has the analyzer's current per-port state row.
            await db.execute(
                """INSERT INTO security_insight_state
                   (device_id, insight_key, alert_id, created_at)
                   VALUES (1, 'risky_port:23', ?,
                           '2026-01-01T00:00:00Z')""",
                (alert.lastrowid,),
            )
            await db.commit()

            result = await clear_alert_history(
                db,
                backup_dir=tmp_path / "backups",
            )
            assert result.alerts_deleted == 1
            with sqlite3.connect(
                tmp_path / "backups" / result.backup_file
            ) as backup:
                assert backup.execute(
                    "SELECT COUNT(*) FROM home_alerts"
                ).fetchone()[0] == 1
                assert backup.execute(
                    "SELECT device_id, insight_key "
                    "FROM security_insight_state ORDER BY device_id"
                ).fetchall() == [(1, "risky_port:23")]

            cursor = await db.execute(
                """SELECT device_id, insight_key, alert_id, resolved_at
                   FROM security_insight_state
                   ORDER BY device_id, insight_key"""
            )
            assert [tuple(row) for row in await cursor.fetchall()] == [
                (1, "risky_port:23", None, None),
                (2, "risky_port:23", None, None),
            ]

            analyzer = SecurityInsightAnalyzer(db=db, event_bus=bus)
            assert await analyzer.analyze_all_devices(devices) == 0
            cursor = await db.execute("SELECT COUNT(*) FROM home_alerts")
            assert (await cursor.fetchone())[0] == 0

            # Once the finding genuinely resolves and recurs, it is new again.
            resolved_devices = [
                {**device, "open_ports": frozenset()} for device in devices
            ]
            await analyzer.analyze_all_devices(resolved_devices)
            assert await analyzer.analyze_all_devices(devices) == 1
            cursor = await db.execute(
                """SELECT issue_key
                   FROM home_alerts
                   WHERE alert_type = 'security.port_risk'"""
            )
            assert [row[0] for row in await cursor.fetchall()] == [
                "port_risk:telnet:23"
            ]
        finally:
            await db.close()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("file_backed", [False, True])
    async def test_clear_tolerates_pathological_legacy_port_risk_json(
        self,
        tmp_path: Path,
        file_backed: bool,
    ):
        """Malformed legacy JSON cannot make alert history impossible to clear."""
        database_target: str | Path = (
            tmp_path / "sensor.sqlite3" if file_backed else ":memory:"
        )
        db = await aiosqlite.connect(database_target)
        db.row_factory = aiosqlite.Row
        await create_all_tables(db)
        oversized_json_integer = "9" * 5000

        try:
            await db.execute(
                """INSERT INTO home_alerts
                   (alert_type, severity, title, detail, issue_key,
                    affected_devices, device_count, created_at)
                   VALUES ('security.port_risk', 'high',
                           'Malformed legacy alert', ?, ?, ?, 1,
                           '2026-01-01T00:00:00Z')""",
                (
                    oversized_json_integer,
                    f"port_risk:legacy:{oversized_json_integer}",
                    oversized_json_integer,
                ),
            )
            await db.commit()

            result = await clear_alert_history(
                db,
                backup_dir=tmp_path / "backups",
            )

            assert result.alerts_deleted == 1
            cursor = await db.execute("SELECT COUNT(*) FROM home_alerts")
            assert (await cursor.fetchone())[0] == 0
        finally:
            await db.close()

    @pytest.mark.asyncio
    async def test_clear_rejects_delayed_pre_clear_decoy_callback(
        self,
        tmp_path: Path,
    ):
        """A queued pre-clear trip cannot recreate an alert after the purge."""
        database_path = tmp_path / "sensor.sqlite3"
        db = await aiosqlite.connect(database_path)
        db.row_factory = aiosqlite.Row
        await create_all_tables(db)
        bus = EventBus(EventLog(db))
        first_started = asyncio.Event()
        release_first = asyncio.Event()
        first_finished = asyncio.Event()
        second_finished = asyncio.Event()

        class DelayedDecoyAlertHandler(DecoyAlertHandler):
            invocations = 0

            async def _on_decoy_event(self, event: dict) -> None:
                self.invocations += 1
                invocation = self.invocations
                if invocation == 1:
                    first_started.set()
                    await release_first.wait()
                try:
                    await super()._on_decoy_event(event)
                finally:
                    if invocation == 1:
                        first_finished.set()
                    else:
                        second_finished.set()

        handler = DelayedDecoyAlertHandler(
            db=db,
            event_bus=bus,
            incident_grouper=None,
        )
        handler.subscribe_to(bus)

        try:
            await db.execute(
                """INSERT INTO home_alerts
                   (alert_type, severity, title, detail, created_at)
                   VALUES ('test', 'low', 'Old', '{}',
                           '2026-01-01T00:00:00Z')"""
            )
            await db.commit()

            await bus.publish(
                "decoy.trip",
                {
                    "source_ip": "192.168.1.50",
                    "dest_port": 8080,
                    "protocol": "tcp",
                },
            )
            await asyncio.wait_for(first_started.wait(), timeout=1)

            async with bus.serialized():
                result = await clear_alert_history(
                    db,
                    backup_dir=tmp_path / "backups",
                )
                await bus.broadcast_persisted(
                    seq=result.event_seq,
                    event_type="alerts.history_cleared",
                    payload={"alerts_deleted": result.alerts_deleted},
                )

            release_first.set()
            await asyncio.wait_for(first_finished.wait(), timeout=1)

            cursor = await db.execute("SELECT COUNT(*) FROM home_alerts")
            alert_count = await cursor.fetchone()
            assert alert_count is not None
            assert alert_count[0] == 0
            cursor = await db.execute(
                "SELECT COUNT(*) FROM events WHERE event_type = 'alert.new'"
            )
            event_count = await cursor.fetchone()
            assert event_count is not None
            assert event_count[0] == 0

            # A trip published after the clear marker remains a real alert.
            await bus.publish(
                "decoy.trip",
                {
                    "source_ip": "192.168.1.51",
                    "dest_port": 8080,
                    "protocol": "tcp",
                },
            )
            await asyncio.wait_for(second_finished.wait(), timeout=1)

            cursor = await db.execute(
                "SELECT source_ip FROM home_alerts ORDER BY id"
            )
            assert [row[0] for row in await cursor.fetchall()] == [
                "192.168.1.51"
            ]
            cursor = await db.execute(
                "SELECT seq FROM events WHERE event_type = 'alert.new'"
            )
            alert_event = await cursor.fetchone()
            assert alert_event is not None
            assert alert_event[0] > result.event_seq
        finally:
            release_first.set()
            await db.close()

    @pytest.mark.asyncio
    async def test_clear_rejects_delayed_pre_clear_incident_grouping(
        self,
        tmp_path: Path,
    ):
        """A grouper holding a deleted alert cannot recreate its incident."""
        database_path = tmp_path / "sensor.sqlite3"
        db = await aiosqlite.connect(database_path)
        db.row_factory = aiosqlite.Row
        await create_all_tables(db)
        bus = EventBus(EventLog(db))
        first_fetched = asyncio.Event()
        release_first = asyncio.Event()
        first_finished = asyncio.Event()
        second_finished = asyncio.Event()

        class DelayedIncidentGrouper(IncidentGrouper):
            invocations = 0

            async def _find_active_incident(
                self,
                source_ip: str,
                alert_time,
            ):
                self.invocations += 1
                if self.invocations == 1:
                    first_fetched.set()
                    await release_first.wait()
                return await super()._find_active_incident(
                    source_ip,
                    alert_time,
                )

        class TrackingDecoyAlertHandler(DecoyAlertHandler):
            invocations = 0

            async def _on_decoy_event(self, event: dict) -> None:
                self.invocations += 1
                invocation = self.invocations
                try:
                    await super()._on_decoy_event(event)
                finally:
                    if invocation == 1:
                        first_finished.set()
                    else:
                        second_finished.set()

        grouper = DelayedIncidentGrouper(db=db, event_bus=bus)
        handler = TrackingDecoyAlertHandler(
            db=db,
            event_bus=bus,
            incident_grouper=grouper,
        )
        handler.subscribe_to(bus)

        try:
            await bus.publish(
                "decoy.trip",
                {
                    "source_ip": "192.168.1.60",
                    "dest_port": 8080,
                    "protocol": "tcp",
                },
            )
            await asyncio.wait_for(first_fetched.wait(), timeout=1)

            async with bus.serialized():
                result = await clear_alert_history(
                    db,
                    backup_dir=tmp_path / "backups",
                )
                await bus.broadcast_persisted(
                    seq=result.event_seq,
                    event_type="alerts.history_cleared",
                    payload={"alerts_deleted": result.alerts_deleted},
                )

            release_first.set()
            await asyncio.wait_for(first_finished.wait(), timeout=1)

            cursor = await db.execute("SELECT COUNT(*) FROM home_alerts")
            alert_count = await cursor.fetchone()
            assert alert_count is not None
            assert alert_count[0] == 0
            cursor = await db.execute("SELECT COUNT(*) FROM incidents")
            incident_count = await cursor.fetchone()
            assert incident_count is not None
            assert incident_count[0] == 0
            cursor = await db.execute(
                "SELECT COUNT(*) FROM events WHERE event_type = 'incident.new'"
            )
            incident_event_count = await cursor.fetchone()
            assert incident_event_count is not None
            assert incident_event_count[0] == 0

            # An alert sourced after the marker is still grouped normally.
            await bus.publish(
                "decoy.trip",
                {
                    "source_ip": "192.168.1.61",
                    "dest_port": 8080,
                    "protocol": "tcp",
                },
            )
            await asyncio.wait_for(second_finished.wait(), timeout=1)

            cursor = await db.execute(
                """SELECT a.source_ip, i.source_ip
                   FROM home_alerts a
                   JOIN incidents i ON i.id = a.incident_id"""
            )
            grouped = await cursor.fetchone()
            assert grouped is not None
            assert tuple(grouped) == ("192.168.1.61", "192.168.1.61")
            cursor = await db.execute(
                "SELECT seq FROM events WHERE event_type = 'incident.new'"
            )
            incident_event = await cursor.fetchone()
            assert incident_event is not None
            assert incident_event[0] > result.event_seq
        finally:
            release_first.set()
            await db.close()


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
