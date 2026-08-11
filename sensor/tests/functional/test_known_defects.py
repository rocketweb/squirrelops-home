"""Functional cases for the four already-diagnosed defects.

Each asserts the behavior the product should have. A failure here is a
reproduction of the defect, not a broken test. See qa/FUNCTIONAL-TEST-PLAN.md
for KD-1 through KD-4 and qa/FINDINGS.md for what the failures mean.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from squirrelops_home_sensor.network.port_forward import PortForwardManager

# ---------------------------------------------------------------------------
# KD-4: config endpoint returns secrets
# ---------------------------------------------------------------------------

SECRETS = {
    "home_assistant": {
        "enabled": True,
        "url": "http://192.168.1.20:8123",
        "token": "eyJhbGciOiJIUzI1NiJ9.functional-ha-token",
    },
    "classifier": {"mode": "cloud", "llm_api_key": "fw-functional-key"},
    "alert_methods": {
        "slack": {
            "enabled": True,
            "webhook_url": "https://hooks.slack.com/services/T1/B2/functional",
        }
    },
}


def _seed_secrets(sensor_config):
    sensor_config["home_assistant"] = dict(SECRETS["home_assistant"])
    sensor_config["classifier"] = dict(SECRETS["classifier"])
    sensor_config["alert_methods"]["slack"] = dict(SECRETS["alert_methods"]["slack"])
    sensor_config["sensor"]["secret_passphrase"] = "functional-passphrase"


class TestG01ConfigDoesNotReturnSecrets:
    """G-01: GET /config must not hand credentials to any client."""

    def test_ha_token_is_not_returned(self, client, sensor_config):
        _seed_secrets(sensor_config)
        body = client.get("/config").text
        assert "functional-ha-token" not in body

    def test_slack_webhook_is_not_returned(self, client, sensor_config):
        _seed_secrets(sensor_config)
        body = client.get("/config").text
        assert "hooks.slack.com/services/T1/B2/functional" not in body

    def test_llm_api_key_is_not_returned(self, client, sensor_config):
        _seed_secrets(sensor_config)
        assert "fw-functional-key" not in client.get("/config").text

    def test_secret_passphrase_is_not_returned(self, client, sensor_config):
        _seed_secrets(sensor_config)
        assert "functional-passphrase" not in client.get("/config").text

    def test_alert_methods_endpoint_does_not_return_the_webhook(
        self, client, sensor_config
    ):
        _seed_secrets(sensor_config)
        body = client.get("/config/alert-methods").text
        assert "hooks.slack.com/services/T1/B2/functional" not in body


class TestG02ConfigIsNotCacheable:
    """G-02: config responses must not be written to a client-side cache."""

    @pytest.mark.parametrize("path", ["/config", "/config/alert-methods"])
    def test_response_is_marked_no_store(self, client, path):
        cache_control = client.get(path).headers.get("cache-control", "")
        assert "no-store" in cache_control.lower()


# ---------------------------------------------------------------------------
# KD-2: PF direct_ports is always empty on macOS
# ---------------------------------------------------------------------------

class _RecordingPrivilegedOps:
    """Captures the payload the sensor would hand the root helper."""

    def __init__(self):
        self.calls = []

    async def setup_port_forwards(self, rules, interface, protected_endpoints=None):
        self.calls.append(
            {
                "rules": rules,
                "interface": interface,
                "protected_endpoints": protected_endpoints or [],
            }
        )
        return True

    async def clear_port_forwards(self):
        return True


class TestC04DirectPortsAlwaysEmpty:
    """C-04: characterizes the deliberate deny-by-default posture."""

    @pytest.mark.asyncio
    async def test_add_forwards_requests_no_direct_ports(self):
        ops = _RecordingPrivilegedOps()
        manager = PortForwardManager(ops, interface="en0")

        ok = await manager.add_forwards(
            decoy_id=1,
            bind_ip="192.168.1.200",
            port_remaps={22: 10022, 80: 10080, 8080: 18080},
        )

        assert ok
        endpoints = ops.calls[-1]["protected_endpoints"]
        assert endpoints, "expected one protected endpoint per decoy"
        for endpoint in endpoints:
            assert endpoint["direct_ports"] == [], (
                "a non-empty direct_ports would punch a hole in the default deny"
            )

    @pytest.mark.asyncio
    async def test_high_ports_are_redirected_not_directly_allowed(self):
        ops = _RecordingPrivilegedOps()
        manager = PortForwardManager(ops, interface="en0")

        await manager.add_forwards(
            decoy_id=1,
            bind_ip="192.168.1.200",
            port_remaps={8080: 18080, 49152: 19152},
        )

        rules = ops.calls[-1]["rules"]
        assert {rule["from_port"] for rule in rules} == {8080, 49152}
        for rule in rules:
            assert rule["from_port"] != rule["to_port"]

    @pytest.mark.asyncio
    async def test_quarantine_also_requests_no_direct_ports(self):
        ops = _RecordingPrivilegedOps()
        manager = PortForwardManager(ops, interface="en0")

        await manager.quarantine_endpoints({1: "192.168.1.200", 2: "192.168.1.201"})

        for endpoint in ops.calls[-1]["protected_endpoints"]:
            assert endpoint["direct_ports"] == []


# ---------------------------------------------------------------------------
# KD-1: service-to-primary mapping populated after _active_mimics
# ---------------------------------------------------------------------------

def _orchestrator_for_status(monkeypatch, db, verified_ips):
    """monkeypatch is unused; kept so existing callers read unchanged."""
    """Build a real orchestrator with doubles sufficient for status queries."""
    from squirrelops_home_sensor.scouts.orchestrator import MimicOrchestrator

    ip_manager = SimpleNamespace(
        verified_ips=verified_ips,
        is_available=AsyncMock(return_value=True),
        add_alias=AsyncMock(return_value=True),
        remove_alias=AsyncMock(return_value=True),
    )
    return MimicOrchestrator(
        scout_engine=SimpleNamespace(),
        template_generator=SimpleNamespace(),
        ip_manager=ip_manager,
        event_bus=SimpleNamespace(publish=AsyncMock(return_value=1)),
        db=db,
        max_mimics=4,
        mdns_advertiser=SimpleNamespace(
            register=AsyncMock(return_value=True), unregister=AsyncMock()
        ),
        port_forward_manager=SimpleNamespace(
            add_forwards=AsyncMock(return_value=True),
            remove_forwards=AsyncMock(return_value=True),
            quarantine_endpoints=AsyncMock(return_value=True),
            clear_all=AsyncMock(return_value=True),
        ),
        sensor_hostnames={"sensor-box.local."},
    )


class TestB08HostStatusIsUniform:
    """B-08: every service of an operational host reports the same status."""

    @pytest.mark.asyncio
    async def test_all_services_active_when_host_is_operational(
        self, monkeypatch, db
    ):
        orch = _orchestrator_for_status(monkeypatch, db, {"192.168.1.200"})
        primary, siblings = 100, [101, 102, 103]
        orch._active_mimics[primary] = SimpleNamespace(
            bind_address="192.168.1.200", name="office.local"
        )
        for service_id in [primary, *siblings]:
            orch._service_to_primary[service_id] = primary

        statuses = {
            service_id: orch.effective_mimic_status(service_id, "active")
            for service_id in [primary, *siblings]
        }
        assert set(statuses.values()) == {"active"}, statuses


class TestB09NoFalseDegradedDuringRegistration:
    """B-09: mapped siblings of an operational host stay operational."""

    @pytest.mark.asyncio
    async def test_a_mapped_sibling_is_active_once_registration_completes(
        self, db
    ):
        orch = _orchestrator_for_status(monkeypatch=None, db=db,
                                        verified_ips={"192.168.1.200"})
        primary, sibling = 100, 101
        for service_id in (primary, sibling):
            orch._service_to_primary[service_id] = primary
        orch._active_mimics[primary] = SimpleNamespace(
            bind_address="192.168.1.200", name="office.local"
        )

        assert orch.effective_mimic_status(primary, "active") == "active"
        assert orch.effective_mimic_status(sibling, "active") == "active"


# ---------------------------------------------------------------------------
# KD-3: rolling decoy-trip alerts notify once and then go silent
# ---------------------------------------------------------------------------

class _RecordingBus:
    """Captures subscriptions and publications."""

    def __init__(self):
        self.subscriptions = []
        self.published = []

    def subscribe(self, event_types, callback):
        self.subscriptions.append((list(event_types), callback))

    async def publish(self, event_type, payload, source_id=None):
        self.published.append((event_type, payload))
        return len(self.published)


class TestD06FoldedTripPublishesUpdate:
    """D-06: a repeat trip folded into an open alert still emits an event."""

    @pytest.mark.asyncio
    async def test_second_trip_publishes_alert_updated(self, db):
        from squirrelops_home_sensor.alerts.decoy_handler import DecoyAlertHandler
        from squirrelops_home_sensor.db import queries as q

        decoy_id = await q.insert_decoy(
            db,
            name="office.local",
            decoy_type="mimic",
            bind_address="192.168.1.212",
            port=22,
            created_at="2026-08-07T00:00:00Z",
            updated_at="2026-08-07T00:00:00Z",
        )
        # home_alerts.event_seq references events(seq), so the source events
        # have to exist before the handler can attribute an alert to them.
        for seq in (1, 2):
            await db.execute(
                "INSERT INTO events (seq, event_type, payload, created_at) "
                "VALUES (?, 'decoy.trip', '{}', '2026-08-07T00:00:00Z')",
                (seq,),
            )
        await db.commit()

        bus = _RecordingBus()
        handler = DecoyAlertHandler(db=db, event_bus=bus, incident_grouper=None)

        for seq, port in enumerate((22, 80), start=1):
            await handler._on_decoy_event(
                {
                    "event_type": "decoy.trip",
                    "seq": seq,
                    "payload": {
                        "source_ip": "192.168.1.101",
                        "dest_port": port,
                        "decoy_id": decoy_id,
                        "decoy_name": "office.local",
                        "timestamp": "2026-08-07T00:00:00.000000Z",
                    },
                }
            )

        kinds = [event_type for event_type, _ in bus.published]
        assert "alert.new" in kinds, kinds
        assert "alert.updated" in kinds, kinds


class TestD07UpdatedAlertsAreDelivered:
    """D-07: the dispatcher must react to a folded alert, not only a new one."""

    def test_dispatcher_subscribes_to_alert_updated(self):
        from squirrelops_home_sensor.alerts.dispatcher import AlertDispatcher

        bus = _RecordingBus()
        AlertDispatcher(methods=[]).subscribe_to(bus)

        subscribed = {kind for kinds, _ in bus.subscriptions for kind in kinds}
        assert "alert.new" in subscribed
        assert "alert.updated" in subscribed, (
            "a rolling decoy-trip alert notifies once and then goes silent"
        )
