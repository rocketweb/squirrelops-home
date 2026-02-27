"""Integration tests for the alert dispatcher.

The dispatcher subscribes to alert.new events on the event bus and
fans out to configured alert methods (Slack webhook, log file, future APNs).
Each method can have a minimum severity threshold.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest


# -- Lightweight event bus stub --------------------------------------

class StubEventBus:
    """Minimal event bus for testing."""

    def __init__(self) -> None:
        self.published: list[tuple[str, dict[str, Any]]] = []
        self._subscribers: dict[str, list[Any]] = {}

    async def publish(self, event_type: str, payload: dict[str, Any]) -> int:
        self.published.append((event_type, payload))
        for cb in self._subscribers.get(event_type, []):
            await cb(event_type, payload)
        for cb in self._subscribers.get("*", []):
            await cb(event_type, payload)
        return len(self.published)

    def subscribe(self, event_types: list[str], callback: Any) -> None:
        for et in event_types:
            self._subscribers.setdefault(et, []).append(callback)


# -- Tests -----------------------------------------------------------


class TestFanOut:
    """Dispatcher fans out alerts to all configured methods."""

    @pytest.mark.asyncio
    async def test_dispatches_to_slack_and_log(self):
        from squirrelops_home_sensor.alerts.dispatcher import AlertDispatcher

        mock_slack = AsyncMock()
        mock_log = AsyncMock()

        dispatcher = AlertDispatcher(
            methods=[
                {"name": "slack", "handler": mock_slack, "min_severity": "low"},
                {"name": "log", "handler": mock_log, "min_severity": "low"},
            ]
        )

        alert_payload = {
            "alert_id": 1,
            "alert_type": "decoy.trip",
            "severity": "high",
            "title": "Decoy tripped",
            "detail": "Connection to fake-nas:8445",
            "source_ip": "192.168.1.99",
            "created_at": "2026-02-22T10:00:00.000Z",
        }

        await dispatcher.dispatch(alert_payload)

        mock_slack.assert_awaited_once()
        mock_log.assert_awaited_once()

        # Both handlers receive the same payload
        slack_call_payload = mock_slack.call_args[0][0]
        assert slack_call_payload["alert_type"] == "decoy.trip"
        log_call_payload = mock_log.call_args[0][0]
        assert log_call_payload["alert_type"] == "decoy.trip"

    @pytest.mark.asyncio
    async def test_dispatches_to_all_methods_even_if_one_fails(self):
        from squirrelops_home_sensor.alerts.dispatcher import AlertDispatcher

        mock_slack = AsyncMock(side_effect=Exception("Slack is down"))
        mock_log = AsyncMock()

        dispatcher = AlertDispatcher(
            methods=[
                {"name": "slack", "handler": mock_slack, "min_severity": "low"},
                {"name": "log", "handler": mock_log, "min_severity": "low"},
            ]
        )

        alert_payload = {
            "alert_id": 1,
            "alert_type": "decoy.trip",
            "severity": "high",
            "title": "Decoy tripped",
            "detail": "Connection to fake-nas:8445",
            "source_ip": "192.168.1.99",
            "created_at": "2026-02-22T10:00:00.000Z",
        }

        # Should not raise even though Slack fails
        await dispatcher.dispatch(alert_payload)

        mock_slack.assert_awaited_once()
        mock_log.assert_awaited_once()


class TestSeverityFiltering:
    """Each method can have a minimum severity threshold."""

    @pytest.mark.asyncio
    async def test_filters_below_minimum_severity(self):
        from squirrelops_home_sensor.alerts.dispatcher import AlertDispatcher

        mock_slack = AsyncMock()
        mock_log = AsyncMock()

        dispatcher = AlertDispatcher(
            methods=[
                {"name": "slack", "handler": mock_slack, "min_severity": "high"},
                {"name": "log", "handler": mock_log, "min_severity": "low"},
            ]
        )

        alert_payload = {
            "alert_id": 1,
            "alert_type": "device.new",
            "severity": "medium",
            "title": "New device detected",
            "detail": "Unknown device appeared",
            "source_ip": "192.168.1.50",
            "created_at": "2026-02-22T10:00:00.000Z",
        }

        await dispatcher.dispatch(alert_payload)

        # Slack has min_severity=high, so medium alert should NOT be dispatched
        mock_slack.assert_not_awaited()
        # Log has min_severity=low, so medium alert SHOULD be dispatched
        mock_log.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_dispatches_at_exact_threshold(self):
        from squirrelops_home_sensor.alerts.dispatcher import AlertDispatcher

        mock_slack = AsyncMock()

        dispatcher = AlertDispatcher(
            methods=[
                {"name": "slack", "handler": mock_slack, "min_severity": "high"},
            ]
        )

        alert_payload = {
            "alert_id": 1,
            "alert_type": "decoy.trip",
            "severity": "high",
            "title": "Decoy tripped",
            "detail": "Probe detected",
            "source_ip": "192.168.1.99",
            "created_at": "2026-02-22T10:00:00.000Z",
        }

        await dispatcher.dispatch(alert_payload)

        mock_slack.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_critical_always_dispatched(self):
        from squirrelops_home_sensor.alerts.dispatcher import AlertDispatcher

        mock_slack = AsyncMock()

        dispatcher = AlertDispatcher(
            methods=[
                {"name": "slack", "handler": mock_slack, "min_severity": "critical"},
            ]
        )

        alert_payload = {
            "alert_id": 1,
            "alert_type": "decoy.credential_trip",
            "severity": "critical",
            "title": "Credential used",
            "detail": "passwords.txt downloaded",
            "source_ip": "192.168.1.99",
            "created_at": "2026-02-22T10:00:00.000Z",
        }

        await dispatcher.dispatch(alert_payload)
        mock_slack.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_low_alert_blocked_by_medium_threshold(self):
        from squirrelops_home_sensor.alerts.dispatcher import AlertDispatcher

        mock_handler = AsyncMock()

        dispatcher = AlertDispatcher(
            methods=[
                {"name": "test", "handler": mock_handler, "min_severity": "medium"},
            ]
        )

        alert_payload = {
            "alert_id": 1,
            "alert_type": "system.learning_complete",
            "severity": "low",
            "title": "Learning complete",
            "detail": "48-hour learning period finished",
            "source_ip": None,
            "created_at": "2026-02-22T10:00:00.000Z",
        }

        await dispatcher.dispatch(alert_payload)
        mock_handler.assert_not_awaited()


class TestSlackPayload:
    """Slack handler produces correctly formatted payloads."""

    @pytest.mark.asyncio
    async def test_slack_payload_format_critical(self):
        from squirrelops_home_sensor.alerts.dispatcher import format_slack_payload

        alert_payload = {
            "alert_id": 42,
            "alert_type": "decoy.credential_trip",
            "severity": "critical",
            "title": "Credential used on file share",
            "detail": "passwords.txt downloaded from fake-nas",
            "source_ip": "192.168.1.99",
            "created_at": "2026-02-22T10:15:30.000Z",
        }

        slack_msg = format_slack_payload(alert_payload)

        # Must have text field (Slack API requirement)
        assert "text" in slack_msg
        assert "Credential used on file share" in slack_msg["text"]

        # Must have blocks for rich formatting
        assert "blocks" in slack_msg
        blocks = slack_msg["blocks"]
        assert len(blocks) >= 1

        # Verify severity emoji is in the header
        block_text = json.dumps(blocks, ensure_ascii=False)
        assert "\U0001f534" in block_text  # red circle for critical

        # Verify source IP is present
        assert "192.168.1.99" in block_text

    @pytest.mark.asyncio
    async def test_slack_payload_format_low(self):
        from squirrelops_home_sensor.alerts.dispatcher import format_slack_payload

        alert_payload = {
            "alert_id": 7,
            "alert_type": "system.learning_complete",
            "severity": "low",
            "title": "Learning period complete",
            "detail": "Network baseline established",
            "source_ip": None,
            "created_at": "2026-02-22T10:15:30.000Z",
        }

        slack_msg = format_slack_payload(alert_payload)

        assert "text" in slack_msg
        block_text = json.dumps(slack_msg["blocks"], ensure_ascii=False)
        assert "\U0001f535" in block_text  # blue circle for low

    @pytest.mark.asyncio
    async def test_slack_payload_includes_timestamp(self):
        from squirrelops_home_sensor.alerts.dispatcher import format_slack_payload

        alert_payload = {
            "alert_id": 1,
            "alert_type": "decoy.trip",
            "severity": "high",
            "title": "Decoy tripped",
            "detail": "Connection detected",
            "source_ip": "192.168.1.99",
            "created_at": "2026-02-22T10:15:30.000Z",
        }

        slack_msg = format_slack_payload(alert_payload)
        block_text = json.dumps(slack_msg["blocks"])
        assert "2026-02-22" in block_text


class TestSlackHandler:
    """Slack handler sends POST request to webhook URL."""

    @pytest.mark.asyncio
    async def test_slack_handler_posts_to_webhook(self):
        from squirrelops_home_sensor.alerts.dispatcher import create_slack_handler

        webhook_url = "https://hooks.slack.com/services/T00/B00/XXXX"

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.raise_for_status = MagicMock()

        mock_session = AsyncMock()
        mock_session.post = AsyncMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        handler = create_slack_handler(
            webhook_url, session_factory=lambda: mock_session
        )

        alert_payload = {
            "alert_id": 1,
            "alert_type": "decoy.trip",
            "severity": "high",
            "title": "Decoy tripped",
            "detail": "Connection to fake-nas",
            "source_ip": "192.168.1.99",
            "created_at": "2026-02-22T10:00:00.000Z",
        }

        await handler(alert_payload)

        mock_session.post.assert_awaited_once()
        call_args = mock_session.post.call_args
        assert call_args[0][0] == webhook_url
        posted_json = call_args[1]["json"]
        assert "text" in posted_json
        assert "blocks" in posted_json


class TestLogHandler:
    """Log handler writes structured JSON to the configured logger."""

    @pytest.mark.asyncio
    async def test_log_handler_writes_json(self, caplog):
        from squirrelops_home_sensor.alerts.dispatcher import create_log_handler

        handler = create_log_handler(logger_name="squirrelops.alerts.test")

        alert_payload = {
            "alert_id": 1,
            "alert_type": "decoy.trip",
            "severity": "high",
            "title": "Decoy tripped",
            "detail": "Connection to fake-nas:8445",
            "source_ip": "192.168.1.99",
            "created_at": "2026-02-22T10:00:00.000Z",
        }

        with caplog.at_level(logging.INFO, logger="squirrelops.alerts.test"):
            await handler(alert_payload)

        assert len(caplog.records) == 1
        record = caplog.records[0]

        # The log message should be valid JSON
        logged = json.loads(record.getMessage())
        assert logged["alert_type"] == "decoy.trip"
        assert logged["severity"] == "high"
        assert logged["source_ip"] == "192.168.1.99"


class TestEventBusIntegration:
    """Dispatcher can subscribe to event bus and auto-dispatch."""

    @pytest.mark.asyncio
    async def test_subscribes_to_alert_new_events(self):
        from squirrelops_home_sensor.alerts.dispatcher import AlertDispatcher

        event_bus = StubEventBus()
        mock_handler = AsyncMock()

        dispatcher = AlertDispatcher(
            methods=[
                {"name": "test", "handler": mock_handler, "min_severity": "low"},
            ]
        )

        dispatcher.subscribe_to(event_bus)

        await event_bus.publish(
            "alert.new",
            {
                "alert_id": 1,
                "alert_type": "decoy.trip",
                "severity": "high",
                "title": "Decoy tripped",
                "detail": "Connection",
                "source_ip": "192.168.1.99",
                "created_at": "2026-02-22T10:00:00.000Z",
            },
        )

        mock_handler.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_ignores_non_alert_events(self):
        from squirrelops_home_sensor.alerts.dispatcher import AlertDispatcher

        event_bus = StubEventBus()
        mock_handler = AsyncMock()

        dispatcher = AlertDispatcher(
            methods=[
                {"name": "test", "handler": mock_handler, "min_severity": "low"},
            ]
        )

        dispatcher.subscribe_to(event_bus)

        await event_bus.publish(
            "device.discovered",
            {"device_id": 5, "ip": "192.168.1.10"},
        )

        mock_handler.assert_not_awaited()


class TestApnsStub:
    """APNs handler is a no-op stub for now."""

    @pytest.mark.asyncio
    async def test_apns_stub_does_not_raise(self):
        from squirrelops_home_sensor.alerts.dispatcher import create_apns_stub_handler

        handler = create_apns_stub_handler()

        alert_payload = {
            "alert_id": 1,
            "alert_type": "decoy.credential_trip",
            "severity": "critical",
            "title": "Credential used",
            "detail": "passwords.txt downloaded",
            "source_ip": "192.168.1.99",
            "created_at": "2026-02-22T10:00:00.000Z",
        }

        # Should complete without error
        await handler(alert_payload)
