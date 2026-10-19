"""The response contract: one documented outbound event per alert.

Operators automate a router block from this. The sensor stays read-only; it
must therefore say exactly who did what, sign it so a receiver can trust it,
and never change shape without a schema bump.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import AsyncMock

import pytest

from squirrelops_home_sensor.alerts.dispatcher import (
    RESPONSE_EVENT_SCHEMA,
    AlertDeliveryError,
    AlertDispatcher,
    build_methods_from_config,
    create_webhook_handler,
    format_response_event,
    sign_response_event,
)


def _trip_payload(**changes):
    payload = {
        "id": 42,
        "alert_type": "decoy.trip",
        "severity": "critical",
        "title": "Write activity on Studio Build Mac from 192.168.1.77",
        "summary": "ransomware intent, write activity; 9 connections across 2 ports",
        "source_ip": "192.168.1.77",
        "source_mac": "AA:BB:CC:DD:EE:77",
        "device_id": 12,
        "decoy_id": 7,
        "decoy_name": "Studio Build Mac",
        "dest_port": 445,
        "protocol": "tcp",
        "intruder_intent": "ransomware",
        "narrative_stage": 4,
        "created_at": "2026-10-19T03:00:00.000000Z",
        "event_type": "alert.updated",
        # Internal bookkeeping that must never leave the sensor.
        "source_event_seq": 9001,
        "read_at": None,
        "actioned_at": None,
    }
    payload.update(changes)
    return payload


class TestFormat:
    def test_full_decoy_alert(self) -> None:
        event = format_response_event(
            _trip_payload(), include_device_info=True, sensor_id="sensor-1", sensor_version="2.1.3"
        )

        assert event["schema"] == RESPONSE_EVENT_SCHEMA == "squirrelops.alert/1"
        assert event["event"] == "alert.updated"
        assert event["sensor"] == {"id": "sensor-1", "version": "2.1.3"}
        assert event["alert"] == {
            "id": 42,
            "type": "decoy.trip",
            "severity": "critical",
            "title": "Write activity on Studio Build Mac from 192.168.1.77",
            "summary": "ransomware intent, write activity; 9 connections across 2 ports",
            "created_at": "2026-10-19T03:00:00.000000Z",
        }
        assert event["source"] == {"ip": "192.168.1.77", "mac": "AA:BB:CC:DD:EE:77", "device_id": 12}
        assert event["decoy"] == {"id": 7, "name": "Studio Build Mac", "port": 445, "protocol": "tcp"}
        assert event["campaign"] == {"intent": "ransomware", "stage": 4, "stage_label": "write activity"}
        assert set(event) == {"schema", "event", "sent_at", "sensor", "alert", "source", "decoy", "campaign"}
        assert "source_event_seq" not in json.dumps(event)

    def test_device_identifiers_are_opt_in(self) -> None:
        event = format_response_event(_trip_payload(), include_device_info=False)
        assert event["source"] == {"ip": "192.168.1.77"}

    def test_alert_without_decoy_or_campaign_context(self) -> None:
        event = format_response_event(
            {
                "id": 3,
                "alert_type": "device.new",
                "severity": "medium",
                "title": "New device on the network",
                "summary": "plex-server (Intel) joined",
                "source_ip": "192.168.1.50",
                "source_mac": "AA:BB:CC:DD:EE:50",
                "device_id": 5,
                "created_at": "2026-10-19T03:00:00Z",
            },
            include_device_info=True,
        )
        assert event["event"] == "alert.new", "a payload without an event_type is a new alert"
        assert event["decoy"] is None
        assert event["campaign"] is None
        assert event["sensor"] == {"id": None, "version": None}

    def test_unknown_stage_still_reports_the_number(self) -> None:
        event = format_response_event(_trip_payload(narrative_stage=9), include_device_info=False)
        assert event["campaign"] == {"intent": "ransomware", "stage": 9, "stage_label": None}

    def test_bounds_free_text(self) -> None:
        event = format_response_event(
            _trip_payload(title="t" * 5000, summary="s" * 5000, decoy_name="d" * 5000),
            include_device_info=False,
        )
        assert len(event["alert"]["title"]) == 256
        assert len(event["alert"]["summary"]) == 512
        assert len(event["decoy"]["name"]) == 128

    def test_sent_at_is_utc_iso8601(self) -> None:
        event = format_response_event(_trip_payload(), include_device_info=False)
        assert event["sent_at"].endswith("Z") and "T" in event["sent_at"]


class TestSignature:
    def test_signature_is_hmac_sha256_over_timestamp_and_body(self) -> None:
        body = b'{"schema":"squirrelops.alert/1"}'
        header = sign_response_event(body, secret="shh", timestamp=1760000000)

        assert header == "t=1760000000,v1=" + hmac.new(
            b"shh", b"1760000000." + body, hashlib.sha256
        ).hexdigest()

    def test_receiver_recipe_in_the_docs_verifies(self) -> None:
        # Mirrors the verification snippet in docs/ALERT_WEBHOOK.md.
        body = json.dumps({"schema": RESPONSE_EVENT_SCHEMA}, separators=(",", ":")).encode()
        header = sign_response_event(body, secret="shh", timestamp=1760000000)
        parts = dict(part.split("=", 1) for part in header.split(","))
        expected = hmac.new(b"shh", f"{parts['t']}.".encode() + body, hashlib.sha256).hexdigest()
        assert hmac.compare_digest(parts["v1"], expected)


def _session(status: int = 200):
    response = AsyncMock()
    response.status = status
    session = AsyncMock()
    session.post = AsyncMock(return_value=response)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session


class TestWebhookHandler:
    @pytest.mark.asyncio
    async def test_posts_signed_compact_json(self) -> None:
        session = _session()
        handler = create_webhook_handler(
            "https://automation.lan/hooks/squirrelops",
            signing_secret="shh",
            include_device_info=True,
            sensor_id="sensor-1",
            sensor_version="2.1.3",
            session_factory=lambda: session,
            clock=lambda: 1760000000.9,
        )

        await handler(_trip_payload())

        session.post.assert_awaited_once()
        args, kwargs = session.post.call_args
        assert args[0] == "https://automation.lan/hooks/squirrelops"
        body = kwargs["data"]
        assert isinstance(body, bytes)
        event = json.loads(body)
        assert event["schema"] == "squirrelops.alert/1"
        assert event["source"]["mac"] == "AA:BB:CC:DD:EE:77"
        headers = kwargs["headers"]
        assert headers["Content-Type"] == "application/json"
        assert headers["X-SquirrelOps-Schema"] == "squirrelops.alert/1"
        assert headers["X-SquirrelOps-Event"] == "alert.updated"
        assert headers["User-Agent"] == "squirrelops-home-sensor/2.1.3"
        assert headers["X-SquirrelOps-Signature"] == sign_response_event(body, secret="shh", timestamp=1760000000)

    @pytest.mark.asyncio
    async def test_unsigned_when_no_secret_is_configured(self) -> None:
        session = _session()
        handler = create_webhook_handler("http://192.168.1.1/hook", session_factory=lambda: session)
        await handler(_trip_payload())
        headers = session.post.call_args.kwargs["headers"]
        assert "X-SquirrelOps-Signature" not in headers

    @pytest.mark.asyncio
    async def test_http_error_is_credential_safe(self) -> None:
        url = "https://automation.lan/hooks/SECRET-PATH"
        handler = create_webhook_handler(url, session_factory=lambda: _session(500))
        with pytest.raises(AlertDeliveryError, match="HTTP 500") as exc_info:
            await handler(_trip_payload())
        assert url not in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_transport_error_is_credential_safe(self) -> None:
        url = "https://automation.lan/hooks/SECRET-PATH"
        session = _session()
        session.post = AsyncMock(side_effect=RuntimeError(url))
        handler = create_webhook_handler(url, session_factory=lambda: session)
        with pytest.raises(AlertDeliveryError) as exc_info:
            await handler(_trip_payload())
        assert url not in str(exc_info.value)
        assert "RuntimeError" in str(exc_info.value)


class TestMethodsFromConfig:
    def _names(self, config):
        return [m["name"] for m in build_methods_from_config(config)]

    def test_webhook_method_is_built_when_enabled_with_a_url(self) -> None:
        config = {
            "alert_methods": {
                "webhook": {"enabled": True, "webhook_url": "https://automation.lan/hook", "min_severity": "high"}
            }
        }
        methods = {m["name"]: m for m in build_methods_from_config(config)}
        assert "webhook" in methods
        assert methods["webhook"]["min_severity"] == "high"

    def test_webhook_method_skipped_without_url_or_when_disabled(self) -> None:
        assert "webhook" not in self._names({"alert_methods": {"webhook": {"enabled": True}}})
        assert "webhook" not in self._names(
            {"alert_methods": {"webhook": {"enabled": False, "webhook_url": "https://automation.lan/hook"}}}
        )

    def test_webhook_rejects_non_http_urls(self) -> None:
        assert "webhook" not in self._names(
            {"alert_methods": {"webhook": {"enabled": True, "webhook_url": "file:///etc/passwd"}}}
        )

    def test_home_assistant_method_needs_the_integration_configured(self) -> None:
        enabled = {"alert_methods": {"home_assistant": {"enabled": True}}}
        assert "home_assistant" not in self._names(enabled)
        enabled["home_assistant"] = {"enabled": True, "url": "http://homeassistant.local:8123", "token": "t"}
        assert "home_assistant" in self._names(enabled)
        enabled["home_assistant"]["enabled"] = False
        assert "home_assistant" not in self._names(enabled)


class TestDispatchEventType:
    @pytest.mark.asyncio
    async def test_handlers_learn_whether_the_alert_is_new_or_updated(self) -> None:
        seen = []

        async def handler(payload):
            seen.append(payload["event_type"])

        dispatcher = AlertDispatcher(methods=[{"name": "h", "handler": handler, "min_severity": "low"}])
        new = _trip_payload(id=1, event_type=None)
        del new["event_type"]
        await dispatcher._on_alert_event({"payload": new})
        changed = dict(new, title="Port scan detected from 192.168.1.77")
        await dispatcher._on_alert_updated({"payload": changed})

        assert seen == ["alert.new", "alert.updated"]
