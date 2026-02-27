"""Unit tests for the APNs push notification handler."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from squirrelops_home_sensor.alerts.dispatcher import create_apns_handler


# -- Helpers ----------------------------------------------------------------

def _mock_session_factory(status: int = 200):
    """Return (factory_callable, mock_session) for injecting into the handler."""
    mock_resp = MagicMock()
    mock_resp.status = status
    mock_session = AsyncMock()
    mock_session.post = AsyncMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return lambda: mock_session, mock_session


# -- Tests ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_apns_handler_sends_push():
    """Handler sends correct payload with device_token, title, severity to relay URL."""
    factory, mock_session = _mock_session_factory(200)
    handler = create_apns_handler(
        "https://relay.example.com/api/push",
        device_token="abc123devicetoken",
        session_factory=factory,
    )

    alert = {
        "title": "Decoy Trip Detected",
        "detail": "Someone accessed the honey share",
        "alert_type": "decoy.trip",
        "severity": "critical",
    }
    await handler(alert)

    mock_session.post.assert_awaited_once()
    call_kwargs = mock_session.post.call_args
    assert call_kwargs[0][0] == "https://relay.example.com/api/push"

    sent_json = call_kwargs[1]["json"]
    assert sent_json["device_token"] == "abc123devicetoken"
    assert sent_json["title"] == "Decoy Trip Detected"
    assert sent_json["body"] == "Someone accessed the honey share"
    assert sent_json["category"] == "decoy.trip"
    assert sent_json["severity"] == "critical"


@pytest.mark.asyncio
async def test_apns_handler_skips_when_no_token():
    """When device_token is empty, handler does nothing (no HTTP call)."""
    factory, mock_session = _mock_session_factory(200)
    handler = create_apns_handler(
        "https://relay.example.com/api/push",
        device_token="",
        session_factory=factory,
    )

    alert = {
        "title": "Anomaly",
        "severity": "low",
    }
    await handler(alert)

    mock_session.post.assert_not_awaited()


@pytest.mark.asyncio
async def test_apns_handler_includes_auth_header():
    """When relay_token provided, Authorization header is set."""
    factory, mock_session = _mock_session_factory(200)
    handler = create_apns_handler(
        "https://relay.example.com/api/push",
        relay_token="secret-relay-token",
        device_token="abc123devicetoken",
        session_factory=factory,
    )

    alert = {
        "title": "New Device",
        "severity": "medium",
    }
    await handler(alert)

    mock_session.post.assert_awaited_once()
    call_kwargs = mock_session.post.call_args
    headers = call_kwargs[1]["headers"]
    assert headers["Authorization"] == "Bearer secret-relay-token"
    assert headers["Content-Type"] == "application/json"
