"""Integration tests for the Home Assistant decoy.

Verifies the HA login page, API endpoint, auth rejection, and
planted HA token detection.
"""

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import httpx

from squirrelops_home_sensor.decoys.types.home_assistant import HomeAssistantDecoy
from squirrelops_home_sensor.decoys.types.base import DecoyConnectionEvent
from squirrelops_home_sensor.decoys.credentials import (
    CredentialGenerator,
    GeneratedCredential,
)


@pytest.fixture
def credentials():
    """Generate HA-specific planted credentials."""
    gen = CredentialGenerator()
    ha_token = gen.generate_ha_token()
    aws_key = gen.generate_aws_key()
    return [ha_token, aws_key]


@pytest.fixture
async def decoy(credentials):
    """Start a Home Assistant decoy on a random high port and yield it."""
    d = HomeAssistantDecoy(
        decoy_id=10,
        name="test-ha-decoy",
        port=0,
        bind_address="127.0.0.1",
        planted_credentials=credentials,
    )
    await d.start()
    yield d
    await d.stop()


@pytest.fixture
def base_url(decoy):
    return f"http://{decoy.bind_address}:{decoy.port}"


# ---------------------------------------------------------------------------
# Login page route
# ---------------------------------------------------------------------------

class TestLoginPage:
    """GET / should return a Home Assistant login page."""

    @pytest.mark.asyncio
    async def test_returns_html(self, decoy, base_url):
        """Login page should return HTML."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/")
            assert resp.status_code == 200
            assert "text/html" in resp.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_contains_ha_markers(self, decoy, base_url):
        """HTML should contain Home Assistant branding markers."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/")
            body = resp.text.lower()
            assert "home assistant" in body or "home-assistant" in body or "hass" in body


# ---------------------------------------------------------------------------
# API endpoint
# ---------------------------------------------------------------------------

class TestAPIEndpoint:
    """GET /api/ should return 401 Unauthorized."""

    @pytest.mark.asyncio
    async def test_api_returns_401(self, decoy, base_url):
        """Unauthenticated API access should be rejected."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/api/")
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_api_returns_json_error(self, decoy, base_url):
        """401 response should include a JSON error body."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/api/")
            assert "application/json" in resp.headers.get("content-type", "")
            data = resp.json()
            assert "message" in data


# ---------------------------------------------------------------------------
# Auth token endpoint
# ---------------------------------------------------------------------------

class TestAuthTokenEndpoint:
    """POST /auth/token should reject all authentication attempts."""

    @pytest.mark.asyncio
    async def test_rejects_token_request(self, decoy, base_url):
        """Token endpoint should reject all credentials."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{base_url}/auth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "fake-auth-code",
                    "client_id": "http://localhost/",
                },
            )
            assert resp.status_code in (400, 401, 403)

    @pytest.mark.asyncio
    async def test_returns_json(self, decoy, base_url):
        """Rejection should be a JSON response."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{base_url}/auth/token",
                data={"grant_type": "authorization_code", "code": "fake"},
            )
            assert "application/json" in resp.headers.get("content-type", "")


# ---------------------------------------------------------------------------
# Connection logging
# ---------------------------------------------------------------------------

class TestHAConnectionLogging:
    """Every request should fire a connection event."""

    @pytest.mark.asyncio
    async def test_connection_event_on_login_page(self, decoy, base_url):
        """Accessing the login page should trigger a connection event."""
        events: list[DecoyConnectionEvent] = []
        decoy.on_connection = lambda e: events.append(e)

        async with httpx.AsyncClient() as client:
            await client.get(f"{base_url}/")

        await asyncio.sleep(0.2)

        assert len(events) >= 1
        assert events[0].request_path == "/"
        assert events[0].protocol == "tcp"

    @pytest.mark.asyncio
    async def test_connection_event_on_api(self, decoy, base_url):
        """Accessing the API should trigger a connection event."""
        events: list[DecoyConnectionEvent] = []
        decoy.on_connection = lambda e: events.append(e)

        async with httpx.AsyncClient() as client:
            await client.get(f"{base_url}/api/")

        await asyncio.sleep(0.2)

        assert len(events) >= 1
        assert events[0].request_path == "/api/"


# ---------------------------------------------------------------------------
# Token detection — Authorization header
# ---------------------------------------------------------------------------

class TestHATokenDetection:
    """Decoy should detect planted HA tokens in Authorization headers and bodies."""

    @pytest.mark.asyncio
    async def test_detects_ha_token_in_bearer_header(self, decoy, base_url, credentials):
        """Planted HA token in Authorization: Bearer header should be detected."""
        events: list[DecoyConnectionEvent] = []
        decoy.on_connection = lambda e: events.append(e)

        ha_cred = next(c for c in credentials if c.credential_type == "ha_token")
        async with httpx.AsyncClient() as client:
            await client.get(
                f"{base_url}/api/",
                headers={"Authorization": f"Bearer {ha_cred.credential_value}"},
            )

        await asyncio.sleep(0.2)

        cred_events = [e for e in events if e.credential_used is not None]
        assert len(cred_events) >= 1
        assert cred_events[0].credential_used == ha_cred.credential_value

    @pytest.mark.asyncio
    async def test_detects_token_in_post_body(self, decoy, base_url, credentials):
        """Planted HA token appearing in POST body should be detected."""
        events: list[DecoyConnectionEvent] = []
        decoy.on_connection = lambda e: events.append(e)

        ha_cred = next(c for c in credentials if c.credential_type == "ha_token")
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{base_url}/auth/token",
                data={"access_token": ha_cred.credential_value},
            )

        await asyncio.sleep(0.2)

        cred_events = [e for e in events if e.credential_used is not None]
        assert len(cred_events) >= 1
        assert cred_events[0].credential_used == ha_cred.credential_value

    @pytest.mark.asyncio
    async def test_no_false_positive_on_normal_request(self, decoy, base_url):
        """Requests without planted credentials should not flag credential_used."""
        events: list[DecoyConnectionEvent] = []
        decoy.on_connection = lambda e: events.append(e)

        async with httpx.AsyncClient() as client:
            await client.get(
                f"{base_url}/api/",
                headers={"Authorization": "Bearer not-a-planted-token"},
            )

        await asyncio.sleep(0.2)

        assert len(events) >= 1
        assert events[0].credential_used is None
