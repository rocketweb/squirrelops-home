"""Integration tests for the Dev Server decoy.

Verifies the Express/Next.js HTTP decoy wrapping ClownPeanuts Emulator:
routes, banners, connection logging, and credential detection.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from squirrelops_home_sensor.decoys.types.dev_server import DevServerDecoy
from squirrelops_home_sensor.decoys.types.base import DecoyConnectionEvent
from squirrelops_home_sensor.decoys.credentials import (
    CredentialGenerator,
    GeneratedCredential,
)


@pytest.fixture
def credentials():
    """Generate a standard set of planted credentials for the decoy."""
    gen = CredentialGenerator()
    env_cred = gen.generate_env_file()
    aws_cred = gen.generate_aws_key()
    return [env_cred, aws_cred]


@pytest.fixture
async def decoy(credentials):
    """Start a dev server decoy on a random high port and yield it."""
    d = DevServerDecoy(
        decoy_id=1,
        name="test-dev-server",
        port=0,  # 0 = OS picks a free port
        bind_address="127.0.0.1",
        planted_credentials=credentials,
    )
    await d.start()
    yield d
    await d.stop()


@pytest.fixture
def base_url(decoy):
    """Return the base URL for the running decoy."""
    return f"http://{decoy.bind_address}:{decoy.port}"


# ---------------------------------------------------------------------------
# HTTP listener starts and stops
# ---------------------------------------------------------------------------

class TestDevServerLifecycle:
    """Decoy must start, serve HTTP, and stop cleanly."""

    @pytest.mark.asyncio
    async def test_is_running_after_start(self, decoy):
        """Decoy should report running after start()."""
        assert decoy.is_running is True

    @pytest.mark.asyncio
    async def test_health_check_passes(self, decoy):
        """health_check() should return True when running."""
        assert await decoy.health_check() is True

    @pytest.mark.asyncio
    async def test_stop_shuts_down(self, credentials):
        """After stop(), the decoy should no longer be running."""
        d = DevServerDecoy(
            decoy_id=2,
            name="stop-test",
            port=0,
            bind_address="127.0.0.1",
            planted_credentials=credentials,
        )
        await d.start()
        port = d.port
        await d.stop()
        assert d.is_running is False

    @pytest.mark.asyncio
    async def test_http_reachable(self, decoy, base_url):
        """The decoy should accept HTTP connections."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/")
            assert resp.status_code in (200, 500)  # React error page returns 500


# ---------------------------------------------------------------------------
# Express/Next.js banner
# ---------------------------------------------------------------------------

class TestExpressBanner:
    """Responses should mimic an Express/Next.js development server."""

    @pytest.mark.asyncio
    async def test_server_header(self, decoy, base_url):
        """Response should include an Express-like server header."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/")
            # Should have X-Powered-By: Express or similar
            powered_by = resp.headers.get("x-powered-by", "")
            assert "Express" in powered_by or "Next.js" in powered_by, (
                f"Expected Express/Next.js banner, got X-Powered-By: {powered_by}"
            )


# ---------------------------------------------------------------------------
# Route: / (React error page)
# ---------------------------------------------------------------------------

class TestRootRoute:
    """GET / should return a React development error page."""

    @pytest.mark.asyncio
    async def test_root_returns_html(self, decoy, base_url):
        """Root route should return HTML content."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/")
            assert "text/html" in resp.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_root_contains_react_markers(self, decoy, base_url):
        """HTML should contain React/Next.js development markers."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/")
            body = resp.text.lower()
            # Should reference react or next.js in the error page
            assert "react" in body or "next" in body or "__next" in body


# ---------------------------------------------------------------------------
# Route: /api/health
# ---------------------------------------------------------------------------

class TestApiHealthRoute:
    """GET /api/health should return a JSON health response."""

    @pytest.mark.asyncio
    async def test_returns_json(self, decoy, base_url):
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/api/health")
            assert resp.status_code == 200
            assert "application/json" in resp.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_has_status_field(self, decoy, base_url):
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/api/health")
            data = resp.json()
            assert "status" in data


# ---------------------------------------------------------------------------
# Route: /.env (planted credentials)
# ---------------------------------------------------------------------------

class TestEnvRoute:
    """GET /.env should return planted .env file credentials."""

    @pytest.mark.asyncio
    async def test_returns_env_content(self, decoy, base_url):
        """/.env should serve the planted .env file contents."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/.env")
            assert resp.status_code == 200
            body = resp.text
            # Should contain env variable patterns
            assert "=" in body

    @pytest.mark.asyncio
    async def test_content_type_is_text(self, decoy, base_url):
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/.env")
            content_type = resp.headers.get("content-type", "")
            assert "text" in content_type


# ---------------------------------------------------------------------------
# Connection logging
# ---------------------------------------------------------------------------

class TestConnectionLogging:
    """Every connection should trigger the on_connection callback."""

    @pytest.mark.asyncio
    async def test_connection_callback_fired(self, decoy, base_url):
        """Accessing any route should invoke the connection callback."""
        events: list[DecoyConnectionEvent] = []
        decoy.on_connection = lambda e: events.append(e)

        async with httpx.AsyncClient() as client:
            await client.get(f"{base_url}/api/health")

        # Allow time for the callback to be invoked (thread -> async boundary)
        await asyncio.sleep(0.2)

        assert len(events) >= 1
        event = events[0]
        assert event.source_ip in ("127.0.0.1", "::1")
        assert event.dest_port == decoy.port
        assert event.protocol == "tcp"
        assert event.request_path == "/api/health"

    @pytest.mark.asyncio
    async def test_connection_event_has_timestamp(self, decoy, base_url):
        """Connection events should include a UTC timestamp."""
        events: list[DecoyConnectionEvent] = []
        decoy.on_connection = lambda e: events.append(e)

        async with httpx.AsyncClient() as client:
            await client.get(f"{base_url}/")

        await asyncio.sleep(0.2)

        assert len(events) >= 1
        assert isinstance(events[0].timestamp, datetime)


# ---------------------------------------------------------------------------
# Credential detection in requests
# ---------------------------------------------------------------------------

class TestCredentialDetection:
    """Decoy should detect when planted credentials appear in requests."""

    @pytest.mark.asyncio
    async def test_credential_in_auth_header(self, decoy, base_url, credentials):
        """Sending a planted credential in Authorization header should be detected."""
        events: list[DecoyConnectionEvent] = []
        decoy.on_connection = lambda e: events.append(e)

        # Use the AWS key as a Bearer token
        aws_cred = next(c for c in credentials if c.credential_type == "aws_key")
        async with httpx.AsyncClient() as client:
            await client.get(
                f"{base_url}/api/health",
                headers={"Authorization": f"Bearer {aws_cred.credential_value}"},
            )

        await asyncio.sleep(0.2)

        assert len(events) >= 1
        cred_events = [e for e in events if e.credential_used is not None]
        assert len(cred_events) >= 1
        assert cred_events[0].credential_used == aws_cred.credential_value

    @pytest.mark.asyncio
    async def test_no_credential_when_none_sent(self, decoy, base_url):
        """Normal requests without planted creds should have credential_used=None."""
        events: list[DecoyConnectionEvent] = []
        decoy.on_connection = lambda e: events.append(e)

        async with httpx.AsyncClient() as client:
            await client.get(f"{base_url}/api/health")

        await asyncio.sleep(0.2)

        assert len(events) >= 1
        assert events[0].credential_used is None
