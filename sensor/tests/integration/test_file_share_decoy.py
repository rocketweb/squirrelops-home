"""Integration tests for the File Share decoy.

Verifies the nginx-style directory listing, passwords.txt download,
SSH key download, access logging, and basic auth credential detection.
"""

import asyncio
import base64
from datetime import datetime, timezone

import pytest
import httpx

from squirrelops_home_sensor.decoys.types.file_share import FileShareDecoy
from squirrelops_home_sensor.decoys.types.base import DecoyConnectionEvent
from squirrelops_home_sensor.decoys.credentials import (
    CredentialGenerator,
    GeneratedCredential,
)


@pytest.fixture
def credentials():
    """Generate file-share-specific planted credentials."""
    gen = CredentialGenerator()
    passwords = gen.generate_passwords_file()
    ssh_key = gen.generate_ssh_key()
    return passwords + [ssh_key]


@pytest.fixture
async def decoy(credentials):
    """Start a file share decoy on a random high port and yield it."""
    d = FileShareDecoy(
        decoy_id=20,
        name="test-file-share",
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
# Directory listing
# ---------------------------------------------------------------------------

class TestDirectoryListing:
    """GET / should return an nginx-style directory listing."""

    @pytest.mark.asyncio
    async def test_returns_html(self, decoy, base_url):
        """Root should return HTML."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/")
            assert resp.status_code == 200
            assert "text/html" in resp.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_nginx_server_header(self, decoy, base_url):
        """Response should include an nginx Server header."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/")
            server = resp.headers.get("server", "")
            assert "nginx" in server.lower(), f"Expected nginx banner, got Server: {server}"

    @pytest.mark.asyncio
    async def test_lists_passwords_file(self, decoy, base_url):
        """Directory listing should include a link to passwords.txt."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/")
            assert "passwords.txt" in resp.text

    @pytest.mark.asyncio
    async def test_lists_ssh_directory(self, decoy, base_url):
        """Directory listing should include a .ssh/ directory or id_rsa link."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/")
            body = resp.text
            assert ".ssh" in body or "id_rsa" in body


# ---------------------------------------------------------------------------
# passwords.txt download
# ---------------------------------------------------------------------------

class TestPasswordsDownload:
    """GET /passwords.txt should return the planted credential file."""

    @pytest.mark.asyncio
    async def test_returns_text(self, decoy, base_url):
        """passwords.txt should be served as plain text."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/passwords.txt")
            assert resp.status_code == 200
            content_type = resp.headers.get("content-type", "")
            assert "text" in content_type

    @pytest.mark.asyncio
    async def test_contains_credential_pairs(self, decoy, base_url):
        """File should contain username:password pairs."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/passwords.txt")
            lines = [l for l in resp.text.strip().split("\n") if l.strip()]
            assert len(lines) >= 8
            for line in lines:
                assert ":" in line, f"Expected user:pass format, got: {line}"

    @pytest.mark.asyncio
    async def test_content_matches_planted_credentials(self, decoy, base_url, credentials):
        """File content should match the planted password credentials."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/passwords.txt")
            body = resp.text
            password_creds = [c for c in credentials if c.credential_type == "password"]
            for cred in password_creds:
                assert cred.credential_value in body


# ---------------------------------------------------------------------------
# SSH key download
# ---------------------------------------------------------------------------

class TestSSHKeyDownload:
    """GET /.ssh/id_rsa should return the planted SSH private key."""

    @pytest.mark.asyncio
    async def test_returns_pem_content(self, decoy, base_url):
        """SSH key route should return PEM-formatted content."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/.ssh/id_rsa")
            assert resp.status_code == 200
            assert "BEGIN RSA PRIVATE KEY" in resp.text

    @pytest.mark.asyncio
    async def test_content_matches_planted_key(self, decoy, base_url, credentials):
        """Content should match the planted SSH key."""
        ssh_cred = next(c for c in credentials if c.credential_type == "ssh_key")
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base_url}/.ssh/id_rsa")
            assert ssh_cred.credential_value in resp.text


# ---------------------------------------------------------------------------
# Connection logging
# ---------------------------------------------------------------------------

class TestFileShareConnectionLogging:
    """Every request should fire a connection event."""

    @pytest.mark.asyncio
    async def test_connection_event_on_directory_listing(self, decoy, base_url):
        events: list[DecoyConnectionEvent] = []
        decoy.on_connection = lambda e: events.append(e)

        async with httpx.AsyncClient() as client:
            await client.get(f"{base_url}/")

        await asyncio.sleep(0.2)

        assert len(events) >= 1
        assert events[0].request_path == "/"
        assert events[0].dest_port == decoy.port

    @pytest.mark.asyncio
    async def test_connection_event_on_passwords_download(self, decoy, base_url):
        events: list[DecoyConnectionEvent] = []
        decoy.on_connection = lambda e: events.append(e)

        async with httpx.AsyncClient() as client:
            await client.get(f"{base_url}/passwords.txt")

        await asyncio.sleep(0.2)

        assert len(events) >= 1
        assert events[0].request_path == "/passwords.txt"


# ---------------------------------------------------------------------------
# Basic auth detection
# ---------------------------------------------------------------------------

class TestBasicAuthDetection:
    """Decoy should decode Base64 Authorization headers and detect planted credentials."""

    @pytest.mark.asyncio
    async def test_detects_planted_password_in_basic_auth(self, decoy, base_url, credentials):
        """Planted username:password in Basic auth header should be detected."""
        events: list[DecoyConnectionEvent] = []
        decoy.on_connection = lambda e: events.append(e)

        # Use the first password credential in Basic auth
        password_cred = next(c for c in credentials if c.credential_type == "password")
        # credential_value is "username:password" — exactly what Basic auth encodes
        encoded = base64.b64encode(password_cred.credential_value.encode()).decode()

        async with httpx.AsyncClient() as client:
            await client.get(
                f"{base_url}/passwords.txt",
                headers={"Authorization": f"Basic {encoded}"},
            )

        await asyncio.sleep(0.2)

        cred_events = [e for e in events if e.credential_used is not None]
        assert len(cred_events) >= 1
        assert cred_events[0].credential_used == password_cred.credential_value

    @pytest.mark.asyncio
    async def test_no_detection_for_unknown_basic_auth(self, decoy, base_url):
        """Non-planted credentials in Basic auth should not set credential_used."""
        events: list[DecoyConnectionEvent] = []
        decoy.on_connection = lambda e: events.append(e)

        encoded = base64.b64encode(b"random:credentials").decode()
        async with httpx.AsyncClient() as client:
            await client.get(
                f"{base_url}/",
                headers={"Authorization": f"Basic {encoded}"},
            )

        await asyncio.sleep(0.2)

        assert len(events) >= 1
        assert events[0].credential_used is None

    @pytest.mark.asyncio
    async def test_detects_bearer_token(self, decoy, base_url, credentials):
        """Planted credentials sent as Bearer tokens should also be detected."""
        events: list[DecoyConnectionEvent] = []
        decoy.on_connection = lambda e: events.append(e)

        password_cred = next(c for c in credentials if c.credential_type == "password")
        async with httpx.AsyncClient() as client:
            await client.get(
                f"{base_url}/",
                headers={"Authorization": f"Bearer {password_cred.credential_value}"},
            )

        await asyncio.sleep(0.2)

        cred_events = [e for e in events if e.credential_used is not None]
        assert len(cred_events) >= 1
