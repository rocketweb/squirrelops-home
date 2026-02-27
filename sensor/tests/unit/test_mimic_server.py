"""Tests for the async mimic server — lightweight HTTP runtime."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from squirrelops_home_sensor.decoys.types.mimic import (
    MimicDecoy,
    _MimicEndpoint,
    _STATUS_TEXTS,
)


class TestMimicEndpointHTTP:
    """Verify HTTP request handling on a mimic endpoint."""

    @pytest.mark.asyncio
    async def test_serves_configured_route(self) -> None:
        """Endpoint should return the configured status and body for matching route."""
        routes = [{
            "path": "/",
            "method": "GET",
            "status": 200,
            "headers": {"X-Custom": "test"},
            "body": "<html>OK</html>",
        }]
        callback = MagicMock()
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=routes,
            server_header="TestServer/1.0",
            protocol_banner=None,
            connection_callback=callback,
            credential_values=set(),
        )
        await endpoint.start()
        port = endpoint._server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            text = response.decode("utf-8")

            assert "HTTP/1.1 200 OK" in text
            assert "TestServer/1.0" in text
            assert "<html>OK</html>" in text
            assert "X-Custom: test" in text

            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

        assert callback.called

    @pytest.mark.asyncio
    async def test_returns_404_for_unknown_path(self) -> None:
        """Endpoint should return 404 for paths not in the route config."""
        routes = [{
            "path": "/api/v1",
            "method": "GET",
            "status": 200,
            "headers": {},
            "body": "ok",
        }]
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=routes,
            server_header=None,
            protocol_banner=None,
            connection_callback=None,
            credential_values=set(),
        )
        await endpoint.start()
        port = endpoint._server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET /nonexistent HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            text = response.decode("utf-8")

            assert "404" in text

            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

    @pytest.mark.asyncio
    async def test_credential_detection_in_header(self) -> None:
        """Should detect a planted credential in the Authorization header."""
        routes = [{"path": "/", "method": "GET", "status": 200, "headers": {}, "body": ""}]
        events = []
        def capture(event):
            events.append(event)

        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=routes,
            server_header=None,
            protocol_banner=None,
            connection_callback=capture,
            credential_values={"secret-token-abc123"},
        )
        await endpoint.start()
        port = endpoint._server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret-token-abc123\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].credential_used == "secret-token-abc123"

    @pytest.mark.asyncio
    async def test_credential_detection_in_body(self) -> None:
        """Should detect a planted credential in the request body."""
        routes = [{"path": "/", "method": "POST", "status": 200, "headers": {}, "body": ""}]
        events = []
        def capture(event):
            events.append(event)

        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=routes,
            server_header=None,
            protocol_banner=None,
            connection_callback=capture,
            credential_values={"my-planted-password"},
        )
        await endpoint.start()
        port = endpoint._server.sockets[0].getsockname()[1]

        try:
            body = b'{"password": "my-planted-password"}'
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(
                f"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].credential_used == "my-planted-password"

    @pytest.mark.asyncio
    async def test_no_credential_when_not_matched(self) -> None:
        """Should report None credential when request doesn't contain planted creds."""
        routes = [{"path": "/", "method": "GET", "status": 200, "headers": {}, "body": ""}]
        events = []
        def capture(event):
            events.append(event)

        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=routes,
            server_header=None,
            protocol_banner=None,
            connection_callback=capture,
            credential_values={"super-secret-token"},
        )
        await endpoint.start()
        port = endpoint._server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].credential_used is None


class TestMimicEndpointBanner:
    """Verify banner-replay handler for non-HTTP ports."""

    @pytest.mark.asyncio
    async def test_sends_protocol_banner(self) -> None:
        """Endpoint should send the configured banner greeting."""
        events = []
        def capture(event):
            events.append(event)

        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[],
            server_header=None,
            protocol_banner="SSH-2.0-OpenSSH_8.9p1",
            connection_callback=capture,
            credential_values=set(),
        )
        await endpoint.start()
        port = endpoint._server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            data = await asyncio.wait_for(reader.read(512), timeout=5.0)
            text = data.decode("utf-8")

            assert "SSH-2.0-OpenSSH_8.9p1" in text

            # Send client data so the banner handler's read() completes
            writer.write(b"SSH-2.0-Client\r\n")
            await writer.drain()

            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

        # Give the handler time to invoke the callback
        await asyncio.sleep(0.05)
        assert len(events) == 1
        assert events[0].credential_used is None


class TestMimicDecoy:
    """Verify MimicDecoy lifecycle — multi-port multiplexing."""

    @pytest.mark.asyncio
    async def test_start_and_stop(self) -> None:
        """MimicDecoy should start and stop all endpoints."""
        decoy = MimicDecoy(
            decoy_id=1,
            name="Test Mimic",
            bind_address="127.0.0.1",
            port_configs=[
                {"port": 0, "routes": [{"path": "/", "method": "GET", "status": 200, "headers": {}, "body": "ok"}]},
            ],
        )
        await decoy.start()
        assert decoy.is_running
        assert await decoy.health_check()

        await decoy.stop()
        assert not decoy.is_running

    @pytest.mark.asyncio
    async def test_multiple_port_configs(self) -> None:
        """MimicDecoy should start an endpoint for each port config."""
        decoy = MimicDecoy(
            decoy_id=1,
            name="Multi-port Mimic",
            bind_address="127.0.0.1",
            port_configs=[
                {"port": 0, "routes": [{"path": "/", "method": "GET", "status": 200, "headers": {}, "body": "a"}]},
                {"port": 0, "protocol_banner": "SSH-2.0-Test"},
            ],
        )
        await decoy.start()
        try:
            assert len(decoy._endpoints) == 2
            assert decoy.is_running
        finally:
            await decoy.stop()

    @pytest.mark.asyncio
    async def test_primary_port_from_first_config(self) -> None:
        """The decoy's primary port should be from the first port config."""
        decoy = MimicDecoy(
            decoy_id=1,
            name="Port Test",
            bind_address="127.0.0.1",
            port_configs=[
                {"port": 8080, "routes": []},
                {"port": 22, "protocol_banner": "SSH"},
            ],
        )
        assert decoy.port == 8080

    def test_credential_values_extracted(self) -> None:
        """Credential values should be extracted from planted_credentials."""
        class FakeCred:
            credential_value = "token-xyz"

        decoy = MimicDecoy(
            decoy_id=1,
            name="Cred Test",
            bind_address="127.0.0.1",
            port_configs=[{"port": 80, "routes": []}],
            planted_credentials=[FakeCred()],
        )
        assert "token-xyz" in decoy._credential_values


class TestMimicEndpointPortRemap:
    """Verify that _MimicEndpoint binds on bind_port and advertises port."""

    @pytest.mark.asyncio
    async def test_bind_port_differs_from_advertised(self) -> None:
        """Endpoint should bind on bind_port but report advertised port in events."""
        events = []

        def capture(event):
            events.append(event)

        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=80,        # advertised port
            bind_port=0,    # OS-assigned for test
            routes=[{"path": "/", "method": "GET", "status": 200, "headers": {}, "body": "ok"}],
            server_header=None,
            protocol_banner=None,
            connection_callback=capture,
            credential_values=set(),
        )
        await endpoint.start()
        actual_port = endpoint._server.sockets[0].getsockname()[1]

        try:
            # The actual bind port should not be 80
            assert actual_port != 80

            reader, writer = await asyncio.open_connection("127.0.0.1", actual_port)
            writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

        # Connection event should report the advertised port (80), not the bind port
        assert len(events) == 1
        assert events[0].dest_port == 80

    @pytest.mark.asyncio
    async def test_default_bind_port_equals_port(self) -> None:
        """Without bind_port, it should default to port."""
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=9999,
            routes=[],
            server_header=None,
            protocol_banner="test",
            connection_callback=None,
            credential_values=set(),
        )
        assert endpoint.bind_port == 9999

    @pytest.mark.asyncio
    async def test_mimic_decoy_with_port_remaps(self) -> None:
        """MimicDecoy should use port_remaps for endpoint binding."""
        decoy = MimicDecoy(
            decoy_id=1,
            name="Remap Test",
            bind_address="127.0.0.1",
            port_configs=[
                {"port": 80, "routes": [{"path": "/", "method": "GET", "status": 200, "headers": {}, "body": "ok"}]},
            ],
            port_remaps={80: 0},  # OS-assigned for test
        )
        await decoy.start()
        try:
            assert decoy.is_running
            # The endpoint should have bound on port 0 (OS-assigned), not 80
            assert decoy._endpoints[0].port == 80
            assert decoy._endpoints[0].bind_port != 80
        finally:
            await decoy.stop()

    def test_port_remaps_property(self) -> None:
        """port_remaps property should return the configured remaps."""
        remaps = {80: 10080, 443: 10443}
        decoy = MimicDecoy(
            decoy_id=1,
            name="Remap Props",
            bind_address="127.0.0.1",
            port_configs=[{"port": 80, "routes": []}],
            port_remaps=remaps,
        )
        assert decoy.port_remaps == remaps

    def test_no_remaps_by_default(self) -> None:
        """Without port_remaps, the property should be empty."""
        decoy = MimicDecoy(
            decoy_id=1,
            name="No Remap",
            bind_address="127.0.0.1",
            port_configs=[{"port": 8080, "routes": []}],
        )
        assert decoy.port_remaps == {}


class TestStatusTexts:
    """Verify HTTP status text mapping."""

    @pytest.mark.parametrize("code,text", [
        (200, "OK"),
        (301, "Moved Permanently"),
        (404, "Not Found"),
        (500, "Internal Server Error"),
    ])
    def test_status_text_mapping(self, code: int, text: str) -> None:
        """Common status codes should have correct text."""
        assert _STATUS_TEXTS[code] == text
