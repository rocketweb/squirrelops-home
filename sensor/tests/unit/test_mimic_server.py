"""Tests for the async mimic server — lightweight HTTP runtime."""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import ssl
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from squirrelops_home_sensor.decoys.tls_identity import (
    generate_host_tls_identity,
    server_ssl_context,
)
from squirrelops_home_sensor.decoys.types import mimic as mimic_module
from squirrelops_home_sensor.decoys.types.mimic import (
    _STATUS_TEXTS,
    MimicDecoy,
    _MimicEndpoint,
)


def _encode_chunked_body(*chunks: bytes) -> bytes:
    encoded = bytearray()
    for chunk in chunks:
        encoded.extend(f"{len(chunk):X}\r\n".encode("ascii"))
        encoded.extend(chunk)
        encoded.extend(b"\r\n")
    encoded.extend(b"0\r\n\r\n")
    return bytes(encoded)


class TestMimicEndpointHTTP:
    """Verify HTTP request handling on a mimic endpoint."""

    @pytest.mark.asyncio
    async def test_records_connect_scanner_that_sends_no_http_request(self) -> None:
        """An accepted TCP connection is a trip even when the scanner closes immediately."""
        events = []

        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/",
                "method": "GET",
                "status": 200,
                "headers": {},
                "body": "ok",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values=set(),
        )
        await endpoint.start()
        port = endpoint._server.sockets[0].getsockname()[1]

        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()

            for _ in range(20):
                if events:
                    break
                await asyncio.sleep(0.01)
        finally:
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].dest_port == 0
        assert events[0].request_path is None

    @pytest.mark.asyncio
    async def test_admission_drop_still_records_connection(
        self,
        monkeypatch,
    ) -> None:
        """A saturated async endpoint alerts before closing excess work."""
        monkeypatch.setattr(mimic_module, "_MAX_CONCURRENT_CONNECTIONS", 1)
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/",
                "method": "GET",
                "status": 200,
                "headers": {},
                "body": "ok",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values=set(),
        )
        await endpoint.start()
        first_reader, first_writer = await asyncio.open_connection(
            "127.0.0.1",
            endpoint.bind_port,
        )
        del first_reader
        second_writer = None
        try:
            first_writer.write(b"GET / HTTP/1.1\r\nX-Hold: ")
            await first_writer.drain()
            for _ in range(50):
                if endpoint._active_connections == 1:
                    break
                await asyncio.sleep(0.01)
            assert endpoint._active_connections == 1

            second_reader, second_writer = await asyncio.open_connection(
                "127.0.0.1",
                endpoint.bind_port,
            )
            second_port = second_writer.get_extra_info("sockname")[1]
            await asyncio.wait_for(second_reader.read(), timeout=1)
            for _ in range(50):
                if any(event.source_port == second_port for event in events):
                    break
                await asyncio.sleep(0.01)
            assert any(event.source_port == second_port for event in events)
        finally:
            first_writer.close()
            await first_writer.wait_closed()
            if second_writer is not None:
                second_writer.close()
                await second_writer.wait_closed()
            await endpoint.stop()

    @pytest.mark.asyncio
    async def test_slow_headers_have_absolute_deadline(
        self,
        monkeypatch,
    ) -> None:
        """Header drips cannot renew the request lifetime indefinitely."""
        monkeypatch.setattr(
            mimic_module,
            "_HTTP_REQUEST_DEADLINE_SECONDS",
            0.08,
        )
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/",
                "method": "GET",
                "status": 200,
                "headers": {},
                "body": "must-not-serve",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values=set(),
        )
        await endpoint.start()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            endpoint.bind_port,
        )
        try:
            writer.write(b"GET / HTTP/1.1\r\n")
            await writer.drain()
            for index in range(30):
                await asyncio.sleep(0.01)
                try:
                    writer.write(f"X-Slow-{index}: value\r\n".encode())
                    await writer.drain()
                except (ConnectionError, RuntimeError):
                    break
            try:
                response = await asyncio.wait_for(reader.read(), timeout=1)
            except (ConnectionError, OSError):
                response = b""
        finally:
            writer.close()
            # The server deliberately aborts this expired connection. Waiting
            # for the peer-side close can replay its expected BrokenPipeError.
            writer.transport.abort()
            await endpoint.stop()

        assert b"must-not-serve" not in response
        assert len(events) == 1
        assert events[0].request_path == "/"

    @pytest.mark.asyncio
    async def test_records_oversized_request_line_as_connection_trip(self) -> None:
        """A parser limit violation must not suppress an accepted decoy connection."""
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/",
                "method": "GET",
                "status": 200,
                "headers": {},
                "body": "ok",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values=set(),
        )
        await endpoint.start()

        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                endpoint.bind_port,
            )
            writer.write(
                b"GET /"
                + (b"a" * (70 * 1024))
                + b" HTTP/1.1\r\nHost: localhost\r\n\r\n"
            )
            await writer.drain()
            await asyncio.wait_for(reader.read(), timeout=1.0)
            writer.close()
            await writer.wait_closed()
            for _ in range(20):
                if events:
                    break
                await asyncio.sleep(0.01)
        finally:
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].dest_port == 0
        assert events[0].request_path is None

    @pytest.mark.parametrize(
        "header_block",
        [
            b"".join(
                f"X-Field-{index}: value\r\n".encode("ascii")
                for index in range(101)
            ),
            b"X-Oversized-Line: " + (b"a" * (9 * 1024)) + b"\r\n",
            b"".join(
                f"X-Large-{index}: ".encode("ascii")
                + (b"a" * 1024)
                + b"\r\n"
                for index in range(40)
            ),
        ],
        ids=["field-count", "line-bytes", "section-bytes"],
    )
    @pytest.mark.asyncio
    async def test_rejects_bounded_header_limit_without_suppressing_trip(
        self,
        header_block: bytes,
    ) -> None:
        """Excess headers must stop parsing while preserving the trip signal."""
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/",
                "method": "GET",
                "status": 200,
                "headers": {},
                "body": "must-not-serve",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values=set(),
        )
        await endpoint.start()

        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                endpoint.bind_port,
            )
            writer.write(
                b"GET / HTTP/1.1\r\nHost: localhost\r\n"
                + header_block
                + b"\r\n"
            )
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), timeout=1.0)
            writer.close()
            await writer.wait_closed()
            for _ in range(20):
                if events:
                    break
                await asyncio.sleep(0.01)
        finally:
            await endpoint.stop()

        assert b"must-not-serve" not in response
        assert len(events) == 1
        assert events[0].request_path is None

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
    async def test_duplicate_authorization_cannot_downgrade_credential_trip(
        self,
    ) -> None:
        """Every bounded Authorization field remains visible to detection."""
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/",
                "method": "GET",
                "status": 200,
                "headers": {},
                "body": "",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values={"secret-token-abc123"},
        )
        await endpoint.start()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            endpoint.bind_port,
        )
        try:
            writer.write(
                b"GET / HTTP/1.1\r\n"
                b"Authorization: Bearer secret-token-abc123\r\n"
                b"aUtHoRiZaTiOn: Bearer harmless\r\n\r\n"
            )
            await writer.drain()
            await asyncio.wait_for(reader.read(), timeout=1)
        finally:
            writer.close()
            await writer.wait_closed()
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].credential_used == "secret-token-abc123"

    @pytest.mark.asyncio
    async def test_header_credential_survives_body_stall_deadline(
        self,
        monkeypatch,
    ) -> None:
        """A stalled declared body cannot downgrade a parsed header credential."""
        monkeypatch.setattr(
            mimic_module,
            "_HTTP_REQUEST_DEADLINE_SECONDS",
            0.1,
        )
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/",
                "method": "POST",
                "status": 200,
                "headers": {},
                "body": "",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values={"secret-token-abc123"},
        )
        await endpoint.start()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            endpoint.bind_port,
        )
        try:
            writer.write(
                b"POST /login HTTP/1.1\r\n"
                b"Authorization: Bearer secret-token-abc123\r\n"
                b"Content-Length: 1024\r\n\r\n"
            )
            await writer.drain()
            await asyncio.wait_for(reader.read(), timeout=1)
        finally:
            writer.close()
            await writer.wait_closed()
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].request_path == "/login"
        assert events[0].credential_used == "secret-token-abc123"

    @pytest.mark.asyncio
    async def test_body_credential_survives_body_stall_deadline(
        self,
        monkeypatch,
    ) -> None:
        """A bounded body prefix remains detectable when framing never completes."""
        monkeypatch.setattr(
            mimic_module,
            "_HTTP_REQUEST_DEADLINE_SECONDS",
            0.1,
        )
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/",
                "method": "POST",
                "status": 200,
                "headers": {},
                "body": "",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values={"secret-token-abc123"},
        )
        await endpoint.start()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            endpoint.bind_port,
        )
        try:
            writer.write(
                b"POST /login HTTP/1.1\r\n"
                b"Content-Length: 1024\r\n\r\n"
                b"secret-token-abc123"
            )
            await writer.drain()
            await asyncio.wait_for(reader.read(), timeout=1)
        finally:
            writer.close()
            await writer.wait_closed()
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].request_path == "/login"
        assert events[0].credential_used == "secret-token-abc123"

    @pytest.mark.asyncio
    async def test_credential_trip_is_recorded_before_response_io(
        self,
        monkeypatch,
    ) -> None:
        """A peer that stops reading cannot downgrade a parsed credential."""
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/",
                "method": "GET",
                "status": 200,
                "headers": {},
                "body": "response",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values={"secret-token-abc123"},
        )
        observed_before_send = False

        async def fail_response_io(writer, route) -> None:
            nonlocal observed_before_send
            del writer, route
            observed_before_send = (
                len(events) == 1
                and events[0].credential_used == "secret-token-abc123"
            )
            raise BrokenPipeError

        monkeypatch.setattr(endpoint, "_send_response", fail_response_io)
        await endpoint.start()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            endpoint.bind_port,
        )
        try:
            writer.write(
                b"GET / HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Authorization: Bearer secret-token-abc123\r\n\r\n"
            )
            await writer.drain()
            try:
                await asyncio.wait_for(reader.read(), timeout=1)
            except (ConnectionError, OSError):
                pass
        finally:
            writer.close()
            writer.transport.abort()
            await endpoint.stop()

        assert observed_before_send is True
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
    async def test_detects_canonical_password_pair_in_basic_auth(self) -> None:
        """A real Basic login should resolve to the stored username:password value."""
        canonical_credential = "operator:QuietRiver42!"
        encoded_credential = base64.b64encode(
            canonical_credential.encode("utf-8")
        ).decode("ascii")
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/login",
                "method": "POST",
                "status": 401,
                "headers": {},
                "body": "",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values={canonical_credential},
        )
        await endpoint.start()

        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                endpoint.bind_port,
            )
            request = (
                "POST /login HTTP/1.1\r\n"
                "Host: localhost\r\n"
                f"Authorization: Basic {encoded_credential}\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
            )
            writer.write(request.encode("ascii"))
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].credential_used == canonical_credential

    @pytest.mark.parametrize("separator", ["   ", "\t", " \t "])
    @pytest.mark.asyncio
    async def test_basic_auth_accepts_http_whitespace(
        self,
        separator: str,
    ) -> None:
        """Basic credentials may follow the scheme after one or more SP/HTAB."""
        canonical_credential = "operator:QuietRiver42!"
        encoded_credential = base64.b64encode(
            canonical_credential.encode("utf-8")
        ).decode("ascii")
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/login",
                "method": "POST",
                "status": 401,
                "headers": {},
                "body": "",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values={canonical_credential},
        )
        await endpoint.start()

        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                endpoint.bind_port,
            )
            request = (
                "POST /login HTTP/1.1\r\n"
                "Host: localhost\r\n"
                f"Authorization: Basic{separator}{encoded_credential}\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
            )
            writer.write(request.encode("ascii"))
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].credential_used == canonical_credential

    @pytest.mark.asyncio
    async def test_detects_canonical_password_pair_in_urlencoded_form(self) -> None:
        """A normal login form should resolve its fields to the stored pair."""
        canonical_credential = "admin:Blue&Gold=7!"
        body = b"username=admin&password=Blue%26Gold%3D7%21"
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/login",
                "method": "POST",
                "status": 200,
                "headers": {},
                "body": "",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values={canonical_credential},
        )
        await endpoint.start()

        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                endpoint.bind_port,
            )
            request_headers = (
                "POST /login HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                "\r\n"
            )
            writer.write(request_headers.encode("ascii") + body)
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].credential_used == canonical_credential

    @pytest.mark.asyncio
    async def test_detects_urlencoded_login_split_across_tcp_reads(self) -> None:
        """Credential parsing should wait for the complete declared request body."""
        canonical_credential = "admin:BlueSecret"
        body_start = b"username=admin&password=Blue"
        body_end = b"Secret"
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/login",
                "method": "POST",
                "status": 200,
                "headers": {},
                "body": "",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values={canonical_credential},
        )
        await endpoint.start()

        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                endpoint.bind_port,
            )
            request_headers = (
                "POST /login HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body_start) + len(body_end)}\r\n"
                "\r\n"
            )
            writer.write(request_headers.encode("ascii") + body_start)
            await writer.drain()
            await asyncio.sleep(0.02)
            writer.write(body_end)
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].credential_used == canonical_credential

    @pytest.mark.asyncio
    async def test_does_not_parse_truncated_oversized_urlencoded_body(self) -> None:
        """The bounded prefix of an oversized form must not become a login."""
        body = (
            b"username=admin&password=secret&padding="
            + b"x" * 4096
        )
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/login",
                "method": "POST",
                "status": 200,
                "headers": {},
                "body": "",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values={"admin:secret"},
        )
        await endpoint.start()

        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                endpoint.bind_port,
            )
            request_headers = (
                "POST /login HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\n"
                "\r\n"
            )
            writer.write(request_headers.encode("ascii") + body)
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].credential_used is None

    @pytest.mark.asyncio
    async def test_detects_canonical_password_pair_in_json_login(self) -> None:
        """A JSON login should resolve its fields to the stored pair."""
        canonical_credential = 'deploy:Strong "quoted" password'
        body = json.dumps(
            {
                "username": "deploy",
                "password": 'Strong "quoted" password',
            },
            separators=(",", ":"),
        ).encode("utf-8")
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/api/login",
                "method": "POST",
                "status": 200,
                "headers": {},
                "body": "",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values={canonical_credential},
        )
        await endpoint.start()

        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                endpoint.bind_port,
            )
            request_headers = (
                "POST /api/login HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                "\r\n"
            )
            writer.write(request_headers.encode("ascii") + body)
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].credential_used == canonical_credential

    @pytest.mark.parametrize(
        ("content_type", "canonical_credential", "chunks"),
        [
            (
                "application/x-www-form-urlencoded",
                "admin:Blue&Gold=7!",
                (
                    b"username=admin&password=",
                    b"Blue%26Gold%3D7%21",
                ),
            ),
            (
                "application/json",
                "deploy:StrongPassword",
                (
                    b'{"username":"deploy",',
                    b'"password":"StrongPassword"}',
                ),
            ),
        ],
        ids=["form", "json"],
    )
    @pytest.mark.asyncio
    async def test_detects_chunked_structured_login(
        self,
        content_type: str,
        canonical_credential: str,
        chunks: tuple[bytes, ...],
    ) -> None:
        """Complete bounded chunked bodies should use the normal login parser."""
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/login",
                "method": "POST",
                "status": 200,
                "headers": {},
                "body": "",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values={canonical_credential},
        )
        await endpoint.start()
        wire_body = _encode_chunked_body(*chunks)

        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                endpoint.bind_port,
            )
            request_headers = (
                "POST /login HTTP/1.1\r\n"
                "Host: localhost\r\n"
                f"Content-Type: {content_type}\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
            )
            writer.write(request_headers.encode("ascii") + wire_body)
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].credential_used == canonical_credential

    @pytest.mark.asyncio
    async def test_chunked_reader_accepts_bounded_trailer(self) -> None:
        """A well-formed small trailer should complete chunked framing."""
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[],
            server_header=None,
            protocol_banner=None,
            connection_callback=None,
            credential_values=set(),
        )
        reader = asyncio.StreamReader()
        wire_body = _encode_chunked_body(b"username=admin")
        reader.feed_data(
            wire_body[:-2] + b"X-Trace: safe\r\n\r\n"
        )
        reader.feed_eof()

        body, complete = await endpoint._read_chunked_body(reader)

        assert complete is True
        assert body == b"username=admin"

    @pytest.mark.parametrize(
        "wire_body",
        [
            b"not-hex\r\nusername=admin&password=secret\r\n0\r\n\r\n",
            b"1001\r\n",
            b"40\r\nusername=admin&password=secret",
        ],
        ids=["malformed", "oversized", "truncated"],
    )
    @pytest.mark.asyncio
    async def test_rejects_invalid_chunked_login_without_hanging(
        self,
        wire_body: bytes,
    ) -> None:
        """Invalid chunks must not become structured credentials or stall."""
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/login",
                "method": "POST",
                "status": 200,
                "headers": {},
                "body": "",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values={"admin:secret"},
        )
        await endpoint.start()

        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                endpoint.bind_port,
            )
            request_headers = (
                "POST /login HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
            )
            writer.write(request_headers.encode("ascii") + wire_body)
            await writer.drain()
            if writer.can_write_eof():
                writer.write_eof()
            await asyncio.wait_for(reader.read(4096), timeout=0.5)
            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].credential_used is None

    @pytest.mark.parametrize(
        "framing_headers",
        [
            "Transfer-Encoding: chunked\r\nContent-Length: 44\r\n",
            "Transfer-Encoding: gzip\r\n",
            "Transfer-Encoding: gzip, chunked\r\n",
        ],
        ids=["ambiguous", "unsupported", "multiple-codings"],
    )
    @pytest.mark.asyncio
    async def test_rejects_ambiguous_or_unsupported_body_framing(
        self,
        framing_headers: str,
    ) -> None:
        """Only an unambiguous single chunked coding may be parsed."""
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[{
                "path": "/login",
                "method": "POST",
                "status": 200,
                "headers": {},
                "body": "",
            }],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values={"admin:secret"},
        )
        await endpoint.start()
        wire_body = _encode_chunked_body(
            b"username=admin&password=secret",
        )

        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                endpoint.bind_port,
            )
            request_headers = (
                "POST /login HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                f"{framing_headers}"
                "\r\n"
            )
            writer.write(request_headers.encode("ascii") + wire_body)
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), timeout=0.5)
            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].credential_used is None

    def test_structured_credential_detection_requires_supported_content_type(self) -> None:
        """Separated fields in arbitrary text must not be treated as a login."""
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[],
            server_header=None,
            protocol_banner=None,
            connection_callback=None,
            credential_values={"admin:secret"},
        )

        result = endpoint._check_credentials(
            {"content-type": "text/plain"},
            "username=admin&password=secret",
        )

        assert result is None

    def test_structured_credential_detection_rejects_oversized_body(self) -> None:
        """Structured parsing must remain bounded even for direct callers."""
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=0,
            routes=[],
            server_header=None,
            protocol_banner=None,
            connection_callback=None,
            credential_values={"admin:secret"},
        )
        body = json.dumps({
            "username": "admin",
            "password": "secret",
            "padding": "x" * 4096,
        })

        result = endpoint._check_credentials(
            {"content-type": "application/json"},
            body,
        )

        assert result is None

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
    async def test_unexpected_banner_io_failure_still_records_trip(self) -> None:
        """An attacker-triggered handler failure must not suppress detection."""
        events = []
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=2222,
            routes=[],
            server_header=None,
            protocol_banner="SSH-2.0-Test",
            connection_callback=events.append,
            credential_values=set(),
        )
        reader = MagicMock()
        writer = MagicMock()
        writer.get_extra_info.return_value = ("192.0.2.10", 49152)
        writer.drain = AsyncMock(side_effect=ValueError("injected write failure"))
        writer.wait_closed = AsyncMock()

        await endpoint._handle_banner(reader, writer)

        assert len(events) == 1
        assert events[0].source_ip == "192.0.2.10"
        assert events[0].source_port == 49152
        assert events[0].dest_port == 2222
        assert events[0].credential_used is None

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


class TestMimicEndpointTLS:
    """Verify TLS endpoints have a fake-host identity and no HTTP downgrade."""

    @pytest.mark.asyncio
    async def test_tls_serves_exact_fake_host_certificate(self) -> None:
        cert_pem, key_pem = generate_host_tls_identity(
            "camera-test.local",
            "127.0.0.1",
        )
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=443,
            bind_port=0,
            routes=[
                {
                    "path": "/",
                    "method": "GET",
                    "status": 200,
                    "headers": {},
                    "body": "secure",
                }
            ],
            server_header=None,
            protocol_banner=None,
            connection_callback=None,
            credential_values=set(),
            ssl_context=server_ssl_context(cert_pem, key_pem),
            advertised_hostname="camera-test.local",
        )
        await endpoint.start()
        client_context = ssl.create_default_context()
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                endpoint.bind_port,
                ssl=client_context,
                server_hostname="camera-test.local",
            )
            ssl_object = writer.get_extra_info("ssl_object")
            cert = x509.load_der_x509_certificate(
                ssl_object.getpeercert(binary_form=True)
            )
            san = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
            assert san.get_values_for_type(x509.DNSName) == [
                "camera-test.local"
            ]
            assert san.get_values_for_type(x509.IPAddress) == [
                ipaddress.ip_address("127.0.0.1")
            ]

            writer.write(
                b"GET / HTTP/1.1\r\nHost: camera-test.local\r\n\r\n"
            )
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), timeout=5.0)
            assert b"HTTP/1.1 200 OK" in response
            assert response.endswith(b"secure")
            writer.close()
            await writer.wait_closed()
        finally:
            await endpoint.stop()

    @pytest.mark.asyncio
    async def test_tls_port_rejects_plaintext_and_records_trip(self) -> None:
        events = []
        cert_pem, key_pem = generate_host_tls_identity(
            "camera-test.local",
            "127.0.0.1",
        )
        endpoint = _MimicEndpoint(
            bind_ip="127.0.0.1",
            port=443,
            bind_port=0,
            routes=[
                {
                    "path": "/",
                    "method": "GET",
                    "status": 200,
                    "headers": {},
                    "body": "must-not-leak",
                }
            ],
            server_header=None,
            protocol_banner=None,
            connection_callback=events.append,
            credential_values=set(),
            ssl_context=server_ssl_context(cert_pem, key_pem),
            advertised_hostname="camera-test.local",
        )
        await endpoint.start()

        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                endpoint.bind_port,
            )
            writer.write(
                b"GET / HTTP/1.1\r\nHost: camera-test.local\r\n\r\n"
            )
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), timeout=5.0)
            assert b"HTTP/" not in response
            assert b"must-not-leak" not in response
            writer.close()
            await writer.wait_closed()
            for _ in range(20):
                if events:
                    break
                await asyncio.sleep(0.01)
        finally:
            await endpoint.stop()

        assert len(events) == 1
        assert events[0].dest_port == 443
        assert events[0].request_path is None


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
    async def test_start_rolls_back_when_any_endpoint_cannot_bind(self) -> None:
        """A mimic must never remain partially active after a bind failure."""
        blocker = await asyncio.start_server(
            lambda _reader, writer: writer.close(), "127.0.0.1", 0,
        )
        blocked_port = blocker.sockets[0].getsockname()[1]
        decoy = MimicDecoy(
            decoy_id=1,
            name="Atomic Mimic",
            bind_address="127.0.0.1",
            port_configs=[
                {"port": 0, "protocol_banner": "first"},
                {"port": blocked_port, "protocol_banner": "blocked"},
            ],
        )

        try:
            with pytest.raises(OSError):
                await decoy.start()
        finally:
            blocker.close()
            await blocker.wait_closed()

        assert decoy._endpoints == []
        assert not decoy.is_running
        assert not await decoy.health_check()

    @pytest.mark.asyncio
    async def test_empty_endpoint_configuration_cannot_start(self) -> None:
        """A zero-endpoint mimic cannot be reported as deployed."""
        decoy = MimicDecoy(
            decoy_id=1,
            name="Empty Mimic",
            bind_address="127.0.0.1",
            port_configs=[],
        )

        with pytest.raises(RuntimeError, match="no configured endpoints"):
            await decoy.start()

        assert not decoy.is_running
        assert not await decoy.health_check()

    @pytest.mark.asyncio
    async def test_health_requires_every_endpoint(self) -> None:
        """One failed advertised service makes the whole mimic unhealthy."""
        decoy = MimicDecoy(
            decoy_id=1,
            name="All-or-nothing Mimic",
            bind_address="127.0.0.1",
            port_configs=[
                {"port": 0, "protocol_banner": "first"},
                {"port": 0, "protocol_banner": "second"},
            ],
        )
        await decoy.start()
        try:
            await decoy._endpoints[0].stop()
            assert not decoy.is_running
            assert not await decoy.health_check()
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
            # The endpoint should have bound on an OS-assigned port, not 80,
            # and expose that concrete port to the PF lifecycle.
            assert decoy._endpoints[0].port == 80
            assert decoy._endpoints[0].bind_port != 80
            assert decoy.port_remaps == {
                80: decoy._endpoints[0].bind_port,
            }
            assert decoy.port_remaps[80] > 0
        finally:
            await decoy.stop()

    @pytest.mark.asyncio
    async def test_dynamic_backend_avoids_wildcard_listener_collision(
        self,
    ) -> None:
        """A host wildcard listener must not prevent a mimic deployment."""
        blocker = await asyncio.start_server(
            lambda _reader, writer: writer.close(),
            "0.0.0.0",
            0,
        )
        advertised_port = blocker.sockets[0].getsockname()[1]
        decoy = MimicDecoy(
            decoy_id=1,
            name="Wildcard-safe Mimic",
            bind_address="127.0.0.1",
            port_configs=[
                {"port": advertised_port, "protocol_banner": "safe"},
            ],
            port_remaps={advertised_port: 0},
        )

        try:
            await decoy.start()
            backend_port = decoy.port_remaps[advertised_port]
            assert backend_port not in {0, advertised_port}
            assert decoy.is_running
        finally:
            await decoy.stop()
            blocker.close()
            await blocker.wait_closed()

    @pytest.mark.asyncio
    async def test_dynamic_backends_are_unique_and_not_advertised(
        self,
    ) -> None:
        advertised = {80, 443, 8443}
        decoy = MimicDecoy(
            decoy_id=1,
            name="All-redirected Mimic",
            bind_address="127.0.0.1",
            port_configs=[
                {"port": port, "protocol_banner": f"service-{port}"}
                for port in sorted(advertised)
            ],
            port_remaps={port: 0 for port in advertised},
        )

        await decoy.start()
        try:
            backends = set(decoy.port_remaps.values())
            assert len(backends) == len(advertised)
            assert 0 not in backends
            assert backends.isdisjoint(advertised)
        finally:
            await decoy.stop()

    @pytest.mark.asyncio
    async def test_partial_dynamic_start_resets_runtime_mapping(
        self,
    ) -> None:
        blocker = await asyncio.start_server(
            lambda _reader, writer: writer.close(),
            "127.0.0.1",
            0,
        )
        blocked_port = blocker.sockets[0].getsockname()[1]
        decoy = MimicDecoy(
            decoy_id=1,
            name="Dynamic rollback Mimic",
            bind_address="127.0.0.1",
            port_configs=[
                {"port": 80, "protocol_banner": "first"},
                {"port": blocked_port, "protocol_banner": "blocked"},
            ],
            port_remaps={80: 0, blocked_port: blocked_port},
        )

        try:
            with pytest.raises(OSError):
                await decoy.start()
        finally:
            blocker.close()
            await blocker.wait_closed()

        assert decoy._endpoints == []
        assert decoy.port_remaps == {80: 0, blocked_port: blocked_port}

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
