"""Adversarial limits for network-facing HTTP decoys."""

from __future__ import annotations

import base64
import http.client
import socket
import threading
import time
from typing import Any

import pytest

from clownpeanuts.services.http.emulator import MAX_REQUEST_BODY_BYTES, Emulator
from squirrelops_home_sensor.decoys.types.dev_server import DevServerDecoy
from squirrelops_home_sensor.decoys.types.file_share import FileShareDecoy
from squirrelops_home_sensor.decoys.types.home_assistant import HomeAssistantDecoy


def test_oversized_body_is_rejected_but_still_records_connection() -> None:
    callbacks: list[tuple[Any, ...]] = []
    callback_received = threading.Event()

    def record(*args: object) -> None:
        callbacks.append(args)
        callback_received.set()

    emulator = Emulator(
        routes=[{"path": "/submit", "method": "POST", "status": 200, "body": "ok"}],
        on_request=record,
    )
    emulator.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", emulator.port, timeout=5)
        connection.request("POST", "/submit", body=b"x" * (MAX_REQUEST_BODY_BYTES + 1))
        response = connection.getresponse()
        assert response.status == 413
        response.read()
        connection.close()
        assert callback_received.wait(timeout=1)
    finally:
        emulator.stop()

    assert len(callbacks) == 1
    assert callbacks[0][1:3] == ("POST", "/submit")
    assert callbacks[0][4] is None


def test_rejected_body_retains_headers_needed_for_credential_alerts() -> None:
    """Early body rejection must not downgrade a parsed credential trip."""
    callbacks: list[tuple[Any, ...]] = []
    callback_received = threading.Event()

    def record(*args: object) -> None:
        callbacks.append(args)
        callback_received.set()

    emulator = Emulator(
        routes=[{"path": "/login", "method": "POST", "status": 200, "body": "ok"}],
        on_request=record,
    )
    emulator.start()
    try:
        with socket.create_connection(
            ("127.0.0.1", emulator.port),
            timeout=5,
        ) as connection:
            connection.sendall(
                b"POST /login HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Authorization: Bearer planted-secret\r\n"
                + f"Content-Length: {MAX_REQUEST_BODY_BYTES + 1}\r\n\r\n".encode()
            )
            while connection.recv(8192):
                pass
        assert callback_received.wait(timeout=1)
    finally:
        emulator.stop()

    assert len(callbacks) == 1
    assert callbacks[0][1:3] == ("POST", "/login")
    assert callbacks[0][3] == {
        "Host": "localhost",
        "Authorization": "Bearer planted-secret",
        "Content-Length": str(MAX_REQUEST_BODY_BYTES + 1),
    }
    assert callbacks[0][4] is None


def test_header_section_cap_records_bounded_partial_metadata(monkeypatch) -> None:
    """Header parsing stops at the aggregate cap and still records the trip."""
    monkeypatch.setattr(
        "clownpeanuts.services.http.emulator.MAX_REQUEST_HEADER_SECTION_BYTES",
        96,
    )
    callbacks: list[tuple[Any, ...]] = []
    callback_received = threading.Event()

    def record(*args: object) -> None:
        callbacks.append(args)
        callback_received.set()

    emulator = Emulator(
        routes=[{"path": "/login", "method": "GET", "status": 200, "body": "ok"}],
        on_request=record,
    )
    emulator.start()
    try:
        with socket.create_connection(
            ("127.0.0.1", emulator.port),
            timeout=5,
        ) as connection:
            connection.sendall(
                b"GET /login HTTP/1.1\r\n"
                b"Authorization: Bearer planted-secret\r\n"
                b"X-Fill-One: 012345678901234567890123456789\r\n"
                b"X-Fill-Two: 012345678901234567890123456789\r\n\r\n"
            )
            try:
                while connection.recv(8192):
                    pass
            except ConnectionError:
                pass
        assert callback_received.wait(timeout=1)
    finally:
        emulator.stop()

    assert len(callbacks) == 1
    assert callbacks[0][1:3] == ("GET", "/login")
    assert callbacks[0][3]["Authorization"] == "Bearer planted-secret"


def test_oversized_request_line_still_records_connection() -> None:
    callbacks: list[tuple[Any, ...]] = []
    callback_received = threading.Event()

    def record(*args: object) -> None:
        callbacks.append(args)
        callback_received.set()

    emulator = Emulator(
        routes=[{"path": "/", "method": "GET", "status": 200, "body": "ok"}],
        on_request=record,
    )
    emulator.start()
    try:
        with socket.create_connection(
            ("127.0.0.1", emulator.port),
            timeout=5,
        ) as connection:
            connection.sendall(
                b"GET /" + (b"a" * (70 * 1024)) + b" HTTP/1.1\r\n\r\n"
            )
            connection.shutdown(socket.SHUT_WR)
            while connection.recv(8192):
                pass
        assert callback_received.wait(timeout=1)
    finally:
        emulator.stop()

    assert len(callbacks) == 1
    assert callbacks[0][4] is None


def test_malformed_absolute_target_cannot_suppress_connection_trip() -> None:
    """Invalid IPv6 URL syntax is bounded, rejected, and still recorded."""
    callbacks: list[tuple[Any, ...]] = []
    callback_received = threading.Event()

    def record(*args: object) -> None:
        callbacks.append(args)
        callback_received.set()

    emulator = Emulator(
        routes=[{"path": "/", "method": "GET", "status": 200, "body": "ok"}],
        on_request=record,
    )
    emulator.start()
    try:
        with socket.create_connection(
            ("127.0.0.1", emulator.port),
            timeout=5,
        ) as connection:
            connection.sendall(
                b"GET http://[x HTTP/1.1\r\nHost: localhost\r\n\r\n"
            )
            try:
                while connection.recv(8192):
                    pass
            except ConnectionError:
                pass
        assert callback_received.wait(timeout=1)
    finally:
        emulator.stop()

    assert len(callbacks) == 1
    assert callbacks[0][1:3] == ("GET", "http://[x")


@pytest.mark.parametrize(
    "raw_request",
    [
        b"",
        b"GET / HTTP/1.1\r\nMalformed-Header\r\n\r\n",
        b"BREW / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        (
            b"GET / HTTP/1.1\r\n"
            + b"".join(
                f"X-Field-{index}: value\r\n".encode()
                for index in range(101)
            )
            + b"\r\n"
        ),
        b"GET /" + (b"a" * 70_000) + b" HTTP/1.1\r\n\r\n",
    ],
    ids=["bare-eof", "malformed-header", "unsupported-method", "headers", "line"],
)
def test_stdlib_rejections_emit_exactly_one_classic_trip(raw_request: bytes) -> None:
    """Parser errors, unsupported methods, and bare connects remain visible."""
    callbacks: list[tuple[Any, ...]] = []
    callback_received = threading.Event()

    def record(*args: object) -> None:
        callbacks.append(args)
        callback_received.set()

    emulator = Emulator(
        routes=[{"path": "/", "method": "GET", "status": 200, "body": "ok"}],
        on_request=record,
    )
    emulator.start()
    try:
        with socket.create_connection(
            ("127.0.0.1", emulator.port),
            timeout=5,
        ) as connection:
            if raw_request:
                connection.sendall(raw_request)
            connection.shutdown(socket.SHUT_WR)
            assert callback_received.wait(timeout=1)
            try:
                while connection.recv(8192):
                    pass
            except OSError:
                pass
    finally:
        emulator.stop()

    assert len(callbacks) == 1


@pytest.mark.parametrize(
    "decoy_type",
    [HomeAssistantDecoy, DevServerDecoy],
)
def test_classic_decoys_match_authorization_header_case_insensitively(
    decoy_type,
) -> None:
    """HTTP field names are case-insensitive, including mixed-case forms."""
    decoy = object.__new__(decoy_type)
    decoy._credential_values = {"planted-secret"}

    detected = decoy._check_credential_in_request(
        {
            "aUtHoRiZaTiOn": "Bearer harmless",
            "AUTHORIZATION": "Bearer planted-secret",
        },
        None,
    )

    assert detected == "planted-secret"


def test_file_share_checks_each_duplicate_mixed_case_authorization_value() -> None:
    """Duplicate Authorization values cannot hide planted Basic credentials."""
    decoy = object.__new__(FileShareDecoy)
    decoy._credential_values = {"admin:planted-secret"}
    encoded = base64.b64encode(b"admin:planted-secret").decode()

    detected = decoy._check_credential_in_request(
        {
            "aUtHoRiZaTiOn": (
                f"Basic {encoded}\n"
                "Bearer harmless"
            ),
        },
        None,
    )

    assert detected == "admin:planted-secret"


@pytest.mark.parametrize("scheme", ["basic", "BASIC", "BaSiC"])
def test_file_share_basic_auth_scheme_is_case_insensitive(scheme: str) -> None:
    """HTTP authentication schemes are case-insensitive."""
    decoy = object.__new__(FileShareDecoy)
    decoy._credential_values = {"admin:planted-secret"}
    encoded = base64.b64encode(b"admin:planted-secret").decode()

    detected = decoy._check_credential_in_request(
        {"authorization": f"{scheme}\t{encoded}"},
        None,
    )

    assert detected == "admin:planted-secret"


def test_transfer_encoding_is_rejected() -> None:
    emulator = Emulator(
        routes=[{"path": "/submit", "method": "POST", "status": 200, "body": "ok"}]
    )
    emulator.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", emulator.port, timeout=5)
        connection.putrequest("POST", "/submit")
        connection.putheader("Transfer-Encoding", "chunked")
        connection.endheaders(b"1\r\nx\r\n0\r\n\r\n")
        response = connection.getresponse()
        assert response.status == 400
        connection.close()
    finally:
        emulator.stop()


def test_configured_banner_does_not_leak_python_http_server() -> None:
    emulator = Emulator(
        routes=[{
            "path": "/",
            "method": "GET",
            "status": 200,
            "headers": {"Server": "nginx/1.24.0"},
            "body": "ok",
        }]
    )
    emulator.start()
    try:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            emulator.port,
            timeout=5,
        )
        connection.request("GET", "/")
        response = connection.getresponse()
        server_headers = [
            value
            for name, value in response.getheaders()
            if name.casefold() == "server"
        ]
        response.read()
        connection.close()
    finally:
        emulator.stop()

    assert server_headers == ["nginx/1.24.0"]


def test_emulator_rebinds_immediately_after_restart() -> None:
    """Fast package upgrades must not strand decoys behind a TIME_WAIT socket."""
    routes = [{"path": "/", "method": "GET", "status": 200, "body": "ok"}]
    first = Emulator(routes=routes)
    first.start()
    port = first.port
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("GET", "/")
        response = connection.getresponse()
        assert response.status == 200
        response.read()
        connection.close()
    finally:
        first.stop()

    replacement = Emulator(port=port, routes=routes)
    try:
        replacement.start()
        assert replacement.is_alive()
    finally:
        replacement.stop()


def test_admission_drop_still_records_connection(monkeypatch) -> None:
    """A saturated decoy must alert before it drops a new connection."""
    monkeypatch.setattr(
        "clownpeanuts.services.http.emulator.MAX_CONCURRENT_REQUESTS",
        1,
    )
    callbacks: list[tuple[Any, ...]] = []
    callback_received = threading.Event()

    def record(*args: object) -> None:
        callbacks.append(args)
        callback_received.set()

    emulator = Emulator(
        routes=[{"path": "/", "method": "GET", "status": 200, "body": "ok"}],
        on_request=record,
    )
    emulator.start()
    first = socket.create_connection(("127.0.0.1", emulator.port), timeout=5)
    second: socket.socket | None = None
    try:
        first.sendall(b"GET / HTTP/1.1\r\nX-Hold: ")
        deadline = time.monotonic() + 1
        while (
            getattr(emulator._server._request_slots, "_value", 1) != 0
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)

        second = socket.create_connection(("127.0.0.1", emulator.port), timeout=5)
        second_port = second.getsockname()[1]
        assert callback_received.wait(timeout=1)
        assert any(
            callback[0][1] == second_port and callback[1] == "UNKNOWN"
            for callback in callbacks
        )
    finally:
        first.close()
        if second is not None:
            second.close()
        emulator.stop()


def test_slow_drip_request_has_absolute_deadline(monkeypatch) -> None:
    """Renewing the socket read timeout cannot hold a handler indefinitely."""
    monkeypatch.setattr(
        "clownpeanuts.services.http.emulator.REQUEST_TIMEOUT_SECONDS",
        0.1,
    )
    callbacks: list[tuple[Any, ...]] = []
    callback_received = threading.Event()

    def record(*args: object) -> None:
        callbacks.append(args)
        callback_received.set()

    emulator = Emulator(
        routes=[{"path": "/", "method": "GET", "status": 200, "body": "ok"}],
        on_request=record,
    )
    emulator.start()
    try:
        with socket.create_connection(
            ("127.0.0.1", emulator.port),
            timeout=5,
        ) as connection:
            connection.sendall(b"GET / HTTP/1.1\r\nX-Slow: ")
            started = time.monotonic()
            while time.monotonic() - started < 0.5:
                try:
                    connection.sendall(b"a")
                except OSError:
                    break
                time.sleep(0.02)
            assert callback_received.wait(timeout=0.5)
    finally:
        emulator.stop()

    assert len(callbacks) == 1
    assert callbacks[0][1:3] == ("GET", "/")


def test_partial_body_credential_survives_absolute_deadline(monkeypatch) -> None:
    """A stalled request retains its bounded body prefix for credential alerts."""
    monkeypatch.setattr(
        "clownpeanuts.services.http.emulator.REQUEST_TIMEOUT_SECONDS",
        0.1,
    )
    events = []
    callback_received = threading.Event()
    decoy = object.__new__(FileShareDecoy)
    decoy.port = 8080
    decoy._credential_values = {"admin:planted-secret"}

    def record_event(event) -> None:
        events.append(event)
        callback_received.set()

    decoy._on_connection = record_event
    emulator = Emulator(
        routes=[{
            "path": "/login",
            "method": "POST",
            "status": 200,
            "body": "ok",
        }],
        on_request=decoy._on_request,
    )
    emulator.start()
    try:
        with socket.create_connection(
            ("127.0.0.1", emulator.port),
            timeout=5,
        ) as connection:
            connection.sendall(
                b"POST /login HTTP/1.1\r\n"
                b"Content-Length: 1024\r\n\r\n"
                b"admin:planted-secret"
            )
            assert callback_received.wait(timeout=1)
    finally:
        emulator.stop()

    assert len(events) == 1
    assert events[0].request_path == "/login"
    assert events[0].credential_used == "admin:planted-secret"
