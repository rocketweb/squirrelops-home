"""Adversarial limits for network-facing HTTP decoys."""

from __future__ import annotations

import http.client

from clownpeanuts.services.http.emulator import MAX_REQUEST_BODY_BYTES, Emulator


def test_oversized_body_is_rejected_before_callback() -> None:
    callbacks: list[object] = []
    emulator = Emulator(
        routes=[{"path": "/submit", "method": "POST", "status": 200, "body": "ok"}],
        on_request=lambda *args: callbacks.append(args),
    )
    emulator.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", emulator.port, timeout=5)
        connection.request("POST", "/submit", body=b"x" * (MAX_REQUEST_BODY_BYTES + 1))
        response = connection.getresponse()
        assert response.status == 413
        assert callbacks == []
        connection.close()
    finally:
        emulator.stop()


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
