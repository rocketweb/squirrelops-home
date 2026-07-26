"""Security invariants for development-only authentication paths."""

import aiosqlite
import pytest
from fastapi import FastAPI, HTTPException, Request

from squirrelops_home_sensor.api.deps import (
    get_db,
    is_loopback_client,
    verify_client_cert,
)


def test_only_literal_loopback_addresses_are_accepted() -> None:
    assert is_loopback_client("127.0.0.1")
    assert is_loopback_client("::1")
    assert not is_loopback_client("192.168.1.10")
    assert not is_loopback_client("localhost")
    assert not is_loopback_client("testclient")
    assert not is_loopback_client(None)


@pytest.mark.asyncio
async def test_tls_transport_cannot_use_bearer_when_scheme_is_downgraded() -> None:
    async with aiosqlite.connect(":memory:") as db:
        await db.execute(
            """CREATE TABLE pairing (
                   client_name TEXT NOT NULL,
                   client_cert_fingerprint TEXT NOT NULL,
                   is_local INTEGER NOT NULL
               )"""
        )
        await db.execute(
            """INSERT INTO pairing
               (client_name, client_cert_fingerprint, is_local)
               VALUES ('local-client', 'local-token', 1)"""
        )
        await db.commit()

        app = FastAPI()

        async def override_db():
            yield db

        app.dependency_overrides[get_db] = override_db
        request = Request({
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            # This is the spoofed value after trusted-proxy rewriting.
            "scheme": "http",
            "method": "GET",
            "path": "/devices",
            "raw_path": b"/devices",
            "query_string": b"",
            "headers": [
                (b"authorization", b"Bearer local-token"),
                (b"x-forwarded-proto", b"http"),
            ],
            "client": ("127.0.0.1", 50000),
            "server": ("127.0.0.1", 8443),
            "extensions": {"tls": {}},
            "app": app,
        })

        with pytest.raises(HTTPException) as exc_info:
            await verify_client_cert(request)

    assert exc_info.value.status_code == 403
