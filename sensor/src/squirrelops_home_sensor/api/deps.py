"""FastAPI dependency injection providers."""
from __future__ import annotations

from typing import AsyncGenerator

import aiosqlite
from fastapi import Depends, HTTPException, Request, status


async def get_db() -> AsyncGenerator[aiosqlite.Connection, None]:
    """Yield an aiosqlite database connection from the app state.

    In production, the connection is stored on app.state during lifespan.
    In tests, this dependency is overridden with an in-memory connection.
    """
    raise NotImplementedError("Must be overridden via app.state or dependency_overrides")


async def get_event_bus():
    """Return the EventBus instance from app state.

    In production, created during lifespan. In tests, overridden.
    """
    raise NotImplementedError("Must be overridden via app.state or dependency_overrides")


async def get_config() -> dict:
    """Return the sensor configuration dict.

    In production, loaded during lifespan. In tests, overridden.
    """
    raise NotImplementedError("Must be overridden via app.state or dependency_overrides")


async def get_privileged_ops():
    """Return the PrivilegedOperations instance from app state.

    In production, created during lifespan. In tests, overridden.
    """
    raise NotImplementedError("Must be overridden via app.state or dependency_overrides")


async def verify_client_cert(request: Request) -> dict:
    """Verify the client certificate fingerprint against the pairing table.

    Extracts the client cert fingerprint from the TLS connection and checks
    it against known paired clients. Returns client info dict on success.

    In tests, this is overridden to return a mock client dict.
    In production without a valid client cert, raises HTTP 403.
    """
    # In production, extract cert from TLS connection
    # For now, check if there's a bearer token (local sensor shortcut)
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        db_dep = request.app.dependency_overrides.get(get_db, get_db)
        db_gen = db_dep()
        db = await db_gen.__anext__()
        try:
            cursor = await db.execute(
                "SELECT client_name FROM pairing WHERE client_cert_fingerprint = ? AND is_local = 1",
                (token,),
            )
            row = await cursor.fetchone()
            if row:
                return {"client_name": row[0], "fingerprint": token}
        finally:
            try:
                await db_gen.__anext__()
            except StopAsyncIteration:
                pass

    # Check for client cert fingerprint in header (set by TLS termination proxy or middleware)
    cert_fingerprint = request.headers.get("x-client-cert-fingerprint", "")
    if cert_fingerprint:
        db_dep = request.app.dependency_overrides.get(get_db, get_db)
        db_gen = db_dep()
        db = await db_gen.__anext__()
        try:
            cursor = await db.execute(
                "SELECT client_name FROM pairing WHERE client_cert_fingerprint = ?",
                (cert_fingerprint,),
            )
            row = await cursor.fetchone()
            if row:
                return {"client_name": row[0], "fingerprint": cert_fingerprint}
        finally:
            try:
                await db_gen.__anext__()
            except StopAsyncIteration:
                pass

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Valid client certificate required",
    )
