"""WebSocket endpoint: auth, subscribe, replay from sequence, live events, keepalive."""
from __future__ import annotations

import asyncio
import json
import time
from typing import Optional

import aiosqlite
from fastapi import APIRouter
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState

router = APIRouter(tags=["websocket"])

# Keepalive constants
PING_INTERVAL_SECONDS = 30
MAX_MISSED_PONGS = 3
AUTH_TIMEOUT_SECONDS = 10


class WebSocketClient:
    """Represents a connected, authenticated WebSocket client."""

    def __init__(self, ws: WebSocket, client_name: str, fingerprint: str):
        self.ws = ws
        self.client_name = client_name
        self.fingerprint = fingerprint
        self.last_pong: float = time.time()
        self.missed_pongs: int = 0

    async def send_event(self, seq: int, event_type: str, payload: dict) -> bool:
        """Send an event to the client. Returns False if send fails."""
        try:
            await self.ws.send_json({
                "type": "event",
                "seq": seq,
                "event_type": event_type,
                "payload": payload,
            })
            return True
        except Exception:
            return False


# Module-level set of connected clients
_connected_clients: set[WebSocketClient] = set()


async def broadcast_event(seq: int, event_type: str, payload: dict) -> None:
    """Broadcast an event to all connected WebSocket clients."""
    disconnected = []
    for client in list(_connected_clients):
        success = await client.send_event(seq, event_type, payload)
        if not success:
            disconnected.append(client)
    for client in disconnected:
        _connected_clients.discard(client)


async def _authenticate(
    ws: WebSocket, db: aiosqlite.Connection
) -> Optional[tuple[str, str]]:
    """Wait for auth frame and validate. Returns (client_name, fingerprint) or None."""
    try:
        raw = await asyncio.wait_for(ws.receive_json(), timeout=AUTH_TIMEOUT_SECONDS)
    except (asyncio.TimeoutError, WebSocketDisconnect):
        return None

    msg_type = raw.get("type")

    if msg_type != "auth":
        await ws.send_json({
            "type": "auth_error",
            "reason": "First message must be an auth frame.",
        })
        return None

    # Check cert fingerprint
    fingerprint = raw.get("cert_fingerprint")
    token = raw.get("token")

    if fingerprint:
        cursor = await db.execute(
            "SELECT client_name FROM pairing WHERE client_cert_fingerprint = ?",
            (fingerprint,),
        )
        row = await cursor.fetchone()
        if row:
            return row[0], fingerprint

    if token:
        cursor = await db.execute(
            "SELECT client_name FROM pairing WHERE client_cert_fingerprint = ? AND is_local = 1",
            (token,),
        )
        row = await cursor.fetchone()
        if row:
            return row[0], token

    await ws.send_json({
        "type": "auth_error",
        "reason": "Invalid credentials.",
    })
    return None


async def _replay_events(
    ws: WebSocket, db: aiosqlite.Connection, since_seq: int
) -> None:
    """Replay events with seq > since_seq, then send replay_complete."""
    cursor = await db.execute(
        "SELECT seq, event_type, payload, created_at FROM events WHERE seq > ? ORDER BY seq",
        (since_seq,),
    )
    rows = await cursor.fetchall()

    # Columns: seq(0), event_type(1), payload(2), created_at(3)
    last_seq = since_seq
    for row in rows:
        payload = row[2]
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except (json.JSONDecodeError, TypeError):
                pass

        await ws.send_json({
            "type": "event",
            "seq": row[0],
            "event_type": row[1],
            "payload": payload,
        })
        last_seq = row[0]

    if not rows and since_seq == 0:
        # Check if there are any events at all
        cursor = await db.execute("SELECT MAX(seq) FROM events")
        max_row = await cursor.fetchone()
        if max_row and max_row[0] is not None:
            last_seq = max_row[0]

    await ws.send_json({
        "type": "replay_complete",
        "last_seq": last_seq,
    })


async def _keepalive_loop(client: WebSocketClient) -> None:
    """Send pings every PING_INTERVAL_SECONDS. Close after MAX_MISSED_PONGS."""
    while True:
        await asyncio.sleep(PING_INTERVAL_SECONDS)
        try:
            await client.ws.send_json({"type": "ping"})
            client.missed_pongs += 1
            if client.missed_pongs >= MAX_MISSED_PONGS:
                await client.ws.close()
                return
        except Exception:
            return


@router.websocket("/ws/events")
async def ws_events(ws: WebSocket):
    """WebSocket endpoint for real-time event streaming.

    Protocol:
    1. Client connects
    2. Client sends auth frame: {"type":"auth","cert_fingerprint":"sha256:..."}
    3. Server validates -> auth_ok or auth_error+close
    4. Client optionally sends: {"type":"replay","since_seq":N}
    5. Server replays missed events -> replay_complete
    6. Live event streaming begins
    7. Keepalive: server pings every 30s, client pongs, 3 missed = close
    """
    await ws.accept()

    # Get DB from app state dependency -- we need direct access here since
    # WebSocket endpoints don't use standard FastAPI dependency injection the same way.
    # In tests, the app has dependency_overrides; we call the override directly.
    from squirrelops_home_sensor.api.deps import get_db

    db_dep = ws.app.dependency_overrides.get(get_db, get_db)

    # Handle both generator and direct-return overrides
    db = None
    db_gen = None
    result = db_dep()
    if hasattr(result, "__anext__"):
        db_gen = result
        db = await result.__anext__()
    else:
        db = await result

    try:
        # Step 1: Authenticate
        auth_result = await _authenticate(ws, db)
        if auth_result is None:
            try:
                await ws.close()
            except Exception:
                pass
            return

        client_name, fingerprint = auth_result
        await ws.send_json({"type": "auth_ok"})

        # Create client and register
        client = WebSocketClient(ws, client_name, fingerprint)
        _connected_clients.add(client)

        # Start keepalive task
        keepalive_task = asyncio.create_task(_keepalive_loop(client))

        try:
            # Step 2: Listen for client messages (replay requests, pongs)
            while True:
                try:
                    raw = await ws.receive_json()
                except WebSocketDisconnect:
                    break

                msg_type = raw.get("type")

                if msg_type == "replay":
                    since_seq = raw.get("since_seq", 0)
                    await _replay_events(ws, db, since_seq)

                elif msg_type == "pong":
                    client.missed_pongs = 0
                    client.last_pong = time.time()

                # Other message types are silently ignored

        finally:
            keepalive_task.cancel()
            _connected_clients.discard(client)

    finally:
        # Clean up DB generator if applicable
        if db_gen is not None:
            try:
                await db_gen.__anext__()
            except (StopAsyncIteration, Exception):
                pass
