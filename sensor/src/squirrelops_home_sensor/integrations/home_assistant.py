"""Home Assistant client for device and area registry data.

Uses the REST API for connectivity checks and the WebSocket API for
device/area registry queries (the registry is not exposed via REST).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass

import httpx
import websockets

logger = logging.getLogger(__name__)

_TIMEOUT = 5.0  # seconds


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HADevice:
    """A device from the Home Assistant device registry."""

    id: str
    name: str | None
    manufacturer: str | None
    model: str | None
    mac_addresses: frozenset[str]
    area_id: str | None


@dataclass(frozen=True)
class HAArea:
    """An area from the Home Assistant area registry."""

    id: str
    name: str


# ---------------------------------------------------------------------------
# Parse helpers
# ---------------------------------------------------------------------------


def parse_ha_devices(raw: list[dict]) -> list[HADevice]:
    """Parse HA device registry response.

    Only keeps devices that have at least one MAC connection.
    MAC addresses are normalized to lowercase.
    Devices without any MAC connections are skipped.
    """
    devices: list[HADevice] = []
    for entry in raw:
        connections = entry.get("connections", [])
        macs = frozenset(
            value.lower() for conn_type, value in connections if conn_type == "mac"
        )
        if not macs:
            continue
        devices.append(
            HADevice(
                id=entry["id"],
                name=entry.get("name"),
                manufacturer=entry.get("manufacturer"),
                model=entry.get("model"),
                mac_addresses=macs,
                area_id=entry.get("area_id"),
            )
        )
    return devices


def parse_ha_areas(raw: list[dict]) -> list[HAArea]:
    """Parse HA area registry response."""
    return [HAArea(id=entry["area_id"], name=entry["name"]) for entry in raw]


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class HomeAssistantClient:
    """Async client for Home Assistant.

    Uses HTTP REST for connectivity checks and WebSocket for registry queries.
    """

    def __init__(self, url: str, token: str) -> None:
        self._base_url = url.rstrip("/")
        self._token = token
        self._headers = {"Authorization": f"Bearer {token}"}
        # Derive ws:// URL from http:// URL
        self._ws_url = self._base_url.replace("http://", "ws://").replace("https://", "wss://")

    async def test_connection(self) -> bool:
        """Test connectivity to Home Assistant. Returns True if the API responds with 200."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self._base_url}/api/",
                    headers=self._headers,
                    timeout=_TIMEOUT,
                )
                return resp.status_code == 200
        except httpx.HTTPError:
            logger.debug("Home Assistant connection test failed", exc_info=True)
            return False

    async def _ws_command(self, command_type: str) -> list[dict]:
        """Send a WebSocket command and return the result list.

        Opens a short-lived WebSocket connection, authenticates, sends
        the command, and returns the result. Returns [] on any error.
        """
        try:
            async with asyncio.timeout(_TIMEOUT * 2):
                async with websockets.connect(
                    f"{self._ws_url}/api/websocket"
                ) as ws:
                    # Wait for auth_required
                    msg = json.loads(await ws.recv())
                    if msg.get("type") != "auth_required":
                        return []

                    # Authenticate
                    await ws.send(json.dumps({
                        "type": "auth",
                        "access_token": self._token,
                    }))
                    msg = json.loads(await ws.recv())
                    if msg.get("type") != "auth_ok":
                        logger.debug("HA WebSocket auth failed: %s", msg.get("type"))
                        return []

                    # Send command
                    await ws.send(json.dumps({
                        "id": 1,
                        "type": command_type,
                    }))
                    msg = json.loads(await ws.recv())
                    if msg.get("success"):
                        return msg.get("result", [])
                    logger.debug("HA WebSocket command %s failed", command_type)
                    return []
        except Exception:
            logger.debug("HA WebSocket command %s error", command_type, exc_info=True)
            return []

    async def get_devices(self) -> list[HADevice]:
        """Fetch device registry via WebSocket API."""
        raw = await self._ws_command("config/device_registry/list")
        return parse_ha_devices(raw)

    async def get_areas(self) -> list[HAArea]:
        """Fetch area registry via WebSocket API."""
        raw = await self._ws_command("config/area_registry/list")
        return parse_ha_areas(raw)
