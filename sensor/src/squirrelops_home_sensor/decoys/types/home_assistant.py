"""Home Assistant decoy — mimics an HA instance login page and API.

Wraps the ClownPeanuts Emulator with Home Assistant-like routes. Inspects
Authorization headers and POST bodies for planted HA tokens.

Routes:
    GET /           — Home Assistant login page (HTML)
    GET /api/       — 401 Unauthorized with JSON error
    POST /auth/token — Rejects all authentication attempts
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from clownpeanuts.services.http.emulator import Emulator
from clownpeanuts.tarpit.throttle import AdaptiveThrottle

from squirrelops_home_sensor.decoys.credentials import GeneratedCredential
from squirrelops_home_sensor.decoys.types.base import BaseDecoy, DecoyConnectionEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HTML / JSON templates
# ---------------------------------------------------------------------------

_HA_LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head>
  <title>Home Assistant</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: Roboto, sans-serif; margin: 0; background: #111; color: #fff; }
    .login { max-width: 400px; margin: 100px auto; padding: 24px; }
    h1 { font-size: 24px; margin-bottom: 8px; }
    .subtitle { color: #aaa; margin-bottom: 32px; }
    input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #333;
            background: #222; color: #fff; border-radius: 4px; box-sizing: border-box; }
    button { width: 100%; padding: 12px; background: #03a9f4; color: #fff;
             border: none; border-radius: 4px; cursor: pointer; margin-top: 16px; }
  </style>
</head>
<body>
  <div class="login">
    <h1>Home Assistant</h1>
    <p class="subtitle">Log in to continue</p>
    <form method="POST" action="/auth/token">
      <input type="text" name="username" placeholder="Username" autocomplete="username">
      <input type="password" name="password" placeholder="Password" autocomplete="current-password">
      <button type="submit">Log in</button>
    </form>
    <p style="font-size: 12px; color: #666; margin-top: 24px;">
      Home Assistant 2024.1.0 &bull; hass.local
    </p>
  </div>
</body>
</html>"""

_API_UNAUTHORIZED = json.dumps({"message": "Invalid access token or password"})

_AUTH_REJECTED = json.dumps({"error": "invalid_grant", "error_description": "Invalid credentials"})


class HomeAssistantDecoy(BaseDecoy):
    """Home Assistant decoy service.

    Uses ClownPeanuts Emulator for the HTTP server. Inspects Authorization
    headers and POST bodies for planted HA long-lived access tokens.

    Args:
        decoy_id: Unique identifier for this decoy instance.
        name: Human-readable name for display.
        port: TCP port to listen on (0 = OS-assigned).
        bind_address: IP address to bind to.
        planted_credentials: List of credentials to detect.
    """

    def __init__(
        self,
        decoy_id: int,
        name: str,
        port: int,
        bind_address: str = "127.0.0.1",
        planted_credentials: Optional[list[GeneratedCredential]] = None,
    ) -> None:
        super().__init__(
            decoy_id=decoy_id,
            name=name,
            port=port,
            bind_address=bind_address,
            decoy_type="home_assistant",
        )
        self._planted_credentials = planted_credentials or []
        self._emulator: Optional[Emulator] = None
        self._running = False

        # Build credential lookup set
        self._credential_values: set[str] = {
            c.credential_value for c in self._planted_credentials
        }

    def _build_routes(self) -> list[dict]:
        """Build ClownPeanuts route configuration for HA endpoints."""
        return [
            {
                "path": "/",
                "method": "GET",
                "status": 200,
                "headers": {"Content-Type": "text/html; charset=utf-8"},
                "body": _HA_LOGIN_PAGE,
            },
            {
                "path": "/api/",
                "method": "GET",
                "status": 401,
                "headers": {"Content-Type": "application/json"},
                "body": _API_UNAUTHORIZED,
            },
            {
                "path": "/auth/token",
                "method": "POST",
                "status": 400,
                "headers": {"Content-Type": "application/json"},
                "body": _AUTH_REJECTED,
            },
        ]

    def _check_credential_in_request(
        self,
        headers: dict[str, str],
        body: str | None,
    ) -> Optional[str]:
        """Check if a planted credential appears in request headers or body."""
        # Check Authorization header
        auth = headers.get("Authorization", "") or headers.get("authorization", "")
        for cred_val in self._credential_values:
            if cred_val in auth:
                return cred_val

        # Check body (POST /auth/token may contain tokens)
        if body:
            for cred_val in self._credential_values:
                if cred_val in body:
                    return cred_val

        return None

    def _on_request(
        self,
        client_address: tuple[str, int],
        method: str,
        path: str,
        headers: dict[str, str],
        body: str | None,
    ) -> None:
        """Callback from ClownPeanuts Emulator for each request."""
        credential_used = self._check_credential_in_request(headers, body)

        event = DecoyConnectionEvent(
            source_ip=client_address[0],
            source_port=client_address[1],
            dest_port=self.port,
            protocol="tcp",
            timestamp=datetime.now(timezone.utc),
            request_path=path,
            credential_used=credential_used,
        )
        self._notify_connection(event)

    async def start(self) -> None:
        """Start the Home Assistant decoy."""
        routes = self._build_routes()
        self._emulator = Emulator(
            bind_address=self.bind_address,
            port=self.port,
            routes=routes,
            on_request=self._on_request,
        )
        await asyncio.to_thread(self._emulator.start)

        if self.port == 0 and self._emulator is not None:
            self.port = self._emulator.port

        self._running = True
        logger.info("HA decoy '%s' started on %s:%d", self.name, self.bind_address, self.port)

    async def stop(self) -> None:
        """Stop the Home Assistant decoy."""
        if self._emulator is not None:
            await asyncio.to_thread(self._emulator.stop)
            self._emulator = None
        self._running = False
        logger.info("HA decoy '%s' stopped", self.name)

    async def health_check(self) -> bool:
        if not self._running or self._emulator is None:
            return False
        return self._emulator.is_alive()

    @property
    def is_running(self) -> bool:
        return self._running
