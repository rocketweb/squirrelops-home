"""Dev server decoy — mimics an Express/Next.js development server.

Wraps the ClownPeanuts Emulator (thread-based ThreadingHTTPServer) with
Express/Next.js-like routes and headers. Detects when planted credentials
appear in incoming requests.

Routes:
    GET /           — React error page (HTML)
    GET /api/health — JSON health endpoint
    GET /.env       — Planted .env file with credentials
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
# HTML templates
# ---------------------------------------------------------------------------

_REACT_ERROR_PAGE = """<!DOCTYPE html>
<html>
<head><title>Application Error</title></head>
<body>
<div id="__next">
  <div style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 20px;">
    <h2>Application error: a client-side exception has occurred</h2>
    <p style="color: #666;">See the developer console for more information.</p>
    <p style="font-size: 12px; color: #999;">
      This error occurred during page generation.
      React and Next.js development server v14.1.0
    </p>
  </div>
</div>
</body>
</html>"""

_HEALTH_RESPONSE = json.dumps({
    "status": "ok",
    "uptime": 847293,
    "version": "1.4.2",
    "environment": "development",
})


class DevServerDecoy(BaseDecoy):
    """Express/Next.js development server decoy.

    Uses ClownPeanuts Emulator for the HTTP server. The Emulator runs a
    ThreadingHTTPServer in a background thread, so we use asyncio.to_thread
    for start/stop operations.

    Args:
        decoy_id: Unique identifier for this decoy instance.
        name: Human-readable name for display.
        port: TCP port to listen on (0 = OS-assigned).
        bind_address: IP address to bind to.
        planted_credentials: List of credentials to serve and detect.
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
            decoy_type="dev_server",
        )
        self._planted_credentials = planted_credentials or []
        self._emulator: Optional[Emulator] = None
        self._running = False

        # Build the credential lookup set for fast detection
        self._credential_values: set[str] = {
            c.credential_value for c in self._planted_credentials
        }

        # Build .env content from planted env_file credentials
        self._env_content = self._build_env_content()

    def _build_env_content(self) -> str:
        """Build .env file content from planted env_file credentials."""
        for cred in self._planted_credentials:
            if cred.credential_type == "env_file":
                return cred.credential_value
        return "# No environment configuration\n"

    def _build_routes(self) -> list[dict]:
        """Build ClownPeanuts route configuration."""
        return [
            {
                "path": "/",
                "method": "GET",
                "status": 500,
                "headers": {
                    "Content-Type": "text/html; charset=utf-8",
                    "X-Powered-By": "Next.js",
                },
                "body": _REACT_ERROR_PAGE,
            },
            {
                "path": "/api/health",
                "method": "GET",
                "status": 200,
                "headers": {
                    "Content-Type": "application/json",
                    "X-Powered-By": "Express",
                },
                "body": _HEALTH_RESPONSE,
            },
            {
                "path": "/.env",
                "method": "GET",
                "status": 200,
                "headers": {
                    "Content-Type": "text/plain; charset=utf-8",
                    "X-Powered-By": "Express",
                },
                "body": self._env_content,
            },
        ]

    def _check_credential_in_request(
        self,
        headers: dict[str, str],
        body: str | None,
    ) -> Optional[str]:
        """Check if any planted credential appears in the request.

        Scans Authorization headers and request body for planted credential
        values. Returns the first matching credential value, or None.
        """
        # Check Authorization header
        auth = headers.get("Authorization", "") or headers.get("authorization", "")
        for cred_val in self._credential_values:
            if cred_val in auth:
                return cred_val

        # Check body
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
        """Callback invoked by the Emulator for each request.

        Creates a DecoyConnectionEvent and notifies the orchestrator
        via _notify_connection.
        """
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
        """Start the dev server decoy via ClownPeanuts Emulator."""
        routes = self._build_routes()
        self._emulator = Emulator(
            bind_address=self.bind_address,
            port=self.port,
            routes=routes,
            on_request=self._on_request,
        )
        await asyncio.to_thread(self._emulator.start)

        # Update port if OS-assigned
        if self.port == 0 and self._emulator is not None:
            self.port = self._emulator.port

        self._running = True
        logger.info("Dev server decoy '%s' started on %s:%d", self.name, self.bind_address, self.port)

    async def stop(self) -> None:
        """Stop the dev server decoy."""
        if self._emulator is not None:
            await asyncio.to_thread(self._emulator.stop)
            self._emulator = None
        self._running = False
        logger.info("Dev server decoy '%s' stopped", self.name)

    async def health_check(self) -> bool:
        """Return True if the emulator is running and responsive."""
        if not self._running or self._emulator is None:
            return False
        return self._emulator.is_alive()

    @property
    def is_running(self) -> bool:
        return self._running
