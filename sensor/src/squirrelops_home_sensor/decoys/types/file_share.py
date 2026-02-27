"""File share decoy — mimics an nginx-served directory with sensitive files.

Wraps the ClownPeanuts Emulator with nginx-like directory listing routes,
a downloadable passwords.txt, and an SSH private key. Detects planted
credentials in Basic and Bearer Authorization headers.

Routes:
    GET /              — nginx autoindex-style directory listing (HTML)
    GET /passwords.txt — Planted username:password pairs
    GET /.ssh/id_rsa   — Planted RSA private key
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from clownpeanuts.services.http.emulator import Emulator
from clownpeanuts.tarpit.throttle import AdaptiveThrottle

from squirrelops_home_sensor.decoys.credentials import GeneratedCredential
from squirrelops_home_sensor.decoys.types.base import BaseDecoy, DecoyConnectionEvent

logger = logging.getLogger(__name__)


def _build_directory_listing_html(password_filename: str = "passwords.txt") -> str:
    """Build an nginx autoindex-style directory listing page."""
    # Pad to align columns like real nginx autoindex
    pad = " " * max(1, 55 - len(password_filename))
    return f"""<!DOCTYPE html>
<html>
<head><title>Index of /</title></head>
<body>
<h1>Index of /</h1>
<hr>
<pre>
<a href="{password_filename}">{password_filename}</a>{pad}14-Jan-2024 03:22    1.2K
<a href=".ssh/">.ssh/</a>                                                      08-Dec-2023 19:45       -
<a href="backup/">.backup/</a>                                                 21-Nov-2023 14:12       -
<a href="notes.txt">notes.txt</a>                                              03-Feb-2024 08:30     256
</pre>
<hr>
</body>
</html>"""


class FileShareDecoy(BaseDecoy):
    """HTTP file share decoy with nginx branding.

    Serves a directory listing with planted credential files.
    Decodes Base64 Authorization headers to detect use of planted
    username:password pairs.

    Args:
        decoy_id: Unique identifier for this decoy instance.
        name: Human-readable name for display.
        port: TCP port to listen on (0 = OS-assigned).
        bind_address: IP address to bind to.
        planted_credentials: Credentials to serve and detect.
    """

    def __init__(
        self,
        decoy_id: int,
        name: str,
        port: int,
        bind_address: str = "127.0.0.1",
        planted_credentials: Optional[list[GeneratedCredential]] = None,
        config: Optional[dict] = None,
    ) -> None:
        super().__init__(
            decoy_id=decoy_id,
            name=name,
            port=port,
            bind_address=bind_address,
            decoy_type="file_share",
        )
        self._planted_credentials = planted_credentials or []
        self._config = config or {}
        self._emulator: Optional[Emulator] = None
        self._running = False

        # Configurable filename (read from decoy config)
        self._password_filename = self._config.get("password_filename", "passwords.txt")

        # Build credential lookup set
        self._credential_values: set[str] = {
            c.credential_value for c in self._planted_credentials
        }

        # Build file contents
        self._passwords_content = self._build_passwords_content()
        self._ssh_key_content = self._build_ssh_key_content()

    def _build_passwords_content(self) -> str:
        """Build passwords.txt from planted password credentials."""
        lines = []
        for cred in self._planted_credentials:
            if cred.credential_type == "password":
                lines.append(cred.credential_value)
        return "\n".join(lines) + "\n" if lines else "# No credentials\n"

    def _build_ssh_key_content(self) -> str:
        """Get the planted SSH key content."""
        for cred in self._planted_credentials:
            if cred.credential_type == "ssh_key":
                return cred.credential_value
        return ""

    def _build_routes(self) -> list[dict]:
        """Build ClownPeanuts route configuration."""
        return [
            {
                "path": "/",
                "method": "GET",
                "status": 200,
                "headers": {
                    "Content-Type": "text/html; charset=utf-8",
                    "Server": "nginx/1.24.0",
                },
                "body": _build_directory_listing_html(self._password_filename),
            },
            {
                "path": f"/{self._password_filename}",
                "method": "GET",
                "status": 200,
                "headers": {
                    "Content-Type": "text/plain; charset=utf-8",
                    "Server": "nginx/1.24.0",
                },
                "body": self._passwords_content,
            },
            {
                "path": "/.ssh/id_rsa",
                "method": "GET",
                "status": 200,
                "headers": {
                    "Content-Type": "application/octet-stream",
                    "Server": "nginx/1.24.0",
                },
                "body": self._ssh_key_content,
            },
        ]

    def _decode_basic_auth(self, auth_header: str) -> Optional[str]:
        """Decode a Basic Authorization header value.

        Returns the decoded 'username:password' string, or None if
        the header is not valid Basic auth.
        """
        if not auth_header.startswith("Basic "):
            return None
        try:
            encoded = auth_header[6:].strip()
            decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
            return decoded
        except Exception:
            return None

    def _check_credential_in_request(
        self,
        headers: dict[str, str],
        body: str | None,
    ) -> Optional[str]:
        """Check for planted credentials in the request.

        Checks both Basic auth (decoded) and Bearer token headers,
        plus the raw header value against planted credential values.
        """
        auth = headers.get("Authorization", "") or headers.get("authorization", "")

        # Check Basic auth: decode and compare
        decoded = self._decode_basic_auth(auth)
        if decoded and decoded in self._credential_values:
            return decoded

        # Check Bearer and raw header for planted values
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
        """Start the file share decoy."""
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
        logger.info("File share decoy '%s' started on %s:%d", self.name, self.bind_address, self.port)

    async def stop(self) -> None:
        """Stop the file share decoy."""
        if self._emulator is not None:
            await asyncio.to_thread(self._emulator.stop)
            self._emulator = None
        self._running = False
        logger.info("File share decoy '%s' stopped", self.name)

    async def health_check(self) -> bool:
        if not self._running or self._emulator is None:
            return False
        return self._emulator.is_alive()

    @property
    def is_running(self) -> bool:
        return self._running
