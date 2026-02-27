"""Async mimic server — lightweight HTTP runtime for profile-based decoys.

Uses asyncio.start_server for a zero-thread, zero-dependency async HTTP
server. Each mimic decoy gets its own asyncio.Server bound to a specific
virtual IP + port, all sharing the main event loop. Memory: ~10KB per server.

For non-HTTP ports (SSH, SMTP), deploys simple banner-replay listeners
that send the captured greeting and log connections.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Callable, Optional

from squirrelops_home_sensor.decoys.types.base import BaseDecoy, DecoyConnectionEvent

logger = logging.getLogger("squirrelops_home_sensor.decoys.mimic")


class _MimicEndpoint:
    """A single mimic endpoint serving routes on one IP:port.

    Parameters
    ----------
    bind_ip:
        IP address to bind to.
    port:
        Advertised port (the one attackers think they're connecting to).
    bind_port:
        Actual port to bind to.  Defaults to ``port`` for non-privileged
        ports.  For privileged ports (< 1024), the caller sets this to
        a high port (port + 10000) and uses pfctl/iptables to redirect.
    """

    def __init__(
        self,
        bind_ip: str,
        port: int,
        routes: list[dict],
        server_header: str | None,
        protocol_banner: str | None,
        connection_callback: Callable[[DecoyConnectionEvent], None] | None,
        credential_values: set[str],
        bind_port: int | None = None,
    ) -> None:
        self.bind_ip = bind_ip
        self.port = port
        self.bind_port = bind_port if bind_port is not None else port
        self.routes = {r.get("path", "/"): r for r in routes}
        self.server_header = server_header
        self.protocol_banner = protocol_banner
        self.connection_callback = connection_callback
        self.credential_values = credential_values
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        """Start serving on bind_port."""
        if self.routes:
            self._server = await asyncio.start_server(
                self._handle_http, self.bind_ip, self.bind_port,
            )
        elif self.protocol_banner:
            self._server = await asyncio.start_server(
                self._handle_banner, self.bind_ip, self.bind_port,
            )
        else:
            self._server = await asyncio.start_server(
                self._handle_banner, self.bind_ip, self.bind_port,
            )
        if self.bind_port != self.port:
            logger.debug(
                "Mimic endpoint started on %s:%d (remapped from :%d)",
                self.bind_ip, self.bind_port, self.port,
            )
        else:
            logger.debug("Mimic endpoint started on %s:%d", self.bind_ip, self.port)

    async def stop(self) -> None:
        """Stop serving."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    @property
    def is_running(self) -> bool:
        return self._server is not None and self._server.is_serving()

    async def _handle_http(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        """Minimal HTTP request handler."""
        peername = writer.get_extra_info("peername")
        source_ip = peername[0] if peername else "0.0.0.0"
        source_port = peername[1] if peername else 0

        try:
            # Read request line
            request_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not request_line:
                return

            request_text = request_line.decode("utf-8", errors="replace").strip()
            parts = request_text.split(" ")
            method = parts[0] if len(parts) >= 1 else "GET"
            path = parts[1] if len(parts) >= 2 else "/"

            # Read headers
            headers: dict[str, str] = {}
            body_text = ""
            content_length = 0
            while True:
                header_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if header_line in (b"\r\n", b"\n", b""):
                    break
                decoded = header_line.decode("utf-8", errors="replace").strip()
                if ":" in decoded:
                    key, _, value = decoded.partition(":")
                    headers[key.strip().lower()] = value.strip()
                    if key.strip().lower() == "content-length":
                        try:
                            content_length = int(value.strip())
                        except ValueError:
                            pass

            # Read body if present
            if content_length > 0:
                body_bytes = await asyncio.wait_for(
                    reader.read(min(content_length, 4096)), timeout=5.0,
                )
                body_text = body_bytes.decode("utf-8", errors="replace")

            # Check for planted credentials
            credential_used = self._check_credentials(headers, body_text)

            # Match route
            route = self.routes.get(path) or self.routes.get("/")
            if route:
                await self._send_response(writer, route)
            else:
                await self._send_404(writer)

            # Notify connection
            if self.connection_callback:
                event = DecoyConnectionEvent(
                    source_ip=source_ip,
                    source_port=source_port,
                    dest_port=self.port,
                    protocol="tcp",
                    timestamp=datetime.now(timezone.utc),
                    request_path=path,
                    credential_used=credential_used,
                )
                self.connection_callback(event)

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            logger.debug("Mimic HTTP handler error on %s:%d", self.bind_ip, self.port, exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_banner(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        """Banner-replay handler for non-HTTP ports (SSH, FTP, SMTP)."""
        peername = writer.get_extra_info("peername")
        source_ip = peername[0] if peername else "0.0.0.0"
        source_port = peername[1] if peername else 0

        try:
            # Send banner
            banner = self.protocol_banner or ""
            if banner and not banner.endswith("\r\n"):
                banner += "\r\n"
            writer.write(banner.encode("utf-8"))
            await writer.drain()

            # Read whatever the client sends (for logging)
            try:
                data = await asyncio.wait_for(reader.read(512), timeout=5.0)
                body_text = data.decode("utf-8", errors="replace") if data else ""
            except asyncio.TimeoutError:
                body_text = ""

            credential_used = self._check_credentials({}, body_text)

            if self.connection_callback:
                event = DecoyConnectionEvent(
                    source_ip=source_ip,
                    source_port=source_port,
                    dest_port=self.port,
                    protocol="tcp",
                    timestamp=datetime.now(timezone.utc),
                    credential_used=credential_used,
                )
                self.connection_callback(event)

        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            logger.debug("Mimic banner handler error", exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _send_response(
        self, writer: asyncio.StreamWriter, route: dict,
    ) -> None:
        """Send an HTTP response based on a route configuration."""
        status = route.get("status", 200)
        body = route.get("body", "")
        resp_headers = dict(route.get("headers", {}))

        if self.server_header:
            resp_headers.setdefault("Server", self.server_header)
        resp_headers["Content-Length"] = str(len(body.encode("utf-8")))
        resp_headers.setdefault("Connection", "close")

        status_text = _STATUS_TEXTS.get(status, "OK")
        lines = [f"HTTP/1.1 {status} {status_text}"]
        for key, value in resp_headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        lines.append(body)

        writer.write("\r\n".join(lines).encode("utf-8"))
        await writer.drain()

    async def _send_404(self, writer: asyncio.StreamWriter) -> None:
        """Send a minimal 404 response."""
        resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        writer.write(resp.encode("utf-8"))
        await writer.drain()

    def _check_credentials(
        self, headers: dict[str, str], body: str,
    ) -> str | None:
        """Check if a planted credential appears in request."""
        for cred_val in self.credential_values:
            # Check Authorization header
            auth = headers.get("authorization", "")
            if cred_val in auth:
                return cred_val
            # Check body
            if cred_val in body:
                return cred_val
        return None


class MimicDecoy(BaseDecoy):
    """A mimic decoy that serves profile-cloned responses on a virtual IP.

    Can serve multiple ports on the same IP, each with its own route config
    or banner replay.

    Parameters
    ----------
    decoy_id:
        Database ID for this decoy.
    name:
        Human-readable name.
    bind_address:
        Virtual IP to bind to.
    port_configs:
        List of dicts, each with: port, routes (list), protocol_banner (str|None).
    server_header:
        Server header to include in HTTP responses.
    planted_credentials:
        Credentials to detect in requests.
    """

    def __init__(
        self,
        decoy_id: int,
        name: str,
        bind_address: str,
        port_configs: list[dict],
        server_header: str | None = None,
        planted_credentials: Optional[list] = None,
        port_remaps: Optional[dict[int, int]] = None,
    ) -> None:
        # Use the first port as the primary port for the base class
        primary_port = port_configs[0]["port"] if port_configs else 0
        super().__init__(
            decoy_id=decoy_id,
            name=name,
            port=primary_port,
            bind_address=bind_address,
            decoy_type="mimic",
        )
        self._port_configs = port_configs
        self._server_header = server_header
        self._planted_credentials = planted_credentials or []
        self._endpoints: list[_MimicEndpoint] = []
        self._port_remaps = port_remaps or {}

        self._credential_values: set[str] = {
            c.credential_value for c in self._planted_credentials
            if hasattr(c, "credential_value")
        }

    @property
    def port_remaps(self) -> dict[int, int]:
        """Port remappings: ``{advertised_port: actual_bind_port}``."""
        return self._port_remaps

    async def start(self) -> None:
        """Start all mimic endpoints."""
        for config in self._port_configs:
            advertised_port = config["port"]
            bind_port = self._port_remaps.get(advertised_port, advertised_port)
            endpoint = _MimicEndpoint(
                bind_ip=self.bind_address,
                port=advertised_port,
                bind_port=bind_port,
                routes=config.get("routes", []),
                server_header=self._server_header,
                protocol_banner=config.get("protocol_banner"),
                connection_callback=self._on_connection,
                credential_values=self._credential_values,
            )
            try:
                await endpoint.start()
                self._endpoints.append(endpoint)
            except OSError as exc:
                logger.warning(
                    "Failed to start mimic endpoint %s:%d (bind :%d): %s",
                    self.bind_address, advertised_port, bind_port, exc,
                )
        logger.info(
            "Mimic decoy '%s' started on %s with %d/%d endpoints",
            self.name, self.bind_address, len(self._endpoints), len(self._port_configs),
        )

    async def stop(self) -> None:
        """Stop all mimic endpoints."""
        for endpoint in self._endpoints:
            await endpoint.stop()
        self._endpoints.clear()
        logger.info("Mimic decoy '%s' stopped", self.name)

    async def health_check(self) -> bool:
        """Check that at least one endpoint is running."""
        return any(ep.is_running for ep in self._endpoints)

    @property
    def is_running(self) -> bool:
        return len(self._endpoints) > 0 and any(ep.is_running for ep in self._endpoints)


# Common HTTP status texts
_STATUS_TEXTS = {
    200: "OK",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
    503: "Service Unavailable",
}
