"""HTTP service emulator using ThreadingHTTPServer.

Provides a configurable HTTP server that serves pre-defined routes with
custom status codes, headers, and bodies. Supports a request callback
for connection logging and credential detection.
"""

from __future__ import annotations

import io
import logging
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class _EmulatorHandler(BaseHTTPRequestHandler):
    """HTTP request handler that serves routes from the emulator config."""

    # Suppress default logging to stderr
    def log_message(self, format, *args):
        pass

    def _handle_request(self, method: str) -> None:
        """Match the request against configured routes and serve the response."""
        emulator: Emulator = self.server._emulator  # type: ignore[attr-defined]
        path = urlparse(self.path).path

        # Read body for POST/PUT
        content_length = int(self.headers.get("Content-Length", 0))
        body: str | None = None
        if content_length > 0:
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        # Collect headers as dict
        headers_dict = {k: v for k, v in self.headers.items()}

        # Fire the request callback
        if emulator._on_request is not None:
            try:
                emulator._on_request(
                    self.client_address,
                    method,
                    path,
                    headers_dict,
                    body,
                )
            except Exception:
                logger.exception("Error in request callback")

        # Find matching route
        route = None
        for r in emulator._routes:
            if r["path"] == path and r["method"].upper() == method.upper():
                route = r
                break

        if route is None:
            # Try matching any method for the path
            for r in emulator._routes:
                if r["path"] == path:
                    route = r
                    break

        if route is None:
            # Fallback: 404
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        # Serve the matched route
        self.send_response(route["status"])
        for header_name, header_value in route.get("headers", {}).items():
            self.send_header(header_name, header_value)
        self.end_headers()

        body_content = route.get("body", "")
        if isinstance(body_content, str):
            self.wfile.write(body_content.encode("utf-8"))
        else:
            self.wfile.write(body_content)

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def do_PUT(self):
        self._handle_request("PUT")

    def do_DELETE(self):
        self._handle_request("DELETE")

    def do_HEAD(self):
        self._handle_request("HEAD")


class Emulator:
    """Thread-based HTTP service emulator.

    Runs a ThreadingHTTPServer in a background thread, serving pre-configured
    routes with custom responses.

    Args:
        bind_address: IP address to bind to.
        port: TCP port (0 = OS-assigned).
        routes: List of route dicts with keys: path, method, status, headers, body.
        on_request: Optional callback invoked for each request with
            (client_address, method, path, headers, body).
    """

    def __init__(
        self,
        bind_address: str = "127.0.0.1",
        port: int = 0,
        routes: Optional[list[dict]] = None,
        on_request: Optional[Callable] = None,
    ) -> None:
        self._bind_address = bind_address
        self._port = port
        self._routes = routes or []
        self._on_request = on_request
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._alive = False

    @property
    def port(self) -> int:
        """Return the actual port the server is listening on."""
        if self._server is not None:
            return self._server.server_address[1]
        return self._port

    def is_alive(self) -> bool:
        """Return True if the server thread is alive."""
        return self._alive and self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Start the HTTP server in a background thread."""
        self._server = ThreadingHTTPServer(
            (self._bind_address, self._port),
            _EmulatorHandler,
        )
        self._server._emulator = self  # type: ignore[attr-defined]
        self._server.daemon_threads = True

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name=f"emulator-{self._bind_address}:{self.port}",
        )
        self._thread.start()
        self._alive = True

    def stop(self) -> None:
        """Stop the HTTP server and wait for the thread to exit."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._alive = False
        self._server = None
        self._thread = None
