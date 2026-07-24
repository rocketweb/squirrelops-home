"""HTTP service emulator using ThreadingHTTPServer.

Provides a configurable HTTP server that serves pre-defined routes with
custom status codes, headers, and bodies. Supports a request callback
for connection logging and credential detection.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

MAX_REQUEST_BODY_BYTES = 64 * 1024
MAX_CONCURRENT_REQUESTS = 16
REQUEST_TIMEOUT_SECONDS = 5


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server with a hard per-decoy concurrency ceiling."""

    # Package upgrades stop and immediately restart active decoys. Reusing the
    # listening address avoids leaving a decoy offline while prior connections
    # finish their TCP TIME_WAIT lifecycle.
    allow_reuse_address = True
    request_queue_size = MAX_CONCURRENT_REQUESTS

    def __init__(self, *args, **kwargs):
        self._request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            self.close_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class _EmulatorHandler(BaseHTTPRequestHandler):
    """HTTP request handler that serves routes from the emulator config."""

    # Suppress default logging to stderr
    def log_message(self, format, *args):
        pass

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(REQUEST_TIMEOUT_SECONDS)

    def _reject(self, status_code: int, message: bytes) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(message)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(message)
        self.close_connection = True

    def _handle_request(self, method: str) -> None:
        """Match the request against configured routes and serve the response."""
        emulator: Emulator = self.server._emulator  # type: ignore[attr-defined]
        path = urlparse(self.path).path

        # Read body for POST/PUT
        if self.headers.get("Transfer-Encoding"):
            self._reject(400, b"Transfer-Encoding is not supported")
            return
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._reject(400, b"Invalid Content-Length")
            return
        if content_length < 0:
            self._reject(400, b"Invalid Content-Length")
            return
        if content_length > MAX_REQUEST_BODY_BYTES:
            self._reject(413, b"Payload Too Large")
            return
        body: str | None = None
        if content_length > 0:
            try:
                raw_body = self.rfile.read(content_length)
            except OSError:
                self._reject(408, b"Request Timeout")
                return
            if len(raw_body) != content_length:
                self._reject(400, b"Incomplete request body")
                return
            body = raw_body.decode("utf-8", errors="replace")

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
            self.send_header("Content-Length", "9")
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(b"Not Found")
            return

        # Serve the matched route
        self.send_response(route["status"])
        for header_name, header_value in route.get("headers", {}).items():
            self.send_header(header_name, header_value)
        body_content = route.get("body", "")
        encoded_body = (
            body_content.encode("utf-8") if isinstance(body_content, str) else body_content
        )
        if not any(
            name.lower() == "content-length" for name in route.get("headers", {})
        ):
            self.send_header("Content-Length", str(len(encoded_body)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(encoded_body)

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
        routes: list[dict] | None = None,
        on_request: Callable | None = None,
    ) -> None:
        self._bind_address = bind_address
        self._port = port
        self._routes = routes or []
        self._on_request = on_request
        self._server: _BoundedThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
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
        self._server = _BoundedThreadingHTTPServer(
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
