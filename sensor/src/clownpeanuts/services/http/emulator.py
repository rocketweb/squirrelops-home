"""HTTP service emulator using ThreadingHTTPServer.

Provides a configurable HTTP server that serves pre-defined routes with
custom status codes, headers, and bodies. Supports a request callback
for connection logging and credential detection.
"""

from __future__ import annotations

import http.client
import logging
import socket
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

MAX_REQUEST_BODY_BYTES = 64 * 1024
MAX_CONCURRENT_REQUESTS = 16
REQUEST_TIMEOUT_SECONDS = 5
MAX_REQUEST_HEADER_LINE_BYTES = 8 * 1024
MAX_REQUEST_HEADER_SECTION_BYTES = 32 * 1024
MAX_REQUEST_HEADER_FIELDS = 100
MAX_ALERT_REQUEST_TARGET_CHARS = 2048


def _append_alert_header(
    headers: dict[str, str],
    key: str,
    value: str,
) -> None:
    """Retain duplicate header values without creating an unbounded list."""
    if key in headers:
        headers[key] = f"{headers[key]}\n{value}"
    else:
        headers[key] = value


def _headers_for_alert(items) -> dict[str, str]:
    """Copy already-bounded parsed headers while preserving duplicates."""
    headers: dict[str, str] = {}
    for key, value in items:
        _append_alert_header(headers, str(key), str(value))
    return headers


def _bounded_request_target(raw_target: object) -> str:
    """Return an alert-safe request target even when URL parsing rejects it."""
    if not isinstance(raw_target, str):
        return ""
    return raw_target[:MAX_ALERT_REQUEST_TARGET_CHARS]


def _safe_request_path(raw_target: object) -> tuple[str, bool]:
    """Normalize a request target without letting urlparse suppress an alert."""
    bounded_target = _bounded_request_target(raw_target)
    if not bounded_target:
        return "", True
    try:
        return urlparse(bounded_target).path, True
    except ValueError:
        return bounded_target, False


class _BoundedHeaderReader:
    """Bound stdlib header parsing while retaining safe alert metadata."""

    def __init__(self, stream, fallback_headers: dict[str, str]) -> None:
        self._stream = stream
        self._fallback_headers = fallback_headers
        self._total_bytes = 0
        self._field_count = 0

    def readline(self, limit: int = -1) -> bytes:
        read_limit = MAX_REQUEST_HEADER_LINE_BYTES + 1
        if limit >= 0:
            read_limit = min(read_limit, limit)
        line = self._stream.readline(read_limit)
        if len(line) > MAX_REQUEST_HEADER_LINE_BYTES:
            raise http.client.LineTooLong("request header line")

        self._total_bytes += len(line)
        if self._total_bytes > MAX_REQUEST_HEADER_SECTION_BYTES:
            raise http.client.HTTPException("request header section too large")

        if line not in (b"\r\n", b"\n", b""):
            self._field_count += 1
            if self._field_count > MAX_REQUEST_HEADER_FIELDS:
                raise http.client.HTTPException("too many request headers")
            decoded = line.decode("iso-8859-1", errors="replace").strip()
            if ":" in decoded:
                key, _, value = decoded.partition(":")
                _append_alert_header(
                    self._fallback_headers,
                    key.strip(),
                    value.strip(),
                )
        return line


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
            emulator: Emulator | None = getattr(self, "_emulator", None)
            if emulator is not None:
                emulator._notify_connection(
                    client_address,
                    method="UNKNOWN",
                    path="",
                    headers={},
                    body=None,
                )
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

    def setup(self) -> None:
        self._recorded_valid_request = False
        self._notification_lock = threading.Lock()
        self._body_lock = threading.Lock()
        self._body_prefix = bytearray()
        self._fallback_headers: dict[str, str] = {}
        super().setup()
        self.connection.settimeout(REQUEST_TIMEOUT_SECONDS)
        self._deadline_timer = threading.Timer(
            REQUEST_TIMEOUT_SECONDS,
            self._expire_request,
        )
        self._deadline_timer.daemon = True
        self._deadline_timer.start()

    def finish(self) -> None:
        self._deadline_timer.cancel()
        super().finish()

    def _expire_request(self) -> None:
        """End a slow-drip request on one absolute wall-clock deadline."""
        method, path, headers = self._request_metadata()
        self._notify_request(
            method=method,
            path=path,
            headers=headers,
            body=self._body_for_alert(),
        )
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def handle(self) -> None:
        """Record malformed or incomplete connections that bypass dispatch."""
        try:
            super().handle()
        finally:
            if not self._recorded_valid_request:
                method, path, headers = self._request_metadata()
                self._notify_request(
                    method=method,
                    path=path,
                    headers=headers,
                    body=self._body_for_alert(),
                )

    def handle_one_request(self) -> None:
        """Make every accepted request attempt observable, including EOF."""
        try:
            super().handle_one_request()
        finally:
            if not self._recorded_valid_request:
                method, path, headers = self._request_metadata()
                self._notify_request(
                    method=method,
                    path=path,
                    headers=headers,
                    body=self._body_for_alert(),
                )

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        """Record stdlib parser and unsupported-method errors before replying."""
        if not self._recorded_valid_request:
            method, path, headers = self._request_metadata()
            self._notify_request(
                method=method,
                path=path,
                headers=headers,
                body=self._body_for_alert(),
            )
        super().send_error(code, message, explain)

    def parse_request(self) -> bool:
        """Use stdlib syntax handling with stricter aggregate header bounds."""
        original_rfile = self.rfile
        self.rfile = _BoundedHeaderReader(  # type: ignore[assignment]
            original_rfile,
            self._fallback_headers,
        )
        try:
            return super().parse_request()
        finally:
            self.rfile = original_rfile

    # Suppress default logging to stderr
    def log_message(self, format, *args):
        pass

    def send_response(self, code, message=None):
        """Send status and Date without BaseHTTPRequestHandler's Python banner."""
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def _request_metadata(self) -> tuple[str, str, dict[str, str]]:
        """Return the best bounded metadata available for an alert."""
        method = getattr(self, "command", None) or "UNKNOWN"
        raw_path = getattr(self, "path", None) or ""
        path, _ = _safe_request_path(raw_path)
        parsed_headers = getattr(self, "headers", None)
        headers = (
            _headers_for_alert(parsed_headers.items())
            if parsed_headers is not None
            else dict(self._fallback_headers)
        )
        return method, path, headers

    def _notify_parsed_request(
        self,
        *,
        method: str,
        path: str,
        body: str | None = None,
    ) -> None:
        """Record a request after headers parse, including rejected bodies."""
        self._notify_request(
            method=method,
            path=path,
            headers=_headers_for_alert(self.headers.items()),
            body=body,
        )

    def _remember_body_prefix(self, body: bytes) -> None:
        """Retain a bounded body prefix for timeout and malformed alerts."""
        with self._body_lock:
            self._body_prefix = bytearray(body[:MAX_REQUEST_BODY_BYTES])

    def _body_for_alert(self) -> str | None:
        """Return any bounded body bytes received before an incomplete request."""
        with self._body_lock:
            if not self._body_prefix:
                return None
            body = bytes(self._body_prefix)
        return body.decode("utf-8", errors="replace")

    def _notify_request(
        self,
        *,
        method: str,
        path: str,
        headers: dict[str, str],
        body: str | None,
    ) -> None:
        """Notify once per parsed request, or once for a malformed connection."""
        with self._notification_lock:
            if self._recorded_valid_request:
                return
            self._recorded_valid_request = True
        emulator: Emulator = self.server._emulator  # type: ignore[attr-defined]
        emulator._notify_connection(
            self.client_address,
            method=method,
            path=path,
            headers=headers,
            body=body,
        )

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
        path, valid_path = _safe_request_path(self.path)
        if not valid_path:
            self._notify_parsed_request(method=method, path=path)
            self._reject(400, b"Invalid request target")
            return

        # Read body for POST/PUT
        if self.headers.get("Transfer-Encoding"):
            self._notify_parsed_request(method=method, path=path)
            self._reject(400, b"Transfer-Encoding is not supported")
            return
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._notify_parsed_request(method=method, path=path)
            self._reject(400, b"Invalid Content-Length")
            return
        if content_length < 0:
            self._notify_parsed_request(method=method, path=path)
            self._reject(400, b"Invalid Content-Length")
            return
        if content_length > MAX_REQUEST_BODY_BYTES:
            self._notify_parsed_request(method=method, path=path)
            self._reject(413, b"Payload Too Large")
            return
        body: str | None = None
        if content_length > 0:
            raw_body = bytearray()
            try:
                while len(raw_body) < content_length:
                    read_size = min(4096, content_length - len(raw_body))
                    chunk = self.rfile.read1(read_size)
                    if not chunk:
                        break
                    raw_body.extend(chunk)
                    self._remember_body_prefix(bytes(raw_body))
            except OSError:
                self._notify_parsed_request(
                    method=method,
                    path=path,
                    body=self._body_for_alert(),
                )
                self._reject(408, b"Request Timeout")
                return
            if len(raw_body) != content_length:
                self._notify_parsed_request(
                    method=method,
                    path=path,
                    body=self._body_for_alert(),
                )
                self._reject(400, b"Incomplete request body")
                return
            body = bytes(raw_body).decode("utf-8", errors="replace")

        # Fire the request callback only after the bounded body has been read.
        self._notify_parsed_request(method=method, path=path, body=body)

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

    def _notify_connection(
        self,
        client_address: tuple[str, int],
        *,
        method: str,
        path: str,
        headers: dict[str, str],
        body: str | None,
    ) -> None:
        """Record an accepted connection, including admission drops."""
        if self._on_request is None:
            return
        try:
            self._on_request(
                client_address,
                method,
                path,
                headers,
                body,
            )
        except Exception:
            logger.exception("Error in request callback")

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
