"""Async mimic server — lightweight HTTP runtime for profile-based decoys.

Uses asyncio.start_server for a zero-thread, zero-dependency async HTTP
server. Each mimic decoy gets its own asyncio.Server bound to a specific
virtual IP + port, all sharing the main event loop. Memory: ~10KB per server.

For non-HTTP ports (SSH, SMTP), deploys simple banner-replay listeners
that send the captured greeting and log connections.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import ssl
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import format_datetime
from urllib.parse import parse_qsl

from squirrelops_home_sensor.decoys.tls_identity import server_ssl_context
from squirrelops_home_sensor.decoys.types.base import BaseDecoy, DecoyConnectionEvent

logger = logging.getLogger("squirrelops_home_sensor.decoys.mimic")

_MAX_REPLAY_BODY_SIZE = 64 * 1024
_MAX_CREDENTIAL_AUTH_SIZE = 8 * 1024
_MAX_CREDENTIAL_BODY_SIZE = 4 * 1024
_MAX_CREDENTIAL_FORM_FIELDS = 32
_MAX_HTTP_REQUEST_LINE_SIZE = 8 * 1024
_MAX_HTTP_HEADER_LINE_SIZE = 8 * 1024
_MAX_HTTP_HEADER_SECTION_SIZE = 32 * 1024
_MAX_HTTP_HEADER_FIELDS = 100
_MAX_CHUNK_LINE_SIZE = 128
_MAX_CHUNK_COUNT = 64
_MAX_TRAILER_LINE_SIZE = 256
_MAX_TRAILER_FIELDS = 16
_MAX_CONCURRENT_CONNECTIONS = 16
_HTTP_REQUEST_DEADLINE_SECONDS = 10.0
_HTTP_BODY_TIMEOUT_SECONDS = 5.0
_HTTP_TOKEN_BYTES = frozenset(
    b"!#$%&'*+-.^_`|~"
    b"0123456789"
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b"abcdefghijklmnopqrstuvwxyz"
)


class _HTTPRequestLimitError(Exception):
    """Raised when an untrusted request exceeds a parser resource limit."""


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
        ssl_context: ssl.SSLContext | None = None,
        advertised_hostname: str | None = None,
    ) -> None:
        self.bind_ip = bind_ip
        self.port = port
        self.bind_port = bind_port if bind_port is not None else port
        self.routes = {r.get("path", "/"): r for r in routes}
        self.server_header = server_header
        self.protocol_banner = protocol_banner
        self.connection_callback = connection_callback
        self.credential_values = credential_values
        self.ssl_context = ssl_context
        self.advertised_hostname = advertised_hostname
        self._server: asyncio.Server | None = None
        self._active_connections = 0
        self._notified_connections: set[int] = set()

    async def start(self) -> None:
        """Start serving on bind_port."""
        if self.ssl_context is not None:
            # Accept the TCP connection before upgrading it. This lets a
            # connect-only scanner trip the decoy even when it never sends a
            # TLS ClientHello, while plaintext application traffic is still
            # rejected before any emulated response is served.
            handler = self._handle_tls
        elif self.routes:
            handler = self._handle_http
        else:
            handler = self._handle_banner
        async def bounded_handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            await self._handle_connection(handler, reader, writer)

        self._server = await asyncio.start_server(
            bounded_handler,
            self.bind_ip,
            self.bind_port,
        )
        sockets = self._server.sockets or []
        if not sockets:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            raise RuntimeError("Mimic endpoint started without a listening socket")
        self.bind_port = int(sockets[0].getsockname()[1])
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

    async def _handle_connection(
        self,
        handler,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Bound accepted work while preserving every trip signal."""
        if self._active_connections >= _MAX_CONCURRENT_CONNECTIONS:
            self._notify_connection(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError, RuntimeError):
                logger.debug("Mimic overload connection cleanup failed", exc_info=True)
            finally:
                self._notified_connections.discard(id(writer))
            return

        # No await occurs between the check and increment, so this admission
        # decision is atomic on the endpoint's event loop.
        self._active_connections += 1
        try:
            await handler(reader, writer)
        finally:
            self._active_connections -= 1
            self._notified_connections.discard(id(writer))

    def _notify_connection(
        self,
        writer: asyncio.StreamWriter,
        *,
        request_path: str | None = None,
        credential_used: str | None = None,
    ) -> None:
        """Emit at most one event for an accepted connection."""
        connection_id = id(writer)
        if (
            connection_id in self._notified_connections
            or self.connection_callback is None
        ):
            return
        self._notified_connections.add(connection_id)

        peername = writer.get_extra_info("peername")
        source_ip = peername[0] if peername else "0.0.0.0"
        source_port = peername[1] if peername else 0
        try:
            self.connection_callback(
                DecoyConnectionEvent(
                    source_ip=source_ip,
                    source_port=source_port,
                    dest_port=self.port,
                    protocol="tcp",
                    timestamp=datetime.now(UTC),
                    request_path=request_path,
                    credential_used=credential_used,
                )
            )
        except Exception:
            logger.exception("Mimic connection callback failed")

    async def _handle_tls(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Upgrade an accepted connection to TLS before serving a protocol."""
        ssl_context = self.ssl_context
        if ssl_context is None:
            raise RuntimeError("TLS connection accepted without an SSL context")
        try:
            await writer.start_tls(
                ssl_context,
                ssl_handshake_timeout=5.0,
            )
        except Exception:
            self._notify_connection(writer)
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError, RuntimeError):
                logger.debug("Mimic TLS connection cleanup failed", exc_info=True)
            return

        if self.routes:
            await self._handle_http(reader, writer)
        else:
            await self._handle_banner(reader, writer)

    async def _handle_http(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        """Minimal HTTP request handler."""
        parsed_request_path: str | None = None
        parsed_header_credential: str | None = None
        parsed_headers: dict[str, str] = {}
        parsed_body_prefix = b""

        def notify_connection(
            *,
            request_path: str | None = None,
            credential_used: str | None = None,
        ) -> None:
            self._notify_connection(
                writer,
                request_path=request_path,
                credential_used=credential_used,
            )

        def expire_request() -> None:
            # Preserve any bounded request metadata parsed before a peer stalls.
            # A planted header or body prefix must not be downgraded to a generic
            # connection by advertising a body and waiting out the deadline.
            credential_used = parsed_header_credential
            if credential_used is None:
                credential_used = self._check_credentials(
                    parsed_headers,
                    parsed_body_prefix.decode("utf-8", errors="replace"),
                    body_complete=False,
                )
            notify_connection(
                request_path=parsed_request_path,
                credential_used=credential_used,
            )
            writer.close()

        def preserve_body_prefix(body_prefix: bytes) -> None:
            """Retain and immediately inspect the bounded bytes read so far."""
            nonlocal parsed_body_prefix
            parsed_body_prefix = body_prefix[:_MAX_CREDENTIAL_BODY_SIZE]
            credential_used = self._check_credentials(
                parsed_headers,
                parsed_body_prefix.decode("utf-8", errors="replace"),
                body_complete=False,
            )
            if credential_used is not None:
                notify_connection(
                    request_path=parsed_request_path,
                    credential_used=credential_used,
                )

        deadline = asyncio.get_running_loop().call_later(
            _HTTP_REQUEST_DEADLINE_SECONDS,
            expire_request,
        )
        try:
            # Read request line
            request_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not request_line:
                # TCP connect scanners commonly complete the handshake and
                # immediately close without sending an HTTP request.  The
                # accepted connection is still a decoy trip and must not be
                # silently discarded.
                notify_connection()
                return
            if len(request_line) > _MAX_HTTP_REQUEST_LINE_SIZE:
                raise _HTTPRequestLimitError("HTTP request line exceeds limit")

            request_text = request_line.decode("utf-8", errors="replace").strip()
            parts = request_text.split(" ")
            path = parts[1] if len(parts) >= 2 else "/"
            parsed_request_path = path

            # Read headers
            headers = parsed_headers
            body_text = ""
            body_complete = True
            body_framing_valid = True
            content_length: int | None = None
            transfer_encoding: str | None = None
            header_count = 0
            header_section_size = 0
            while True:
                header_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if header_line in (b"\r\n", b"\n", b""):
                    break
                header_count += 1
                header_section_size += len(header_line)
                if (
                    len(header_line) > _MAX_HTTP_HEADER_LINE_SIZE
                    or header_count > _MAX_HTTP_HEADER_FIELDS
                    or header_section_size > _MAX_HTTP_HEADER_SECTION_SIZE
                ):
                    raise _HTTPRequestLimitError(
                        "HTTP header section exceeds limit"
                    )
                decoded = header_line.decode("utf-8", errors="replace").strip()
                if ":" in decoded:
                    key, _, value = decoded.partition(":")
                    normalized_key = key.strip().lower()
                    normalized_value = value.strip()
                    if normalized_key in headers:
                        headers[normalized_key] = (
                            f"{headers[normalized_key]}\n{normalized_value}"
                        )
                    else:
                        headers[normalized_key] = normalized_value
                    if normalized_key == "authorization":
                        parsed_header_credential = self._check_credentials(
                            headers,
                            "",
                            body_complete=False,
                        )
                        if parsed_header_credential is not None:
                            # Record as soon as the bounded header is available.
                            # Later malformed headers, body stalls, and response
                            # backpressure cannot downgrade this detection.
                            notify_connection(
                                request_path=path,
                                credential_used=parsed_header_credential,
                            )
                    if normalized_key == "content-length":
                        if (
                            content_length is not None
                            or not normalized_value.isascii()
                            or not normalized_value.isdigit()
                        ):
                            body_framing_valid = False
                        else:
                            content_length = int(normalized_value)
                    elif normalized_key == "transfer-encoding":
                        if transfer_encoding is not None:
                            body_framing_valid = False
                        transfer_encoding = normalized_value

            # Read body if present
            if transfer_encoding is not None:
                if content_length is not None:
                    body_framing_valid = False
                if transfer_encoding.casefold() != "chunked":
                    body_framing_valid = False

                if body_framing_valid:
                    try:
                        body_bytes, body_complete = await asyncio.wait_for(
                            self._read_chunked_body(
                                reader,
                                on_progress=preserve_body_prefix,
                            ),
                            timeout=_HTTP_BODY_TIMEOUT_SECONDS,
                        )
                    except TimeoutError:
                        body_bytes = parsed_body_prefix
                        body_complete = False
                    preserve_body_prefix(body_bytes)
                    body_text = body_bytes.decode("utf-8", errors="replace")
                else:
                    body_complete = False
            elif content_length is not None and content_length > 0:
                read_size = min(content_length, _MAX_CREDENTIAL_BODY_SIZE)
                body_complete = content_length <= _MAX_CREDENTIAL_BODY_SIZE
                try:
                    body_bytes, read_complete = await asyncio.wait_for(
                        self._read_body_prefix(
                            reader,
                            read_size,
                            on_progress=preserve_body_prefix,
                        ),
                        timeout=_HTTP_BODY_TIMEOUT_SECONDS,
                    )
                    body_complete = body_complete and read_complete
                except TimeoutError:
                    body_bytes = parsed_body_prefix
                    body_complete = False
                preserve_body_prefix(body_bytes)
                body_text = body_bytes.decode("utf-8", errors="replace")
            elif not body_framing_valid:
                body_complete = False

            # Check for planted credentials
            credential_used = self._check_credentials(
                headers,
                body_text,
                body_complete=body_complete,
            )
            # Detection precedes all response I/O. A peer that stops reading
            # cannot turn a parsed credential trip into a generic timeout.
            notify_connection(
                request_path=path,
                credential_used=credential_used,
            )

            # Match route
            route = self.routes.get(path) or self.routes.get("/")
            if route:
                await self._send_response(writer, route)
            else:
                await self._send_404(writer)

        except (TimeoutError, ConnectionResetError, BrokenPipeError):
            # TCP connect without completing HTTP exchange (e.g. nmap scan).
            # Still record the connection attempt.
            expire_request()
        except _HTTPRequestLimitError:
            # Resource-limit violations are attacker-controlled malformed
            # requests, but the accepted TCP connection remains a decoy trip.
            notify_connection()
        except Exception:
            logger.debug("Mimic HTTP handler error on %s:%d", self.bind_ip, self.port, exc_info=True)
            # Parsing must fail closed for serving while failing open for
            # detection: no malformed request may suppress the trip signal.
            notify_connection()
        finally:
            deadline.cancel()
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError, RuntimeError):
                logger.debug("Mimic HTTP connection cleanup failed", exc_info=True)

    async def _read_chunked_body(
        self,
        reader: asyncio.StreamReader,
        *,
        on_progress: Callable[[bytes], None] | None = None,
    ) -> tuple[bytes, bool]:
        """Read one strictly framed, bounded HTTP chunked body."""
        body = bytearray()
        chunk_count = 0

        while chunk_count < _MAX_CHUNK_COUNT:
            try:
                size_line = await reader.readline()
            except (ValueError, asyncio.LimitOverrunError):
                return bytes(body), False
            if (
                not size_line
                or len(size_line) > _MAX_CHUNK_LINE_SIZE
                or not size_line.endswith(b"\r\n")
            ):
                return bytes(body), False

            size_and_extensions = size_line[:-2]
            size_token, separator, extensions = size_and_extensions.partition(b";")
            if (
                not size_token
                or any(
                    byte not in b"0123456789abcdefABCDEF"
                    for byte in size_token
                )
            ):
                return bytes(body), False
            if separator and not self._valid_chunk_extensions(extensions):
                return bytes(body), False

            chunk_size = int(size_token, 16)
            if chunk_size == 0:
                trailers_valid = await self._read_chunked_trailers(reader)
                return bytes(body), trailers_valid
            if len(body) + chunk_size > _MAX_CREDENTIAL_BODY_SIZE:
                return bytes(body), False

            chunk, chunk_complete = await self._read_body_prefix(
                reader,
                chunk_size,
                on_progress=(
                    (
                        lambda partial: on_progress(bytes(body) + partial)
                    )
                    if on_progress is not None
                    else None
                )
            )
            body.extend(chunk)
            if on_progress is not None:
                on_progress(bytes(body))
            if not chunk_complete:
                return bytes(body), False

            chunk_ending, ending_complete = await self._read_body_prefix(
                reader,
                2,
            )
            if not ending_complete or chunk_ending != b"\r\n":
                return bytes(body), False

            chunk_count += 1

        return bytes(body), False

    @staticmethod
    async def _read_body_prefix(
        reader: asyncio.StreamReader,
        size: int,
        *,
        on_progress: Callable[[bytes], None] | None = None,
    ) -> tuple[bytes, bool]:
        """Read up to ``size`` bytes while retaining progress across timeouts."""
        body = bytearray()
        while len(body) < size:
            chunk = await reader.read(min(4096, size - len(body)))
            if not chunk:
                return bytes(body), False
            body.extend(chunk)
            if on_progress is not None:
                on_progress(bytes(body))
        return bytes(body), True

    @staticmethod
    def _valid_chunk_extensions(extensions: bytes) -> bool:
        """Accept a bounded conservative subset of RFC token extensions."""
        for extension in extensions.split(b";"):
            normalized = extension.strip(b" \t")
            if not normalized:
                return False
            name, separator, value = normalized.partition(b"=")
            if not name or any(byte not in _HTTP_TOKEN_BYTES for byte in name):
                return False
            if separator and (
                not value
                or any(byte not in _HTTP_TOKEN_BYTES for byte in value)
            ):
                return False
        return True

    @staticmethod
    async def _read_chunked_trailers(
        reader: asyncio.StreamReader,
    ) -> bool:
        """Consume a small, strictly bounded trailer section."""
        for _ in range(_MAX_TRAILER_FIELDS + 1):
            try:
                line = await reader.readline()
            except (ValueError, asyncio.LimitOverrunError):
                return False
            if (
                not line
                or len(line) > _MAX_TRAILER_LINE_SIZE
                or not line.endswith(b"\r\n")
            ):
                return False
            if line == b"\r\n":
                return True
            name, separator, value = line[:-2].partition(b":")
            if (
                not separator
                or not name
                or any(byte not in _HTTP_TOKEN_BYTES for byte in name)
                or name.lower() in {b"content-length", b"transfer-encoding"}
                or any(
                    byte != 9 and not 32 <= byte <= 126
                    for byte in value
                )
            ):
                return False
        return False

    async def _handle_banner(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        """Banner-replay handler for non-HTTP ports (SSH, FTP, SMTP)."""
        def notify_connection(*, credential_used: str | None = None) -> None:
            self._notify_connection(writer, credential_used=credential_used)

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
            except TimeoutError:
                body_text = ""

            credential_used = self._check_credentials({}, body_text)
            notify_connection(credential_used=credential_used)

        except (ConnectionResetError, BrokenPipeError):
            # TCP connect without completing banner exchange (e.g. nmap scan).
            notify_connection()
        except Exception:
            logger.debug("Mimic banner handler error", exc_info=True)
            # An accepted connection is still a trip even when malformed I/O
            # takes an unexpected parser or transport path.
            notify_connection()
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError, RuntimeError):
                logger.debug("Mimic banner connection cleanup failed", exc_info=True)

    async def _send_response(
        self, writer: asyncio.StreamWriter, route: dict,
    ) -> None:
        """Send an HTTP response based on a route configuration."""
        status = route.get("status", 200)
        encoded_body = route.get("body_base64")
        if isinstance(encoded_body, str):
            try:
                body_bytes = base64.b64decode(
                    encoded_body,
                    validate=True,
                )[:_MAX_REPLAY_BODY_SIZE]
            except (ValueError, binascii.Error):
                body_bytes = b""
        else:
            body = route.get("body", "")
            body_text = self._rewrite_source_identity(str(body), route)
            body_bytes = body_text.encode("utf-8")[:_MAX_REPLAY_BODY_SIZE]
        resp_headers = dict(route.get("headers", {}))
        for key, value in list(resp_headers.items()):
            resp_headers[key] = self._rewrite_source_identity(str(value), route)
        if route.get("_include_date"):
            resp_headers["Date"] = format_datetime(
                datetime.now(UTC),
                usegmt=True,
            )

        if self.server_header and not any(
            key.lower() == "server" for key in resp_headers
        ):
            resp_headers["Server"] = self.server_header
        for key in list(resp_headers):
            if key.lower() == "content-length":
                resp_headers.pop(key)
        resp_headers["Content-Length"] = str(len(body_bytes))
        for key in list(resp_headers):
            if key.lower() == "connection":
                resp_headers.pop(key)
        resp_headers["Connection"] = "close"

        status_text = _STATUS_TEXTS.get(status, "OK")
        lines = [f"HTTP/1.1 {status} {status_text}"]
        for key, value in resp_headers.items():
            lines.append(f"{key}: {value}")
        lines.extend(("", ""))
        writer.write("\r\n".join(lines).encode("utf-8") + body_bytes)
        await writer.drain()

    def _rewrite_source_identity(self, value: str, route: dict) -> str:
        """Replace captured real-host references with the virtual identity."""
        source_ip = route.get("_source_ip")
        if isinstance(source_ip, str) and source_ip:
            value = value.replace(source_ip, self.bind_ip)
        source_hostname = route.get("_source_hostname")
        if (
            isinstance(source_hostname, str)
            and source_hostname
            and self.advertised_hostname
        ):
            replacement = self.advertised_hostname.rstrip(".")
            value = value.replace(source_hostname.rstrip("."), replacement)
        return value

    async def _send_404(self, writer: asyncio.StreamWriter) -> None:
        """Send a minimal 404 response."""
        resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        writer.write(resp.encode("utf-8"))
        await writer.drain()

    def _check_credentials(
        self,
        headers: dict[str, str],
        body: str,
        *,
        body_complete: bool = True,
    ) -> str | None:
        """Return the canonical planted credential used by an HTTP request."""
        auth_values = self._header_values(headers, "authorization")
        bounded_auth_values = [
            value[:_MAX_CREDENTIAL_AUTH_SIZE] for value in auth_values
        ]
        bounded_body = body[:_MAX_CREDENTIAL_BODY_SIZE]

        # Preserve exact token/Bearer and body matching within the same bounds
        # enforced by the HTTP reader.
        for cred_val in self.credential_values:
            if not cred_val:
                continue
            if any(cred_val in value for value in bounded_auth_values):
                return cred_val
            if cred_val in bounded_body:
                return cred_val

        # HTTP Basic carries the canonical username:password value as base64.
        for auth in auth_values:
            if len(auth) > _MAX_CREDENTIAL_AUTH_SIZE:
                continue
            scheme = auth[:5]
            separator = auth[5:6]
            encoded = auth[5:].lstrip(" \t")
            if (
                scheme.casefold() == "basic"
                and separator in {" ", "\t"}
                and encoded
                and not any(char.isspace() for char in encoded)
            ):
                try:
                    decoded_bytes = base64.b64decode(
                        encoded.encode("ascii"),
                        validate=True,
                    )
                    if len(decoded_bytes) <= _MAX_CREDENTIAL_BODY_SIZE:
                        decoded = decoded_bytes.decode("utf-8", errors="strict")
                        if decoded in self.credential_values:
                            return decoded
                except (UnicodeDecodeError, UnicodeEncodeError, ValueError):
                    pass

        # Structured parsing is content-type gated and skipped entirely for
        # oversized bodies. Raw exact matching above remains available for the
        # bounded prefix, matching the prior runtime behavior.
        if (
            not body_complete
            or not body
            or len(body) > _MAX_CREDENTIAL_BODY_SIZE
        ):
            return None
        media_types = {
            value.partition(";")[0].strip().casefold()
            for value in self._header_values(headers, "content-type")
        }

        username: str | None = None
        password: str | None = None
        if "application/x-www-form-urlencoded" in media_types:
            try:
                fields = parse_qsl(
                    body,
                    keep_blank_values=True,
                    strict_parsing=True,
                    encoding="utf-8",
                    errors="strict",
                    max_num_fields=_MAX_CREDENTIAL_FORM_FIELDS,
                    separator="&",
                )
            except (UnicodeDecodeError, ValueError):
                return None

            login_fields: dict[str, str] = {}
            for key, value in fields:
                if key not in {"username", "password"}:
                    continue
                if key in login_fields:
                    return None
                login_fields[key] = value
            username = login_fields.get("username")
            password = login_fields.get("password")
        elif "application/json" in media_types:
            def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
                result: dict[str, object] = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate JSON object key")
                    result[key] = value
                return result

            def reject_constant(value: str) -> object:
                raise ValueError(f"invalid JSON constant: {value}")

            try:
                payload = json.loads(
                    body,
                    object_pairs_hook=unique_object,
                    parse_constant=reject_constant,
                )
            except (json.JSONDecodeError, RecursionError, ValueError):
                return None
            if isinstance(payload, dict):
                raw_username = payload.get("username")
                raw_password = payload.get("password")
                if isinstance(raw_username, str) and isinstance(raw_password, str):
                    username = raw_username
                    password = raw_password

        if username is not None and password is not None:
            canonical = f"{username}:{password}"
            if canonical in self.credential_values:
                return canonical
        return None

    @staticmethod
    def _header_values(headers: dict[str, str], name: str) -> list[str]:
        """Return every bounded value retained for a case-insensitive header."""
        values: list[str] = []
        for key, value in headers.items():
            if key.casefold() == name.casefold():
                values.extend(value.split("\n"))
        return values


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
        planted_credentials: list | None = None,
        port_remaps: dict[int, int] | None = None,
        tls_cert_pem: str | None = None,
        tls_key_pem: str | None = None,
        credentials_by_port: dict[int, list] | None = None,
        backend_bind_address: str | None = None,
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
        self._backend_bind_address = backend_bind_address or bind_address
        self._server_header = server_header
        self._planted_credentials = planted_credentials or []
        self._credentials_scoped = credentials_by_port is not None
        self._credentials_by_port = {
            int(port): list(credentials)
            for port, credentials in (credentials_by_port or {}).items()
        }
        self._endpoints: list[_MimicEndpoint] = []
        self._port_remaps = dict(port_remaps or {})
        self._dynamic_ports = {
            port for port, bind_port in self._port_remaps.items()
            if bind_port == 0
        }
        tls_required = any(bool(config.get("tls")) for config in port_configs)
        if tls_required and (not tls_cert_pem or not tls_key_pem):
            raise ValueError(
                "TLS mimic endpoints require a persisted certificate and key"
            )
        self._ssl_context = (
            server_ssl_context(tls_cert_pem, tls_key_pem)
            if tls_required and tls_cert_pem and tls_key_pem
            else None
        )

        self._credential_values: set[str] = {
            c.credential_value
            for c in self._planted_credentials
            if hasattr(c, "credential_value")
        }

    @property
    def port_remaps(self) -> dict[int, int]:
        """Port remappings: ``{advertised_port: actual_bind_port}``."""
        return dict(self._port_remaps)

    def replace_tls_identity(
        self,
        cert_pem: str,
        key_pem: str,
    ) -> None:
        """Use a newly persisted host certificate for future handshakes."""
        context = server_ssl_context(cert_pem, key_pem)
        self._ssl_context = context
        for endpoint in self._endpoints:
            if endpoint.ssl_context is not None:
                endpoint.ssl_context = context

    def rename_identity(
        self,
        hostname: str,
        *,
        cert_pem: str | None = None,
        key_pem: str | None = None,
    ) -> None:
        """Update live HTTP rewriting and, when present, TLS identity."""
        self.name = hostname
        for endpoint in self._endpoints:
            endpoint.advertised_hostname = hostname
        if cert_pem and key_pem:
            self.replace_tls_identity(cert_pem, key_pem)

    def _reset_dynamic_port_remaps(self) -> None:
        """Discard OS-assigned backend ports after listeners stop."""
        for port in self._dynamic_ports:
            self._port_remaps[port] = 0

    async def start(self) -> None:
        """Start every configured endpoint, or leave the mimic stopped.

        A partially bound mimic is misleading: the dashboard reports the
        decoy as active even though one or more of the advertised services
        cannot be reached. Treat the set of endpoints as one deployment and
        roll it back when any bind fails.
        """
        if not self._port_configs:
            raise RuntimeError("Mimic decoy has no configured endpoints")
        if self._endpoints:
            raise RuntimeError("Mimic decoy is already started")

        advertised_ports = {
            int(config["port"]) for config in self._port_configs
        }
        used_backend_ports: set[int] = set()
        try:
            for config in self._port_configs:
                advertised_port = config["port"]
                dynamic = advertised_port in self._dynamic_ports
                attempts = 16 if dynamic else 1
                for _attempt in range(attempts):
                    endpoint = _MimicEndpoint(
                        bind_ip=self._backend_bind_address,
                        port=advertised_port,
                        bind_port=(
                            0 if dynamic else self._port_remaps.get(
                                advertised_port,
                                advertised_port,
                            )
                        ),
                        routes=config.get("routes", []),
                        server_header=(
                            config.get("server_header")
                            or self._server_header
                        ),
                        protocol_banner=config.get("protocol_banner"),
                        connection_callback=self._on_connection,
                        credential_values={
                            credential.credential_value
                            for credential in self._credentials_by_port.get(
                                int(advertised_port),
                                [],
                            )
                            if hasattr(credential, "credential_value")
                        }
                        if self._credentials_scoped
                        else self._credential_values,
                        ssl_context=(
                            self._ssl_context if config.get("tls") else None
                        ),
                        advertised_hostname=self.name,
                    )
                    await endpoint.start()
                    backend_port = endpoint.bind_port
                    if (
                        dynamic
                        and (
                            backend_port in advertised_ports
                            or backend_port in used_backend_ports
                        )
                    ):
                        await endpoint.stop()
                        continue
                    if dynamic:
                        self._port_remaps[advertised_port] = backend_port
                    used_backend_ports.add(backend_port)
                    self._endpoints.append(endpoint)
                    break
                else:
                    raise RuntimeError(
                        "Could not allocate an isolated backend port for "
                        f"advertised port {advertised_port}"
                    )
        except Exception:
            logger.exception(
                "Failed to start all endpoints for mimic '%s' on %s; "
                "rolling back %d started endpoint(s)",
                self.name,
                self.bind_address,
                len(self._endpoints),
            )
            await asyncio.gather(
                *(endpoint.stop() for endpoint in self._endpoints),
                return_exceptions=True,
            )
            self._endpoints.clear()
            self._reset_dynamic_port_remaps()
            raise

        logger.info(
            "Mimic decoy '%s' started on %s with all %d endpoints",
            self.name, self.bind_address, len(self._endpoints),
        )

    async def stop(self) -> None:
        """Stop all mimic endpoints."""
        for endpoint in self._endpoints:
            await endpoint.stop()
        self._endpoints.clear()
        self._reset_dynamic_port_remaps()
        logger.info("Mimic decoy '%s' stopped", self.name)

    async def health_check(self) -> bool:
        """Check that every advertised endpoint is running."""
        return (
            len(self._endpoints) == len(self._port_configs)
            and len(self._endpoints) > 0
            and all(ep.is_running for ep in self._endpoints)
        )

    @property
    def is_running(self) -> bool:
        return (
            len(self._endpoints) == len(self._port_configs)
            and len(self._endpoints) > 0
            and all(ep.is_running for ep in self._endpoints)
        )


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
