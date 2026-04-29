"""Helpers for carrying verified TLS client certificates into ASGI scopes."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
from typing import Any

from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.protocols.websockets.websockets_impl import WebSocketProtocol

logger = logging.getLogger(__name__)

_TLS_EXTENSION_KEY = "tls"
_CLIENT_CERT_DER_KEY = "client_cert_der"


def add_client_cert_to_scope(scope: Any, transport: asyncio.Transport) -> None:
    """Add the peer certificate DER bytes to an ASGI scope when TLS provided one."""
    ssl_object = transport.get_extra_info("ssl_object")
    if not isinstance(ssl_object, ssl.SSLObject):
        return

    try:
        cert_der = ssl_object.getpeercert(binary_form=True)
    except ssl.SSLError:
        logger.debug("Could not read TLS peer certificate", exc_info=True)
        return

    if not cert_der:
        return

    extensions = scope.setdefault("extensions", {})
    tls_extension = extensions.setdefault(_TLS_EXTENSION_KEY, {})
    tls_extension[_CLIENT_CERT_DER_KEY] = cert_der


def client_cert_fingerprint_from_scope(scope: Any) -> str | None:
    """Return the SHA-256 fingerprint for the verified TLS client certificate."""
    extensions = scope.get("extensions")
    if not isinstance(extensions, dict):
        return None
    tls_extension = extensions.get(_TLS_EXTENSION_KEY)
    if not isinstance(tls_extension, dict):
        return None
    cert_der = tls_extension.get(_CLIENT_CERT_DER_KEY)
    if not isinstance(cert_der, bytes):
        return None
    return f"sha256:{hashlib.sha256(cert_der).hexdigest()}"


class ClientCertH11Protocol(H11Protocol):
    """Uvicorn HTTP protocol that exposes verified peer certs to FastAPI."""

    def handle_events(self) -> None:
        super().handle_events()
        if self.scope is not None and self.transport is not None:
            add_client_cert_to_scope(self.scope, self.transport)


class ClientCertWebSocketProtocol(WebSocketProtocol):
    """Uvicorn WebSocket protocol that exposes verified peer certs to FastAPI."""

    async def run_asgi(self) -> None:
        if self.scope is not None and self.transport is not None:
            add_client_cert_to_scope(self.scope, self.transport)
        await super().run_asgi()
