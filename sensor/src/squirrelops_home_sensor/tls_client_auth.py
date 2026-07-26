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
    """Record the TLS transport and any peer certificate in an ASGI scope."""
    ssl_object = transport.get_extra_info("ssl_object")
    if not isinstance(ssl_object, ssl.SSLObject):
        return

    # Transport security is independent of whether the peer supplied a
    # certificate. Keep this server-derived signal in the scope so auth never
    # has to trust proxy-rewritable scheme data.
    extensions = scope.setdefault("extensions", {})
    tls_extension = extensions.setdefault(_TLS_EXTENSION_KEY, {})

    try:
        cert_der = ssl_object.getpeercert(binary_form=True)
    except ssl.SSLError:
        logger.debug("Could not read TLS peer certificate", exc_info=True)
        return

    if not cert_der:
        return

    tls_extension[_CLIENT_CERT_DER_KEY] = cert_der


def is_tls_transport(scope: Any) -> bool:
    """Return whether the server transport, rather than a header, established TLS."""
    extensions = scope.get("extensions")
    if not isinstance(extensions, dict):
        return False
    return isinstance(extensions.get(_TLS_EXTENSION_KEY), dict)


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
