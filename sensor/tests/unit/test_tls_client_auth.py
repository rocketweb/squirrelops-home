"""Tests for transport-derived TLS authentication scope data."""

from __future__ import annotations

import ssl
from unittest.mock import MagicMock

from squirrelops_home_sensor.tls_client_auth import add_client_cert_to_scope


def test_tls_transport_is_recorded_without_client_certificate() -> None:
    """Actual TLS remains visible even when the peer supplied no certificate."""
    ssl_object = MagicMock(spec=ssl.SSLObject)
    ssl_object.getpeercert.return_value = None
    transport = MagicMock()
    transport.get_extra_info.return_value = ssl_object
    scope: dict = {}

    add_client_cert_to_scope(scope, transport)

    assert isinstance(scope.get("extensions", {}).get("tls"), dict)
