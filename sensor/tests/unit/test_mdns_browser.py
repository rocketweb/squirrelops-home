"""Unit tests for mDNS browser.

Tests cover:
- MDNSResult dataclass
- Service type list
- Result extraction from ServiceInfo mocks
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from squirrelops_home_sensor.scanner.mdns_browser import (
    BROWSE_SERVICE_TYPES,
    MDNSBrowser,
    MDNSResult,
    extract_result_from_info,
)


# ---------------------------------------------------------------------------
# MDNSResult dataclass
# ---------------------------------------------------------------------------

class TestMDNSResult:
    """Test MDNSResult dataclass."""

    def test_create_full_result(self) -> None:
        result = MDNSResult(
            ip="192.168.1.42",
            hostname="Living-Room.local.",
            service_types=frozenset({"_airplay._tcp.local.", "_raop._tcp.local."}),
        )
        assert result.ip == "192.168.1.42"
        assert result.hostname == "Living-Room.local."
        assert len(result.service_types) == 2

    def test_create_minimal_result(self) -> None:
        result = MDNSResult(ip="192.168.1.1", hostname=None, service_types=frozenset())
        assert result.ip == "192.168.1.1"
        assert result.hostname is None
        assert len(result.service_types) == 0


# ---------------------------------------------------------------------------
# Service types
# ---------------------------------------------------------------------------

class TestServiceTypes:
    """Verify the list of browsed service types."""

    def test_includes_common_types(self) -> None:
        assert "_http._tcp.local." in BROWSE_SERVICE_TYPES
        assert "_airplay._tcp.local." in BROWSE_SERVICE_TYPES
        assert "_googlecast._tcp.local." in BROWSE_SERVICE_TYPES
        assert "_hap._tcp.local." in BROWSE_SERVICE_TYPES

    def test_all_end_with_local(self) -> None:
        for st in BROWSE_SERVICE_TYPES:
            assert st.endswith(".local."), f"{st} does not end with .local."


# ---------------------------------------------------------------------------
# Result extraction from ServiceInfo
# ---------------------------------------------------------------------------

class TestExtractResultFromInfo:
    """Test extracting MDNSResult fields from a zeroconf ServiceInfo mock."""

    def test_extract_with_ipv4_and_server(self) -> None:
        info = MagicMock()
        info.parsed_addresses.return_value = ["192.168.1.42"]
        info.server = "Living-Room.local."
        info.type = "_airplay._tcp.local."

        result = extract_result_from_info(info)
        assert result is not None
        assert result["ip"] == "192.168.1.42"
        assert result["hostname"] == "Living-Room.local."
        assert result["service_type"] == "_airplay._tcp.local."

    def test_extract_no_addresses(self) -> None:
        info = MagicMock()
        info.parsed_addresses.return_value = []
        info.server = "device.local."
        info.type = "_http._tcp.local."

        result = extract_result_from_info(info)
        assert result is None

    def test_extract_no_server(self) -> None:
        info = MagicMock()
        info.parsed_addresses.return_value = ["192.168.1.10"]
        info.server = None
        info.type = "_http._tcp.local."

        result = extract_result_from_info(info)
        assert result is not None
        assert result["ip"] == "192.168.1.10"
        assert result["hostname"] is None

    def test_extract_filters_ipv6(self) -> None:
        """Only IPv4 addresses are returned."""
        info = MagicMock()
        info.parsed_addresses.return_value = ["fe80::1", "192.168.1.5"]
        info.server = "device.local."
        info.type = "_http._tcp.local."

        result = extract_result_from_info(info)
        assert result is not None
        assert result["ip"] == "192.168.1.5"
