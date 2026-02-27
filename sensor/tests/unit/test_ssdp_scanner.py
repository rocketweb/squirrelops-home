"""Unit tests for SSDP/UPnP scanner.

Tests cover:
- SSDP response header parsing
- UPnP device description XML parsing
- SSDPResult dataclass
- Edge cases (missing fields, malformed XML, empty responses)
"""
from __future__ import annotations

import pytest

from squirrelops_home_sensor.scanner.ssdp_scanner import (
    SSDPResult,
    parse_ssdp_response,
    parse_upnp_xml,
)


# ---------------------------------------------------------------------------
# SSDP response parsing
# ---------------------------------------------------------------------------

class TestParseSSDPResponse:
    """Test parsing of SSDP M-SEARCH response headers."""

    def test_parse_full_response(self) -> None:
        """All standard headers are extracted."""
        raw = (
            "HTTP/1.1 200 OK\r\n"
            "LOCATION: http://192.168.1.42:49152/description.xml\r\n"
            "SERVER: Linux/4.4, UPnP/1.0, Sonos/70.3-12345\r\n"
            "USN: uuid:RINCON_48A6B88E5FA10100::urn:schemas-upnp-org:device:ZonePlayer:1\r\n"
            "ST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n"
            "\r\n"
        )
        result = parse_ssdp_response(raw, "192.168.1.42")
        assert result is not None
        assert result["location"] == "http://192.168.1.42:49152/description.xml"
        assert "Sonos" in result["server"]
        assert result["usn"] is not None
        assert result["st"] is not None

    def test_parse_missing_location(self) -> None:
        """Response without LOCATION returns None."""
        raw = (
            "HTTP/1.1 200 OK\r\n"
            "SERVER: Linux UPnP\r\n"
            "\r\n"
        )
        result = parse_ssdp_response(raw, "192.168.1.1")
        assert result is None

    def test_parse_case_insensitive_headers(self) -> None:
        """Header names are matched case-insensitively."""
        raw = (
            "HTTP/1.1 200 OK\r\n"
            "location: http://192.168.1.1:80/desc.xml\r\n"
            "server: MyDevice/1.0\r\n"
            "\r\n"
        )
        result = parse_ssdp_response(raw, "192.168.1.1")
        assert result is not None
        assert result["location"] == "http://192.168.1.1:80/desc.xml"

    def test_parse_empty_response(self) -> None:
        """Empty string returns None."""
        assert parse_ssdp_response("", "192.168.1.1") is None


# ---------------------------------------------------------------------------
# UPnP XML parsing
# ---------------------------------------------------------------------------

class TestParseUPnPXML:
    """Test parsing of UPnP device description XML."""

    def test_parse_full_xml(self) -> None:
        """All device fields are extracted from well-formed XML."""
        xml = """<?xml version="1.0"?>
        <root xmlns="urn:schemas-upnp-org:device-1-0">
          <device>
            <friendlyName>Living Room Speaker</friendlyName>
            <manufacturer>Sonos, Inc.</manufacturer>
            <modelName>Sonos One</modelName>
            <modelNumber>S13</modelNumber>
          </device>
        </root>"""
        result = parse_upnp_xml(xml)
        assert result is not None
        assert result["friendly_name"] == "Living Room Speaker"
        assert result["manufacturer"] == "Sonos, Inc."
        assert result["model_name"] == "Sonos One"
        assert result["model_number"] == "S13"

    def test_parse_partial_xml(self) -> None:
        """XML with only friendlyName still parses."""
        xml = """<?xml version="1.0"?>
        <root xmlns="urn:schemas-upnp-org:device-1-0">
          <device>
            <friendlyName>My Device</friendlyName>
          </device>
        </root>"""
        result = parse_upnp_xml(xml)
        assert result is not None
        assert result["friendly_name"] == "My Device"
        assert result["manufacturer"] is None
        assert result["model_name"] is None

    def test_parse_no_namespace_xml(self) -> None:
        """XML without the UPnP namespace still parses."""
        xml = """<?xml version="1.0"?>
        <root>
          <device>
            <friendlyName>Router</friendlyName>
            <manufacturer>ASUS</manufacturer>
            <modelName>RT-AX86U</modelName>
          </device>
        </root>"""
        result = parse_upnp_xml(xml)
        assert result is not None
        assert result["friendly_name"] == "Router"
        assert result["manufacturer"] == "ASUS"

    def test_parse_malformed_xml(self) -> None:
        """Malformed XML returns None."""
        assert parse_upnp_xml("<not>valid<xml") is None

    def test_parse_empty_xml(self) -> None:
        """Empty string returns None."""
        assert parse_upnp_xml("") is None

    def test_parse_xml_no_device_element(self) -> None:
        """XML without <device> element returns None."""
        xml = """<?xml version="1.0"?>
        <root xmlns="urn:schemas-upnp-org:device-1-0">
          <specVersion><major>1</major></specVersion>
        </root>"""
        assert parse_upnp_xml(xml) is None


# ---------------------------------------------------------------------------
# SSDPResult dataclass
# ---------------------------------------------------------------------------

class TestSSDPResult:
    """Test SSDPResult dataclass."""

    def test_create_full_result(self) -> None:
        result = SSDPResult(
            ip="192.168.1.42",
            friendly_name="Living Room Speaker",
            manufacturer="Sonos, Inc.",
            model_name="Sonos One",
            server_header="Linux/4.4 UPnP/1.0 Sonos/70.3",
        )
        assert result.ip == "192.168.1.42"
        assert result.friendly_name == "Living Room Speaker"
        assert result.manufacturer == "Sonos, Inc."
        assert result.model_name == "Sonos One"

    def test_create_minimal_result(self) -> None:
        result = SSDPResult(ip="192.168.1.1")
        assert result.ip == "192.168.1.1"
        assert result.friendly_name is None
        assert result.manufacturer is None
        assert result.model_name is None
        assert result.server_header is None
