"""SSDP/UPnP device discovery scanner.

Sends M-SEARCH multicast to discover UPnP devices on the local network,
then fetches device description XML from LOCATION URLs to extract
friendly names, manufacturers, and model information.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass
from urllib.parse import urlparse
from xml.etree import ElementTree

import httpx

logger = logging.getLogger(__name__)

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
UPNP_NS = "urn:schemas-upnp-org:device-1-0"

M_SEARCH_REQUEST = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


@dataclass(frozen=True)
class SSDPResult:
    """Result from SSDP/UPnP discovery for a single device."""

    ip: str
    friendly_name: str | None = None
    manufacturer: str | None = None
    model_name: str | None = None
    server_header: str | None = None


def parse_ssdp_response(raw: str, source_ip: str) -> dict | None:
    """Parse an SSDP M-SEARCH response into a dict of header values.

    Returns None if the response is missing a LOCATION header (required).
    """
    if not raw.strip():
        return None

    headers: dict[str, str] = {}
    for line in raw.split("\r\n"):
        if ":" in line and not line.startswith("HTTP/"):
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()

    location = headers.get("location")
    if not location:
        return None

    return {
        "location": location,
        "server": headers.get("server"),
        "usn": headers.get("usn"),
        "st": headers.get("st"),
        "source_ip": source_ip,
    }


def parse_upnp_xml(xml_text: str) -> dict | None:
    """Parse a UPnP device description XML and extract device metadata.

    Returns None if the XML is malformed or has no <device> element.
    """
    if not xml_text.strip():
        return None

    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return None

    # Try with UPnP namespace first, then without
    device = root.find(f"{{{UPNP_NS}}}device")
    if device is None:
        device = root.find("device")
    if device is None:
        return None

    def _text(tag: str) -> str | None:
        # Try namespaced, then bare
        el = device.find(f"{{{UPNP_NS}}}{tag}")
        if el is None:
            el = device.find(tag)
        return el.text if el is not None and el.text else None

    return {
        "friendly_name": _text("friendlyName"),
        "manufacturer": _text("manufacturer"),
        "model_name": _text("modelName"),
        "model_number": _text("modelNumber"),
    }


class SSDPScanner:
    """SSDP/UPnP device discovery scanner.

    Sends M-SEARCH multicast, collects responses, fetches device
    description XMLs, and returns rich device metadata.

    Parameters
    ----------
    collect_timeout:
        Seconds to collect SSDP responses.
    xml_fetch_timeout:
        Seconds to wait for each XML fetch.
    """

    def __init__(
        self,
        collect_timeout: float = 3.0,
        xml_fetch_timeout: float = 2.0,
    ) -> None:
        self._collect_timeout = collect_timeout
        self._xml_fetch_timeout = xml_fetch_timeout

    async def scan(self) -> list[SSDPResult]:
        """Send M-SEARCH and return discovered device results."""
        # Send M-SEARCH and collect raw responses
        responses = await self._send_msearch()

        # Parse responses and deduplicate LOCATION URLs
        parsed: list[dict] = []
        seen_locations: set[str] = set()
        for raw, source_ip in responses:
            result = parse_ssdp_response(raw, source_ip)
            if result and result["location"] not in seen_locations:
                seen_locations.add(result["location"])
                parsed.append(result)

        # Fetch and parse XML descriptions
        results: list[SSDPResult] = []
        xml_cache: dict[str, dict | None] = {}

        async with httpx.AsyncClient(timeout=self._xml_fetch_timeout, verify=False) as client:
            for resp in parsed:
                location = resp["location"]
                if location not in xml_cache:
                    xml_cache[location] = await self._fetch_xml(client, location)

                xml_data = xml_cache[location]
                source_ip = resp["source_ip"]

                if xml_data:
                    results.append(SSDPResult(
                        ip=source_ip,
                        friendly_name=xml_data.get("friendly_name"),
                        manufacturer=xml_data.get("manufacturer"),
                        model_name=xml_data.get("model_name"),
                        server_header=resp.get("server"),
                    ))
                else:
                    # No XML but we still have server header
                    results.append(SSDPResult(
                        ip=source_ip,
                        server_header=resp.get("server"),
                    ))

        # Deduplicate by IP (keep the richest result)
        by_ip: dict[str, SSDPResult] = {}
        for r in results:
            existing = by_ip.get(r.ip)
            if existing is None or (r.friendly_name and not existing.friendly_name):
                by_ip[r.ip] = r
        return list(by_ip.values())

    async def _send_msearch(self) -> list[tuple[str, str]]:
        """Send M-SEARCH multicast and collect responses.

        Returns list of (raw_response, source_ip) tuples.
        """
        responses: list[tuple[str, str]] = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0)

            sock.sendto(M_SEARCH_REQUEST.encode(), (SSDP_ADDR, SSDP_PORT))

            loop = asyncio.get_running_loop()
            deadline = loop.time() + self._collect_timeout

            while loop.time() < deadline:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    data, addr = await asyncio.wait_for(
                        loop.run_in_executor(None, lambda: sock.recvfrom(4096)),
                        timeout=min(remaining, 0.5),
                    )
                    responses.append((data.decode("utf-8", errors="replace"), addr[0]))
                except (asyncio.TimeoutError, OSError):
                    continue

            sock.close()
        except OSError:
            logger.warning("Failed to send SSDP M-SEARCH", exc_info=True)

        logger.info("SSDP collected %d responses", len(responses))
        return responses

    async def _fetch_xml(self, client: httpx.AsyncClient, url: str) -> dict | None:
        """Fetch and parse a UPnP device description XML."""
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            return parse_upnp_xml(resp.text)
        except Exception:
            logger.debug("Failed to fetch UPnP XML from %s", url, exc_info=True)
            return None
