"""mDNS service browser for device discovery.

Uses the zeroconf library to browse common service types and collect
hostnames, IPs, and service type information from the local network.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from zeroconf import IPVersion, ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

logger = logging.getLogger(__name__)

# Common service types to browse
BROWSE_SERVICE_TYPES: list[str] = [
    "_http._tcp.local.",
    "_airplay._tcp.local.",
    "_googlecast._tcp.local.",
    "_sonos._tcp.local.",
    "_hap._tcp.local.",
    "_raop._tcp.local.",
    "_smb._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
]


@dataclass(frozen=True)
class MDNSResult:
    """Result from mDNS browsing for a single device."""

    ip: str
    hostname: str | None = None
    service_types: frozenset[str] = frozenset()


def extract_result_from_info(info) -> dict | None:
    """Extract IP, hostname, and service type from a zeroconf ServiceInfo.

    Returns None if no IPv4 address is available.
    """
    addresses = info.parsed_addresses()
    # Filter to IPv4 only
    ipv4_addrs = [a for a in addresses if ":" not in a]
    if not ipv4_addrs:
        return None

    return {
        "ip": ipv4_addrs[0],
        "hostname": info.server if info.server else None,
        "service_type": info.type,
    }


class MDNSBrowseCollector:
    """Collects mDNS browse results during a timed browse window."""

    def __init__(self) -> None:
        self.discovered: dict[str, dict] = {}  # ip -> {hostname, service_types}

    def add(self, ip: str, hostname: str | None, service_type: str) -> None:
        if ip not in self.discovered:
            self.discovered[ip] = {"hostname": hostname, "service_types": set()}
        # Update hostname if we got a better one
        if hostname and not self.discovered[ip]["hostname"]:
            self.discovered[ip]["hostname"] = hostname
        self.discovered[ip]["service_types"].add(service_type)

    def results(self) -> list[MDNSResult]:
        return [
            MDNSResult(
                ip=ip,
                hostname=data["hostname"],
                service_types=frozenset(data["service_types"]),
            )
            for ip, data in self.discovered.items()
        ]


class MDNSBrowser:
    """Browse the local network for mDNS services.

    Parameters
    ----------
    browse_timeout:
        Seconds to collect browse results.
    service_types:
        Service types to browse. Defaults to common types.
    """

    def __init__(
        self,
        browse_timeout: float = 3.0,
        service_types: list[str] | None = None,
    ) -> None:
        self._browse_timeout = browse_timeout
        self._service_types = service_types or BROWSE_SERVICE_TYPES

    async def browse(self) -> list[MDNSResult]:
        """Browse for mDNS services and return results."""
        collector = MDNSBrowseCollector()

        try:
            aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only)

            async def on_service_state_change(
                zeroconf: Zeroconf,
                service_type: str,
                name: str,
                state_change: ServiceStateChange,
            ) -> None:
                if state_change != ServiceStateChange.Added:
                    return
                info = AsyncServiceInfo(service_type, name)
                await info.async_request(zeroconf, 1500)
                extracted = extract_result_from_info(info)
                if extracted:
                    collector.add(
                        extracted["ip"],
                        extracted["hostname"],
                        extracted["service_type"],
                    )

            browser = AsyncServiceBrowser(
                aiozc.zeroconf,
                self._service_types,
                handlers=[on_service_state_change],
            )

            await asyncio.sleep(self._browse_timeout)
            await browser.async_cancel()
            await aiozc.async_close()

        except OSError:
            logger.warning("mDNS browse failed", exc_info=True)

        results = collector.results()
        logger.info("mDNS browse found %d devices", len(results))
        return results
