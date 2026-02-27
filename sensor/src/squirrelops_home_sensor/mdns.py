"""mDNS service advertisement for sensor discovery.

Advertises the sensor as a ``_squirrelops._tcp.local.`` service so the
macOS SwiftUI control-plane app can discover it via Bonjour / NWBrowser.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import subprocess
import sys

from zeroconf import ServiceInfo
from zeroconf.asyncio import AsyncZeroconf

logger = logging.getLogger("squirrelops_home_sensor")

# Standard private LAN ranges (RFC 1918).
_LAN_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)

# CGNAT range (RFC 6598) — used by Tailscale, carrier NAT, etc.
_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")


def _is_lan_ip(addr: str) -> bool:
    """Return True if *addr* is a standard private LAN address.

    Excludes CGNAT/Tailscale (``100.64.0.0/10``), link-local, and loopback
    so that VPN interfaces are not preferred over real LAN interfaces.
    """
    try:
        ip = ipaddress.IPv4Address(addr)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_link_local:
        return False
    if ip in _CGNAT_NETWORK:
        return False
    return any(ip in net for net in _LAN_NETWORKS)


def _collect_interface_ips() -> list[str]:
    """Collect all IPv4 addresses from network interfaces using OS tools.

    Uses ``ifconfig`` on macOS and ``ip -4 addr`` on Linux.  Returns a list
    of IPv4 address strings (excluding loopback).
    """
    import re

    ips: list[str] = []
    try:
        if sys.platform == "darwin":
            result = subprocess.run(
                ["ifconfig"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        else:
            result = subprocess.run(
                ["ip", "-4", "-o", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=5,
            )

        for addr in re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout):
            if not addr.startswith("127."):
                ips.append(addr)
    except Exception:
        pass

    return ips


def _get_local_ip() -> str:
    """Pick the best local IP for mDNS advertisement.

    Enumerates all network interfaces and prefers standard private LAN
    addresses (``10.x``, ``172.16-31.x``, ``192.168.x``) over VPN/CGNAT
    addresses (Tailscale ``100.x``).  Falls back to the UDP-to-8.8.8.8
    trick, then ``127.0.0.1``.
    """
    lan_ips: list[str] = []
    other_private_ips: list[str] = []

    for addr in _collect_interface_ips():
        if _is_lan_ip(addr):
            lan_ips.append(addr)
        else:
            try:
                ip = ipaddress.IPv4Address(addr)
                if ip.is_private and not ip.is_loopback:
                    other_private_ips.append(addr)
            except ValueError:
                pass

    if lan_ips:
        chosen = lan_ips[0]
        logger.debug("mDNS: selected LAN IP %s (candidates: %s)", chosen, lan_ips)
        return chosen

    if other_private_ips:
        chosen = other_private_ips[0]
        logger.debug("mDNS: no LAN IP found, using private IP %s", chosen)
        return chosen

    # Fallback: UDP socket trick (may return CGNAT/VPN IP, but better than nothing)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        logger.debug("mDNS: using UDP-detected IP %s", ip)
        return ip
    except Exception:
        return "127.0.0.1"


class ServiceAdvertiser:
    """Advertise the sensor over mDNS/DNS-SD.

    Parameters
    ----------
    name:
        Human-readable sensor name (e.g. ``"SquirrelOps Sensor"``).
    port:
        TCP port the sensor API is listening on.
    """

    service_type = "_squirrelops._tcp.local."

    def __init__(self, name: str, port: int) -> None:
        self.name = name
        self.port = port
        self._zeroconf: AsyncZeroconf | None = None
        self._info: ServiceInfo | None = None

    async def start(self) -> None:
        """Register the service on the local network."""
        ip = _get_local_ip()
        self._info = ServiceInfo(
            type_=self.service_type,
            name=f"{self.name}.{self.service_type}",
            addresses=[socket.inet_aton(ip)],
            port=self.port,
            properties={"name": self.name},
        )
        self._zeroconf = AsyncZeroconf()
        try:
            await self._zeroconf.async_register_service(self._info)
            logger.info("mDNS: advertising %s on %s:%d", self.name, ip, self.port)
        except Exception as exc:
            logger.warning("mDNS: failed to register service (%s) — sensor will run without mDNS discovery", exc)
            await self._zeroconf.async_close()
            self._zeroconf = None

    async def stop(self) -> None:
        """Unregister the service and close the responder."""
        if self._zeroconf is None:
            return

        await self._zeroconf.async_unregister_service(self._info)
        await self._zeroconf.async_close()
        logger.info("mDNS: stopped advertising")
