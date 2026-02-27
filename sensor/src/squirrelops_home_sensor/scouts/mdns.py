"""mDNS service registration for mimic decoys.

Registers mDNS services with custom hostnames on virtual IPs so they
appear as individual devices during Bonjour/mDNS service discovery.
This adds a layer of authenticity to mimic decoys — network scanners
that browse mDNS services will see device-appropriate service types
(e.g., _smb._tcp for NAS mimics, _ipp._tcp for printer mimics).

Limitation: macOS mDNSResponder also responds to reverse DNS queries
for aliased IPs with the machine's real hostname.  This registration
mitigates service-level discovery but cannot fully override reverse
DNS on macOS.
"""

from __future__ import annotations

import hashlib
import logging
import socket

from zeroconf import ServiceInfo
from zeroconf.asyncio import AsyncZeroconf

logger = logging.getLogger("squirrelops_home_sensor.scouts")

# Device category -> plausible hostname prefixes.
# Uses real product names so the hostnames blend in on a home network.
_HOSTNAME_PREFIXES: dict[str, list[str]] = {
    "smart_home": ["tapo-plug", "kasa-smart", "wemo-mini", "hue-bridge", "tp-smart"],
    "camera": ["ipcam", "wyze-cam", "reolink-cam", "blink-mini"],
    "nas": ["synology-ds", "qnap-ts", "wd-mycloud"],
    "media": ["appletv", "roku-ultra", "chromecast", "fire-stick"],
    "printer": ["hp-envy", "epson-wf", "canon-mx"],
    "router": ["linksys-ea", "netgear-r", "asus-rt"],
    "dev_server": ["homelab", "dev-srv"],
    "generic": ["iot-device", "smart-device"],
}


def generate_mimic_hostname(
    mdns_name: str | None,
    device_category: str,
    virtual_ip: str,
) -> str:
    """Generate a deterministic, plausible hostname for a virtual IP.

    Uses the virtual IP as seed for deterministic output — the same IP
    always produces the same hostname across restarts.

    Parameters
    ----------
    mdns_name:
        Original device hostname (from scout data).  If provided, the
        generated name is a variation of it.
    device_category:
        Device type category for prefix selection.
    virtual_ip:
        The virtual IP address (used as deterministic seed).
    """
    digest = hashlib.md5(virtual_ip.encode()).hexdigest()
    suffix = digest[:4].upper()

    if mdns_name:
        base = mdns_name.rstrip(".").removesuffix(".local")
        return f"{base}-{suffix}"

    prefixes = _HOSTNAME_PREFIXES.get(device_category, _HOSTNAME_PREFIXES["generic"])
    idx = int(digest[4:8], 16) % len(prefixes)
    return f"{prefixes[idx]}-{suffix}"


class MimicMDNSAdvertiser:
    """Registers mDNS services with custom hostnames on virtual IPs.

    Each mimic decoy gets one mDNS service registered using a hostname
    derived from the original device's name or device category.  The
    zeroconf library creates an A record for the hostname -> virtual IP
    mapping, making the hostname resolvable via mDNS.
    """

    def __init__(self) -> None:
        self._zeroconf: AsyncZeroconf | None = None
        self._services: dict[int, list[ServiceInfo]] = {}

    async def start(self) -> None:
        """Initialize the mDNS responder."""
        self._zeroconf = AsyncZeroconf()
        logger.info("mDNS mimic advertiser started")

    async def register(
        self,
        decoy_id: int,
        virtual_ip: str,
        port: int,
        service_type: str | None,
        hostname: str,
    ) -> bool:
        """Register an mDNS service for a mimic decoy.

        Parameters
        ----------
        decoy_id:
            Database ID for tracking.
        virtual_ip:
            The virtual IP the mimic is bound to.
        port:
            Primary port for the service.
        service_type:
            mDNS service type (e.g. ``_http._tcp``).
            Falls back to ``_http._tcp`` if None.
        hostname:
            The hostname to advertise (without ``.local.``).
        """
        if self._zeroconf is None:
            return False

        svc_type = f"{service_type or '_http._tcp'}.local."
        fqdn = f"{hostname}.local."
        ip_bytes = socket.inet_aton(virtual_ip)

        info = ServiceInfo(
            type_=svc_type,
            name=f"{hostname}.{svc_type}",
            addresses=[ip_bytes],
            port=port,
            server=fqdn,
            properties={"name": hostname},
        )

        try:
            await self._zeroconf.async_register_service(info)
            self._services.setdefault(decoy_id, []).append(info)
            logger.info(
                "mDNS: registered '%s' (%s) on %s:%d",
                hostname, svc_type, virtual_ip, port,
            )
            return True
        except Exception as exc:
            logger.warning(
                "mDNS: failed to register service for mimic %d: %s",
                decoy_id, exc,
            )
            return False

    async def unregister(self, decoy_id: int) -> None:
        """Unregister all mDNS services for a mimic decoy."""
        services = self._services.pop(decoy_id, [])
        if not services or self._zeroconf is None:
            return

        for info in services:
            try:
                await self._zeroconf.async_unregister_service(info)
            except Exception:
                pass

        logger.debug(
            "mDNS: unregistered %d services for mimic %d",
            len(services), decoy_id,
        )

    async def stop(self) -> None:
        """Unregister all services and shut down."""
        if self._zeroconf is None:
            return

        for decoy_id in list(self._services.keys()):
            await self.unregister(decoy_id)

        await self._zeroconf.async_close()
        self._zeroconf = None
        logger.info("mDNS mimic advertiser stopped")
