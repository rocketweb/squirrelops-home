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
import re
import socket
from contextlib import suppress

from zeroconf import ServiceInfo
from zeroconf.asyncio import AsyncZeroconf

logger = logging.getLogger("squirrelops_home_sensor.scouts")

# Device category -> plausible low-drama hostnames.
_HOSTNAME_CHOICES: dict[str, list[str]] = {
    "smart_home": ["home", "hub", "control", "automation"],
    "camera": ["camera", "security", "garage-cam", "porch-cam"],
    "nas": ["files", "backup", "archive", "storage"],
    "media": ["media", "photos", "plex", "library"],
    "printer": ["printer", "scanner", "office-printer"],
    "router": ["gateway", "router", "network", "admin"],
    "dev_server": ["dev", "staging", "build", "api"],
    "generic": ["files", "media", "business", "office", "docs", "backup"],
}
_LEGACY_SUFFIX_RE = re.compile(r"-[0-9A-Fa-f]{4}$")
_HOST_LABEL_SANITIZER = re.compile(r"[^a-z0-9-]+")

_PORT_SERVICE_TYPES: dict[int, str] = {
    21: "_ftp._tcp",
    22: "_ssh._tcp",
    80: "_http._tcp",
    443: "_https._tcp",
    445: "_smb._tcp",
    548: "_afpovertcp._tcp",
    1883: "_mqtt._tcp",
    8123: "_home-assistant._tcp",
    8443: "_https._tcp",
    8883: "_mqtt._tcp",
    9100: "_pdl-datastream._tcp",
    32400: "_plexmediasvr._tcp",
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
    stable_token = hashlib.blake2s(
        virtual_ip.encode("utf-8"),
        digest_size=2,
        usedforsecurity=False,
    ).hexdigest()
    seed = int(stable_token, 16)

    source_label = str(mdns_name or "").strip().rstrip(".").lower()
    if source_label.endswith(".local"):
        source_label = source_label[:-6].rstrip(".")
    source_label = _HOST_LABEL_SANITIZER.sub("-", source_label).strip("-")
    source_label = re.sub(r"-+", "-", source_label)
    if source_label:
        # Always vary the discovered hostname. Advertising the real source name
        # would create an mDNS collision and make two IPs claim one identity.
        suffix = f"-{stable_token}"
        base = source_label[: 63 - len(suffix)].rstrip("-") or "decoy"
        return f"{base}{suffix}"

    choices = _HOSTNAME_CHOICES.get(device_category, _HOSTNAME_CHOICES["generic"])
    base = choices[seed % len(choices)]
    # The category vocabulary is intentionally small, but the service
    # instance and host labels must be unique across a Full profile. The
    # address suffix is stable, readable, and unique within the /24 pool.
    return f"{base}-{stable_token}"


def mdns_service_type_for(
    *,
    port: int,
    service_name: str | None,
    configured_type: str | None = None,
) -> str | None:
    """Return a credible Bonjour type for one actually emulated service."""
    # Merely finding CUPS/IPP open on a computer does not make that host a
    # network printer. Advertising every port-631 service as ``_ipp._tcp``
    # causes normal Bonjour clients to probe generic laptop/server mimics and
    # produces false intrusion alerts. Only a source classified as a printer
    # supplies the matching configured type.
    if port == 631:
        return "_ipp._tcp" if configured_type == "_ipp._tcp" else None

    mapped = _PORT_SERVICE_TYPES.get(port)
    if mapped is not None:
        return mapped

    normalized = str(service_name or "").strip().lower()
    if "http" in normalized:
        return "_http._tcp"
    if normalized == "ssh":
        return "_ssh._tcp"
    if normalized in {"smb", "file share"}:
        return "_smb._tcp"
    # Do not borrow a host/category-level type for an unrelated port. A camera
    # template, for example, must never make its RTSP listener look like HTTP.
    return None


def mimic_display_name(hostname: str) -> str:
    """Human-readable decoy name for UI and alerts."""
    clean = hostname.rstrip(".").removesuffix(".local")
    return f"{clean}.local"


def should_refresh_mimic_name(name: str, mdns_hostname: str | None) -> bool:
    """Return true for old generated names that should be replaced at startup."""
    if name.startswith("Mimic:"):
        return True
    return bool(mdns_hostname and _LEGACY_SUFFIX_RE.search(mdns_hostname))


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
        try:
            self._zeroconf = AsyncZeroconf()
        except OSError:
            self._zeroconf = None
            logger.warning(
                "mDNS mimic advertiser unavailable; continuing without it",
                exc_info=True,
            )
            return
        logger.info("mDNS mimic advertiser started")

    async def register(
        self,
        decoy_id: int,
        virtual_ip: str,
        port: int,
        service_type: str | None,
        hostname: str,
        instance_name: str | None = None,
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

        if service_type is None:
            return False
        svc_type = f"{service_type}.local."
        fqdn = f"{hostname}.local."
        ip_bytes = socket.inet_aton(virtual_ip)
        instance = instance_name or hostname

        info = ServiceInfo(
            type_=svc_type,
            name=f"{instance}.{svc_type}",
            addresses=[ip_bytes],
            port=port,
            server=fqdn,
            properties=self._properties_for(
                service_type=service_type,
                hostname=hostname,
            ),
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

    @staticmethod
    def _properties_for(
        *,
        service_type: str,
        hostname: str,
    ) -> dict[str, str]:
        """Return a small credible TXT set for the advertised protocol."""
        if service_type == "_ipp._tcp":
            return {
                "txtvers": "1",
                "qtotal": "1",
                "rp": "ipp/print",
                "ty": "Network Printer",
                "product": "(Network Printer)",
                "pdl": "application/pdf,image/urf",
            }
        if service_type in {"_http._tcp", "_https._tcp"}:
            return {"path": "/"}
        if service_type == "_pdl-datastream._tcp":
            return {"ty": "Network Printer", "product": "(Network Printer)"}
        if service_type == "_plexmediasvr._tcp":
            stable_id = hashlib.blake2s(
                hostname.encode("utf-8"),
                digest_size=8,
                usedforsecurity=False,
            ).hexdigest()
            return {
                "name": hostname,
                "machineIdentifier": stable_id,
                "version": "1.41.0",
            }
        return {}

    async def unregister(self, decoy_id: int) -> None:
        """Unregister all mDNS services for a mimic decoy."""
        services = self._services.pop(decoy_id, [])
        if not services or self._zeroconf is None:
            return

        for info in services:
            with suppress(Exception):
                await self._zeroconf.async_unregister_service(info)

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
