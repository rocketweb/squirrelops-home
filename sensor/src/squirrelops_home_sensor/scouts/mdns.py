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
import ipaddress
import logging
import os
import re
import socket
from collections.abc import Iterable
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
_GENERAL_HOSTNAME_CHOICES = [
    "files",
    "media",
    "office",
    "docs",
    "backup",
    "archive",
    "storage",
    "shared",
    "library",
    "photos",
    "printer",
    "scanner",
    "home",
    "hub",
    "control",
    "automation",
    "gateway",
    "network",
    "admin",
    "dev",
    "staging",
    "build",
    "api",
    "camera",
    "security",
    "records",
    "vault",
    "workroom",
    "studio",
    "business",
]
_COMPOUND_MODIFIERS = [
    "main",
    "central",
    "shared",
    "home",
    "office",
    "family",
    "work",
    "north",
    "south",
    "east",
    "west",
]
_LEGACY_SUFFIX_RE = re.compile(r"-[0-9A-Fa-f]{4}$")
_HOST_LABEL_SANITIZER = re.compile(r"[^a-z0-9-]+")
_TERMINAL_IDENTIFIER_RE = re.compile(r"(?:^|-)(?:[a-z]{0,10})?\d{1,4}$")

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
    *,
    existing_hostnames: Iterable[str] = (),
    suggested_names: Iterable[str] = (),
    allow_identifiers: bool | None = None,
) -> str:
    """Generate a deterministic, plausible, collision-free hostname.

    AI suggestions are untrusted inputs and are accepted only after the same
    local normalization and collision checks as deterministic candidates.
    Address-derived identifiers are used only when the observed network already
    follows a terminal-identifier convention.

    Parameters
    ----------
    mdns_name:
        Original device hostname. It contributes to style detection but is
        never cloned into a fake-host identity.
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
    observed = [str(value) for value in existing_hostnames]
    if mdns_name:
        observed.append(str(mdns_name))
    existing = {
        label
        for value in existing_hostnames
        if (label := _normalize_hostname_label(value)) is not None
    }
    if allow_identifiers is None:
        allow_identifiers = network_uses_host_identifiers(observed)

    category_choices = _HOSTNAME_CHOICES.get(
        device_category,
        _HOSTNAME_CHOICES["generic"],
    )
    category_offset = seed % len(category_choices)
    ordered_category = (
        category_choices[category_offset:] + category_choices[:category_offset]
    )
    deterministic = list(
        dict.fromkeys(ordered_category + _GENERAL_HOSTNAME_CHOICES)
    )

    compounds = [
        f"{modifier}-{base}"
        for modifier in _COMPOUND_MODIFIERS
        for base in deterministic
    ]
    candidates = [*suggested_names, *deterministic, *compounds]
    for candidate in candidates:
        label = _normalize_hostname_label(candidate)
        if label is None or label in existing:
            continue
        if _is_ip_address(label):
            continue
        if not allow_identifiers and (
            _TERMINAL_IDENTIFIER_RE.search(label)
            or _LEGACY_SUFFIX_RE.search(label)
        ):
            continue
        return label

    if allow_identifiers:
        for candidate in deterministic:
            label = _normalize_hostname_label(f"{candidate}-{seed % 100:02d}")
            if label is not None and label not in existing:
                return label

    # The semantic candidate space is deliberately much larger than the
    # supported fake-host ceiling. Reaching this means a caller supplied
    # hundreds of collisions and there is no honest identifier-free name left.
    raise ValueError("No collision-free fake-host name is available")


def _normalize_hostname_label(value: object) -> str | None:
    """Return one safe DNS label or ``None`` for an unusable suggestion."""
    label = str(value or "").strip().rstrip(".").lower()
    for suffix in (".localdomain", ".local"):
        if label.endswith(suffix):
            label = label[: -len(suffix)].rstrip(".")
            break
    label = _HOST_LABEL_SANITIZER.sub("-", label).strip("-")
    label = re.sub(r"-+", "-", label)[:63].rstrip("-")
    if not label or label in {"localhost", "local", "localdomain", "broadcasthost"}:
        return None
    return label


def _is_ip_address(label: str) -> bool:
    try:
        ipaddress.ip_address(label)
    except ValueError:
        return False
    return True


def network_uses_host_identifiers(hostnames: Iterable[str]) -> bool:
    """Detect a repeated terminal numeric identifier convention.

    Requiring a repeated pattern avoids treating one product/model hostname,
    such as ``iphone-15-pro``, as a network-wide naming convention.
    """
    labels = [
        label
        for value in hostnames
        if (label := _normalize_hostname_label(value)) is not None
    ]
    matches = [
        label
        for label in labels
        if _TERMINAL_IDENTIFIER_RE.search(label)
    ]
    if len(labels) <= 2:
        return bool(matches)
    return len(matches) >= 2


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
        self._helper = None

    async def start(self) -> None:
        """Initialize the mDNS responder."""
        helper_socket = os.environ.get("SQUIRRELOPS_NETWORK_HELPER_SOCKET", "")
        if helper_socket:
            from squirrelops_home_sensor.privileged.linux_sidecar import (
                LinuxNetworkHelperClient,
            )

            helper = LinuxNetworkHelperClient(helper_socket)
            if await helper.is_available():
                self._helper = helper
                logger.info("mDNS mimic advertiser delegated to Linux helper")
                return
            logger.warning("mDNS network helper is unavailable")
            return
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
        if self._helper is not None:
            if service_type is None:
                return False
            return await self._helper.register_mdns(
                registration_id=f"mimic:{decoy_id}:{port}",
                virtual_ip=virtual_ip,
                port=port,
                service_type=service_type,
                hostname=hostname,
                instance_name=instance_name or hostname,
                properties=self._properties_for(
                    service_type=service_type,
                    hostname=hostname,
                ),
            )

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
        if self._helper is not None:
            await self._helper.unregister_mdns(f"mimic:{decoy_id}")
            return
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
        if self._helper is not None:
            await self._helper.unregister_mdns("mimic")
            self._helper = None
            return
        if self._zeroconf is None:
            return

        for decoy_id in list(self._services.keys()):
            await self.unregister(decoy_id)

        await self._zeroconf.async_close()
        self._zeroconf = None
        logger.info("mDNS mimic advertiser stopped")
