"""Mimic template generator — creates decoy configs from scout profiles.

Analyzes ServiceProfile data and generates route configurations that
replicate real device responses. Templates include HTTP routes, server
headers, credential injection points, and mDNS advertisement info.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from squirrelops_home_sensor.scouts.engine import ServiceProfile

logger = logging.getLogger("squirrelops_home_sensor.scouts")

# Device category → credential types to plant
_CREDENTIAL_STRATEGY: dict[str, list[str]] = {
    "smart_home": ["ha_token"],
    "camera": ["password"],
    "nas": ["password", "ssh_key"],
    "media": ["password"],
    "printer": ["password"],
    "router": ["password"],
    "dev_server": ["env_file"],
    "generic": ["password"],
}

# mDNS service types by device category
_MDNS_SERVICES: dict[str, str] = {
    "smart_home": "_home-assistant._tcp",
    "camera": "_http._tcp",
    "nas": "_smb._tcp",
    "media": "_airplay._tcp",
    "printer": "_ipp._tcp",
    "router": "_http._tcp",
}


@dataclass
class MimicTemplate:
    """Complete template for deploying a mimic decoy."""

    source_device_id: int | None
    source_ip: str
    device_category: str
    routes: list[dict]
    server_header: str | None = None
    credential_types: list[str] = field(default_factory=list)
    mdns_service_type: str | None = None
    mdns_name: str | None = None
    ports: list[int] = field(default_factory=list)


class MimicTemplateGenerator:
    """Generates mimic decoy templates from scout profile data."""

    def generate(
        self,
        profiles: list[ServiceProfile],
        device_type: str,
        hostname: str | None = None,
    ) -> MimicTemplate:
        """Create a mimic template from scout profiles for a device.

        Parameters
        ----------
        profiles:
            Service profiles for all ports on the target device.
        device_type:
            The device type (from device classification).
        hostname:
            Optional hostname for mDNS advertisement.
        """
        if not profiles:
            return MimicTemplate(
                source_device_id=None,
                source_ip="",
                device_category="generic",
                routes=[],
            )

        first = profiles[0]
        category = self._categorize(device_type)
        routes = self._build_routes(profiles)
        server_header = self._pick_server_header(profiles)
        credential_types = _CREDENTIAL_STRATEGY.get(category, ["password"])
        mdns_service = _MDNS_SERVICES.get(category)
        ports = sorted({p.port for p in profiles})

        return MimicTemplate(
            source_device_id=first.device_id,
            source_ip=first.ip_address,
            device_category=category,
            routes=routes,
            server_header=server_header,
            credential_types=credential_types,
            mdns_service_type=mdns_service,
            mdns_name=hostname,
            ports=ports,
        )

    def _categorize(self, device_type: str) -> str:
        """Map device_type to a mimic category."""
        mapping = {
            "smart_home": "smart_home",
            "camera": "camera",
            "nas": "nas",
            "media": "media",
            "printer": "printer",
            "router": "router",
            "network": "router",
            "computer": "dev_server",
        }
        return mapping.get(device_type, "generic")

    def _build_routes(self, profiles: list[ServiceProfile]) -> list[dict]:
        """Build HTTP route configs from profiles with HTTP data."""
        routes: list[dict] = []
        for profile in profiles:
            if profile.http_status is None:
                continue

            route = {
                "path": "/",
                "method": "GET",
                "port": profile.port,
                "status": profile.http_status,
                "headers": profile.http_headers or {},
                "body": profile.http_body_snippet or "",
            }

            # Strip out hop-by-hop headers that shouldn't be replayed
            for hdr in ("transfer-encoding", "connection", "keep-alive",
                        "content-length", "content-encoding"):
                route["headers"].pop(hdr, None)

            routes.append(route)

        return routes

    def _pick_server_header(self, profiles: list[ServiceProfile]) -> str | None:
        """Pick the most common Server header from profiles."""
        servers: list[str] = []
        for p in profiles:
            if p.http_server_header:
                servers.append(p.http_server_header)

        if not servers:
            return None

        # Return the most common one
        from collections import Counter
        counter = Counter(servers)
        return counter.most_common(1)[0][0]
