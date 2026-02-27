"""Port forwarding manager for mimic decoys.

On macOS, unprivileged processes cannot bind to ports below 1024.
Mimic decoys need to serve on the same ports as the real devices
they're impersonating (e.g. 22, 80, 443). This module remaps
privileged ports to high ports (port + 10000) and uses pfctl/iptables
to redirect incoming traffic from the original port to the high port.

macOS: pfctl rdr rules loaded into the ``com.apple/squirrelops`` anchor.
Linux: iptables DNAT rules in a ``SQUIRRELOPS_MIMIC`` chain.
"""

from __future__ import annotations

import logging

from squirrelops_home_sensor.privileged.helper import PrivilegedOperations

logger = logging.getLogger("squirrelops_home_sensor.network")

PRIVILEGED_PORT_THRESHOLD = 1024
PORT_OFFSET = 10000


def remap_port(port: int) -> int:
    """Return the high port a mimic endpoint should bind to.

    Ports below 1024 are remapped to port + 10000.
    Ports 1024+ are returned unchanged.
    """
    if port < PRIVILEGED_PORT_THRESHOLD:
        return port + PORT_OFFSET
    return port


def needs_remap(port: int) -> bool:
    """Check if a port requires remapping to avoid privilege issues."""
    return port < PRIVILEGED_PORT_THRESHOLD


class PortForwardManager:
    """Manages port forwarding rules for mimic decoys.

    Tracks port remappings per decoy and syncs all rules atomically
    to the system's packet filter (pfctl on macOS, iptables on Linux).

    Parameters
    ----------
    privileged_ops:
        Platform-specific privileged operations implementation.
    interface:
        Network interface for forwarding rules (default "en0").
    """

    def __init__(
        self,
        privileged_ops: PrivilegedOperations,
        interface: str = "en0",
    ) -> None:
        self._priv_ops = privileged_ops
        self._interface = interface
        self._rules: dict[int, list[dict]] = {}  # decoy_id -> list of rules

    async def add_forwards(
        self,
        decoy_id: int,
        bind_ip: str,
        port_remaps: dict[int, int],
    ) -> bool:
        """Add port forward rules for a decoy and sync to system.

        Parameters
        ----------
        decoy_id:
            Database ID for tracking.
        bind_ip:
            The virtual IP address.
        port_remaps:
            Dict of ``{original_port: actual_bind_port}`` for remapped ports.
        """
        if not port_remaps:
            return True

        rules = [
            {
                "from_ip": bind_ip,
                "from_port": from_port,
                "to_ip": bind_ip,
                "to_port": to_port,
            }
            for from_port, to_port in port_remaps.items()
        ]

        self._rules[decoy_id] = rules
        return await self._sync_rules()

    async def remove_forwards(self, decoy_id: int) -> bool:
        """Remove port forward rules for a decoy and sync to system."""
        if decoy_id not in self._rules:
            return True

        del self._rules[decoy_id]
        return await self._sync_rules()

    async def clear_all(self) -> bool:
        """Clear all port forwarding rules from system and internal state."""
        self._rules.clear()
        try:
            return await self._priv_ops.clear_port_forwards()
        except Exception:
            logger.exception("Failed to clear port forwards")
            return False

    async def _sync_rules(self) -> bool:
        """Sync all accumulated rules atomically to the system."""
        all_rules: list[dict] = []
        for rules in self._rules.values():
            all_rules.extend(rules)

        try:
            if not all_rules:
                return await self._priv_ops.clear_port_forwards()
            return await self._priv_ops.setup_port_forwards(
                rules=all_rules, interface=self._interface,
            )
        except Exception:
            logger.exception("Failed to sync port forward rules")
            return False

    @property
    def active_rule_count(self) -> int:
        """Total number of active port forward rules across all decoys."""
        return sum(len(rules) for rules in self._rules.values())
