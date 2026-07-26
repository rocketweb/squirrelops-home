"""Port forwarding and host-isolation manager for mimic decoys.

Every advertised mimic port is redirected to a private runtime listener.
Using a distinct backend even for high ports prevents a wildcard-bound host
daemon from answering on the virtual IP when the mimic stops or cannot bind.
Legacy helpers for deterministic privileged-port remapping remain available
for callers and migrations; live mimics use OS-assigned backend ports.

macOS: pfctl rdr rules loaded into the ``com.apple/squirrelops`` anchor.
Linux: iptables DNAT rules in a ``SQUIRRELOPS_MIMIC`` chain.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from functools import wraps
from typing import Any

from squirrelops_home_sensor.privileged.helper import PrivilegedOperations

logger = logging.getLogger("squirrelops_home_sensor.network")

PRIVILEGED_PORT_THRESHOLD = 1024
PORT_OFFSET = 10000


def _serialized_mutation(method: Any) -> Any:
    """Run each complete PF state transition under one lock."""

    @wraps(method)
    async def wrapped(self: PortForwardManager, *args: Any, **kwargs: Any) -> Any:
        async with self._mutation_lock:
            return await method(self, *args, **kwargs)

    return wrapped


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
        self._protected_endpoints: dict[int, dict] = {}
        self._mutation_lock = asyncio.Lock()

    @_serialized_mutation
    async def add_forwards(
        self,
        decoy_id: int,
        bind_ip: str,
        port_remaps: dict[int, int],
        exposed_ports: Iterable[int] | None = None,
    ) -> bool:
        """Add forwarding and host-isolation rules for a decoy.

        Parameters
        ----------
        decoy_id:
            Database ID for tracking.
        bind_ip:
            The virtual IP address.
        port_remaps:
            Dict of ``{advertised_port: private_bind_port}`` for every port.
        exposed_ports:
            Every TCP port intentionally advertised by the mimic. If omitted,
            the advertised sides of ``port_remaps`` are used for compatibility
            with older callers.

        The protected endpoint metadata is as important as the redirects.
        An IP alias shares the host network stack, so without a default-deny
        filter every unrelated daemon bound to ``0.0.0.0`` is reachable on the
        decoy IP and a port scan mirrors the real host.
        """
        advertised = set(exposed_ports) if exposed_ports is not None else set(port_remaps)
        if not advertised:
            logger.error(
                "Refusing to configure unisolated virtual IP %s for decoy %d: "
                "no exposed ports were supplied",
                bind_ip,
                decoy_id,
            )
            return False
        if any(not isinstance(port, int) or not 1 <= port <= 65535 for port in advertised):
            raise ValueError("exposed_ports must contain TCP ports in the range 1..65535")
        if set(port_remaps) != advertised:
            raise ValueError(
                "every exposed port must have exactly one private redirect"
            )
        backend_ports = list(port_remaps.values())
        for from_port, to_port in port_remaps.items():
            if not isinstance(from_port, int) or not 1 <= from_port <= 65535:
                raise ValueError("port_remaps keys must be TCP ports in the range 1..65535")
            if not isinstance(to_port, int) or not 1 <= to_port <= 65535:
                raise ValueError("port_remaps values must be TCP ports in the range 1..65535")
            if from_port == to_port:
                raise ValueError(
                    "mimic backend ports must differ from advertised ports"
                )
        if len(set(backend_ports)) != len(backend_ports):
            raise ValueError("mimic backend ports must be unique")
        if advertised.intersection(backend_ports):
            raise ValueError(
                "mimic backend ports must not overlap any advertised port"
            )

        rules = [
            {
                "from_ip": bind_ip,
                "from_port": from_port,
                "to_ip": bind_ip,
                "to_port": to_port,
            }
            for from_port, to_port in port_remaps.items()
        ]

        previous_rules = self._rules.get(decoy_id)
        previous_endpoint = self._protected_endpoints.get(decoy_id)
        self._rules[decoy_id] = rules
        # Every advertised port is redirected to an isolated runtime listener.
        # Never directly allow a virtual-IP port: a wildcard-bound host daemon
        # could otherwise answer on the decoy address if the mimic listener
        # stopped or could not bind.
        direct_ports: list[int] = []
        self._protected_endpoints[decoy_id] = {
            "ip": bind_ip,
            "direct_ports": direct_ports,
        }

        if await self._sync_rules():
            return True

        if previous_rules is None:
            self._rules.pop(decoy_id, None)
        else:
            self._rules[decoy_id] = previous_rules
        if previous_endpoint is None:
            self._protected_endpoints.pop(decoy_id, None)
        else:
            self._protected_endpoints[decoy_id] = previous_endpoint
        if not await self._sync_rules():
            logger.critical(
                "Failed to restore packet-filter state after rejecting decoy %d",
                decoy_id,
            )
        return False

    @_serialized_mutation
    async def quarantine_endpoints(self, endpoints: dict[int, str]) -> bool:
        """Atomically default-deny persisted aliases during startup recovery.

        A crashed process can leave several aliases live. Installing one
        mimic's normal rules at a time would replace the PF anchor and briefly
        expose every alias not processed yet. This seeds deny-all protection
        for the complete persisted set in one atomic ruleset; normal
        ``add_forwards`` calls then replace each entry as its listener resumes.
        """
        if not endpoints:
            return True

        for decoy_id, bind_ip in endpoints.items():
            self._rules[decoy_id] = []
            self._protected_endpoints[decoy_id] = {
                "ip": bind_ip,
                "direct_ports": [],
            }

        if await self._sync_rules():
            return True

        # Never flush or "restore" from an empty in-memory state here. A new
        # process does not know the anchor rules left by its predecessor, and
        # the helper applies replacements atomically. The old rules or the new
        # deny-all rules may still be live; retaining the requested endpoints
        # in memory keeps all later cleanup conservative.
        logger.critical(
            "Startup quarantine could not be confirmed; retaining protected "
            "endpoint state without modifying PF again"
        )
        return False

    @_serialized_mutation
    async def remove_forwards(self, decoy_id: int) -> bool:
        """Remove port forward rules for a decoy and sync to system."""
        if decoy_id not in self._rules:
            return True

        previous_rules = self._rules.pop(decoy_id)
        previous_endpoint = self._protected_endpoints.pop(decoy_id, None)
        if await self._sync_rules():
            return True

        self._rules[decoy_id] = previous_rules
        if previous_endpoint is not None:
            self._protected_endpoints[decoy_id] = previous_endpoint
        if not await self._sync_rules():
            logger.critical(
                "Failed to restore packet-filter state after retaining decoy %d",
                decoy_id,
            )
        return False

    @_serialized_mutation
    async def clear_all(self) -> bool:
        """Clear all port forwarding rules from system and internal state."""
        try:
            if not await self._priv_ops.clear_port_forwards():
                return False
            self._rules.clear()
            self._protected_endpoints.clear()
            return True
        except Exception:
            logger.exception("Failed to clear port forwards")
            return False

    async def _sync_rules(self) -> bool:
        """Sync all accumulated rules atomically to the system."""
        all_rules: list[dict] = []
        for rules in self._rules.values():
            all_rules.extend(rules)
        protected_by_ip: dict[str, dict] = {}
        for endpoint in self._protected_endpoints.values():
            protected_by_ip.setdefault(endpoint["ip"], endpoint)

        try:
            if not all_rules and not self._protected_endpoints:
                return await self._priv_ops.clear_port_forwards()
            return await self._priv_ops.setup_port_forwards(
                rules=all_rules,
                protected_endpoints=list(protected_by_ip.values()),
                interface=self._interface,
            )
        except Exception:
            logger.exception("Failed to sync port forward rules")
            return False

    @property
    def active_rule_count(self) -> int:
        """Total number of active port forward rules across all decoys."""
        return sum(len(rules) for rules in self._rules.values())

    @property
    def protected_endpoint_count(self) -> int:
        """Number of virtual IPs isolated from the host's listening surface."""
        return len({
            endpoint["ip"]
            for endpoint in self._protected_endpoints.values()
        })
