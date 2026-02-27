"""Passive DNS monitor — polls privileged_ops for DNS queries and feeds
the CanaryManager for canary hostname detection.

The DNSMonitor is called periodically by the scan loop. It retrieves
recent DNS queries from the privileged helper (which runs a scapy sniffer
on UDP 53) and checks each query against known canary hostnames.

On a canary match, it:
1. Records an observation in the CanaryManager
2. Publishes a 'decoy.credential_trip' event to the event bus
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from squirrelops_home_sensor.decoys.canary import CanaryManager

logger = logging.getLogger(__name__)


@runtime_checkable
class PrivilegedOpsProtocol(Protocol):
    """Protocol for the subset of PrivilegedOperations used by DNSMonitor."""

    async def get_dns_queries(self, since: datetime | None = None) -> list: ...


@runtime_checkable
class EventBusProtocol(Protocol):
    """Protocol for the subset of EventBus used by DNSMonitor."""

    async def publish(self, event_type: str, payload: dict) -> int: ...


class DNSMonitor:
    """Polls for DNS queries and matches against canary hostnames.

    Args:
        privileged_ops: Provider of raw DNS query data.
        canary_manager: Canary hostname matcher and observation recorder.
        event_bus: Event bus for publishing credential trip events.
    """

    def __init__(
        self,
        privileged_ops: PrivilegedOpsProtocol,
        canary_manager: CanaryManager,
        event_bus: EventBusProtocol,
    ) -> None:
        self._privileged_ops = privileged_ops
        self._canary_manager = canary_manager
        self._event_bus = event_bus
        self._last_poll: datetime | None = None

    async def poll(self) -> None:
        """Fetch recent DNS queries and check for canary matches.

        Called periodically by the scan loop. Retrieves DNS queries since
        the last poll and checks each against the canary manager.
        """
        queries = await self._privileged_ops.get_dns_queries(since=self._last_poll)
        self._last_poll = datetime.now(timezone.utc)

        for query in queries:
            query_name = query.query_name
            source_ip = query.source_ip

            if not self._canary_manager.check_query(query_name):
                continue

            # Canary match — record observation and publish event
            logger.warning(
                "DNS canary match: %s queried by %s", query_name, source_ip
            )

            observation = self._canary_manager.record_observation(
                hostname=query_name,
                queried_by_ip=source_ip,
                queried_by_mac=getattr(query, "source_mac", None),
            )

            await self._event_bus.publish(
                "decoy.credential_trip",
                {
                    "canary_hostname": observation["hostname"],
                    "queried_by_ip": observation["queried_by_ip"],
                    "queried_by_mac": observation["queried_by_mac"],
                    "credential_id": observation["credential_id"],
                    "observed_at": observation["observed_at"].isoformat(),
                    "detection_method": "dns_canary",
                },
            )
