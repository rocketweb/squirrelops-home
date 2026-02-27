"""macOS privileged helper communication via Unix domain socket JSON-RPC.

The squirrelops-helper runs as a privileged Swift binary installed via
SMJobBless. This module communicates with it using a simple JSON-RPC 2.0
protocol over a Unix domain socket.

Socket path: /var/run/squirrelops-helper.sock
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from datetime import datetime, timezone
from typing import Any

from squirrelops_home_sensor.privileged.helper import (
    DNSQuery,
    PrivilegedOperations,
    ServiceResult,
)

logger = logging.getLogger(__name__)


class MacOSPrivilegedOps(PrivilegedOperations):
    """Privileged operations delegated to the macOS helper via JSON-RPC.

    Parameters
    ----------
    socket_path:
        Path to the Unix domain socket (default: /var/run/squirrelops-helper.sock).
    """

    def __init__(
        self,
        socket_path: str = "/var/run/squirrelops-helper.sock",
        rpc_timeout: float = 30.0,
    ) -> None:
        self._socket_path = socket_path
        self._request_id = 0
        self._rpc_timeout = rpc_timeout

    async def _call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """Send a JSON-RPC request to the helper and return the result.

        Raises asyncio.TimeoutError if the helper does not respond
        within rpc_timeout seconds.
        """
        return await asyncio.wait_for(
            self._call_inner(method, params),
            timeout=self._rpc_timeout,
        )

    async def _call_inner(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """Inner implementation of _call without timeout wrapper.

        Parameters
        ----------
        method:
            JSON-RPC method name (e.g., "runARPScan").
        params:
            Optional parameters dict.

        Returns
        -------
        Any:
            The "result" field from the JSON-RPC response.

        Raises
        ------
        ConnectionRefusedError:
            If the helper socket is not available.
        RuntimeError:
            If the helper returns a JSON-RPC error.
        """
        self._request_id += 1
        request: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
        }
        if params is not None:
            request["params"] = params

        reader, writer = await asyncio.open_unix_connection(self._socket_path)
        try:
            writer.write(json.dumps(request).encode() + b"\n")
            await writer.drain()

            response_line = await reader.readline()
            response = json.loads(response_line.decode())

            if "error" in response:
                raise RuntimeError(
                    f"Helper error: {response['error'].get('message', 'unknown')}"
                )

            return response.get("result")
        finally:
            writer.close()
            await writer.wait_closed()

    async def arp_scan(self, subnet: str) -> list[tuple[str, str]]:
        """Delegate ARP scan to the helper."""
        result = await self._call("runARPScan", {"subnet": subnet})
        return [(entry["ip"], entry["mac"]) for entry in result]

    async def service_scan(
        self, targets: list[str], ports: list[int]
    ) -> list[ServiceResult]:
        """Delegate service scan to the helper."""
        result = await self._call(
            "runServiceScan",
            {"targets": targets, "ports": ports},
        )
        return [
            ServiceResult(
                ip=entry["ip"],
                port=entry["port"],
                banner=entry.get("banner"),
            )
            for entry in result
        ]

    async def bind_listener(self, address: str, port: int) -> socket.socket:
        """Request the helper to bind a listening socket.

        The helper binds the socket and returns the file descriptor,
        which we wrap in a Python socket object.
        """
        result = await self._call(
            "bindListener",
            {"address": address, "port": port},
        )
        fd = result.get("fd")
        if fd is not None:
            sock = socket.socket(fileno=fd)
            return sock
        # Fallback: create a socket directly (non-privileged port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((address, port))
        sock.listen(128)
        sock.setblocking(False)
        return sock

    async def start_dns_sniff(self, interface: str) -> None:
        """Request the helper to start DNS sniffing."""
        await self._call("startDNSSniff", {"interface": interface})

    async def stop_dns_sniff(self) -> None:
        """Request the helper to stop DNS sniffing."""
        await self._call("stopDNSSniff")

    async def get_dns_queries(self, since: datetime) -> list[DNSQuery]:
        """Request captured DNS queries from the helper."""
        result = await self._call(
            "getDNSQueries",
            {"since": since.isoformat()},
        )
        queries = []
        for entry in result:
            ts = datetime.fromisoformat(entry["timestamp"])
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            queries.append(
                DNSQuery(
                    query_name=entry["query_name"],
                    source_ip=entry["source_ip"],
                    timestamp=ts,
                )
            )
        return queries

    async def add_ip_alias(
        self, ip: str, interface: str = "en0", mask: str = "255.255.255.0",
    ) -> bool:
        """Delegate IP alias creation to the helper."""
        try:
            result = await self._call(
                "addIPAlias",
                {"ip": ip, "interface": interface, "mask": mask},
            )
            return result.get("success", False)
        except Exception:
            logger.exception("Failed to add IP alias %s via helper", ip)
            return False

    async def remove_ip_alias(self, ip: str, interface: str = "en0") -> bool:
        """Delegate IP alias removal to the helper."""
        try:
            result = await self._call(
                "removeIPAlias",
                {"ip": ip, "interface": interface},
            )
            return result.get("success", False)
        except Exception:
            logger.exception("Failed to remove IP alias %s via helper", ip)
            return False

    async def setup_port_forwards(
        self, rules: list[dict], interface: str = "en0",
    ) -> bool:
        """Delegate pfctl port forward setup to the helper."""
        try:
            result = await self._call(
                "setupPortForwards",
                {"rules": rules, "interface": interface},
            )
            count = result.get("rules_count", 0)
            logger.info("Port forwarding: %d pfctl rules loaded", count)
            return result.get("success", False)
        except Exception:
            logger.exception("Failed to set up port forwards via helper")
            return False

    async def clear_port_forwards(self) -> bool:
        """Delegate pfctl port forward cleanup to the helper."""
        try:
            result = await self._call("clearPortForwards")
            return result.get("success", False)
        except Exception:
            logger.exception("Failed to clear port forwards via helper")
            return False
