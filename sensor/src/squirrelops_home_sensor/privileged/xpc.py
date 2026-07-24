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
from datetime import datetime
from typing import Any

from squirrelops_home_sensor.netvalidation import is_valid_ipv4
from squirrelops_home_sensor.privileged.helper import (
    DNSQuery,
    PrivilegedOperations,
    ServiceResult,
)
from squirrelops_home_sensor.scanner.port_scanner import PortScanner

logger = logging.getLogger(__name__)

HELPER_PROTOCOL_VERSION = 1
REQUIRED_HELPER_CAPABILITIES = frozenset(
    {
        "arp_scan",
        "virtual_ip",
        "port_forward_isolation",
    }
)
SERVICE_SCAN_CONNECT_TIMEOUT = 2.0
SERVICE_SCAN_BANNER_TIMEOUT = 2.0
SERVICE_SCAN_MAX_CONCURRENT = 32
SERVICE_SCAN_MAX_PROBES = 4096


class MacOSPrivilegedOps(PrivilegedOperations):
    """macOS operations, delegating only privileged work to the helper.

    Parameters
    ----------
    socket_path:
        Path to the Unix domain socket (default: /var/run/squirrelops-helper.sock).
    """

    requires_active_alias_withdrawal_probe = True

    def __init__(
        self,
        socket_path: str = "/var/run/squirrelops-helper.sock",
        rpc_timeout: float = 30.0,
    ) -> None:
        self._socket_path = socket_path
        self._request_id = 0
        self._rpc_timeout = rpc_timeout

    async def is_available(self) -> bool:
        """Prove this process can use the expected helper RPC protocol."""
        import os

        if not os.path.exists(self._socket_path):
            return False
        try:
            result = await asyncio.wait_for(
                self._call("ping"),
                timeout=2.0,
            )
            if not isinstance(result, dict):
                return False
            capabilities = result.get("capabilities")
            return (
                result.get("status") == "ok"
                and result.get("protocol_version") == HELPER_PROTOCOL_VERSION
                and isinstance(capabilities, list)
                and all(isinstance(item, str) for item in capabilities)
                and REQUIRED_HELPER_CAPABILITIES.issubset(capabilities)
            )
        except Exception:
            logger.debug("Privileged helper capability probe failed", exc_info=True)
            return False

    async def _call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> Any:
        """Send a JSON-RPC request to the helper and return the result.

        Raises asyncio.TimeoutError if the helper does not respond within the
        operation timeout.
        """
        return await asyncio.wait_for(
            self._call_inner(method, params),
            timeout=self._rpc_timeout if timeout is None else timeout,
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
        request_id = self._request_id
        request: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
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

            if (
                not isinstance(response, dict)
                or response.get("jsonrpc") != "2.0"
                or response.get("id") != request_id
            ):
                raise RuntimeError("Invalid helper JSON-RPC response")
            if "error" in response:
                error = response["error"]
                message = error.get("message", "unknown") if isinstance(error, dict) else "unknown"
                raise RuntimeError(f"Helper error: {message}")
            if "result" not in response:
                raise RuntimeError("Helper response is missing a result")

            return response["result"]
        finally:
            writer.close()
            await writer.wait_closed()

    async def arp_scan(self, subnet: str) -> list[tuple[str, str]]:
        """Delegate ARP scan to the helper."""
        result = await self._call("runARPScan", {"subnet": subnet})
        return [(entry["ip"], entry["mac"]) for entry in result]

    async def service_scan(self, targets: list[str], ports: list[int]) -> list[ServiceResult]:
        """Scan services locally with bounded unprivileged TCP connections."""
        if not targets or not ports:
            return []
        for target in targets:
            if not isinstance(target, str) or not is_valid_ipv4(target):
                raise ValueError(f"Invalid scan target: {target!r}")
        for port in ports:
            if (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= 65535
            ):
                raise ValueError(f"Invalid scan port: {port!r}")
        if len(targets) * len(ports) > SERVICE_SCAN_MAX_PROBES:
            raise ValueError(
                f"Service scan requested too many probes; "
                f"maximum is {SERVICE_SCAN_MAX_PROBES}"
            )

        scanner = PortScanner(
            timeout_per_port=SERVICE_SCAN_CONNECT_TIMEOUT,
            max_concurrent=SERVICE_SCAN_MAX_CONCURRENT,
        )
        scanned = await scanner.scan_with_banners(
            targets=targets,
            ports=ports,
            banner_timeout=SERVICE_SCAN_BANNER_TIMEOUT,
        )
        return [
            ServiceResult(ip=target, port=result.port, banner=result.banner)
            for target in targets
            for result in scanned.get(target, [])
        ]

    async def start_dns_sniff(self, interface: str) -> None:
        """Reject DNS capture until a real macOS implementation exists."""
        del interface
        raise NotImplementedError(
            "DNS capture is not supported on macOS"
        )

    async def stop_dns_sniff(self) -> None:
        """Allow optional cleanup even though macOS DNS capture is unsupported."""

    async def get_dns_queries(self, since: datetime) -> list[DNSQuery]:
        """Reject DNS reads rather than pretending an empty capture is real."""
        del since
        raise NotImplementedError(
            "DNS capture is not supported on macOS"
        )

    async def bind_listener(self, address: str, port: int) -> socket.socket:
        """Bind an unprivileged listener in the sensor process.

        JSON-RPC cannot transfer an open file descriptor. Privileged ports must
        therefore use the helper's PF redirect support instead of pretending a
        helper-side bind can produce a usable sensor-side socket.
        """
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("Listener port must be between 1 and 65535")
        if port < 1024:
            raise PermissionError(
                "The macOS helper cannot transfer listening socket descriptors; "
                "privileged ports below 1024 must use PF port forwarding"
            )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((address, port))
            sock.listen(128)
            sock.setblocking(False)
        except Exception:
            sock.close()
            raise
        return sock

    async def add_ip_alias(
        self,
        ip: str,
        interface: str = "en0",
        mask: str = "255.255.255.255",
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
        self,
        rules: list[dict],
        interface: str = "en0",
        protected_endpoints: list[dict] | None = None,
    ) -> bool:
        """Delegate pfctl forwarding and virtual-IP isolation to the helper."""
        try:
            result = await self._call(
                "setupPortForwards",
                {
                    "rules": rules,
                    "protected_endpoints": protected_endpoints or [],
                    "interface": interface,
                },
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
