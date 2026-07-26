"""Constrained Linux network-helper RPC.

The normal sensor process runs without host networking or Linux capabilities.
Only this companion process enters the host network namespace and receives
``CAP_NET_RAW`` and ``CAP_NET_ADMIN``.  The two processes communicate over a
Unix-domain socket shared read-only with the sensor container.

The RPC is deliberately not a shell or arbitrary command channel:

* one bounded JSON request is accepted per connection;
* Linux peer credentials must match the configured sensor UID;
* methods and parameters are allow-listed;
* all addresses must be inside the configured LAN subnet; and
* packet-filter destinations are rewritten to the configured sensor address.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import json
import logging
import os
import re
import socket
import stat
import struct
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from zeroconf import ServiceInfo
from zeroconf.asyncio import AsyncZeroconf

from squirrelops_home_sensor.netvalidation import is_valid_ipv4
from squirrelops_home_sensor.privileged.helper import (
    DNSQuery,
    LinuxPrivilegedOps,
    PrivilegedOperations,
    ServiceResult,
)
from squirrelops_home_sensor.scanner.port_scanner import PortScanner

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = 1
DEFAULT_SOCKET_PATH = "/run/squirrelops/network-helper.sock"
MAX_REQUEST_BYTES = 64 * 1024
MAX_RULES = 256
MAX_PROTECTED_ENDPOINTS = 64
MAX_SCAN_HOSTS = 1024
MAX_SCAN_PORTS = 128
RPC_TIMEOUT_SECONDS = 30.0
SERVICE_SCAN_MAX_PROBES = 4096

CAPABILITIES = (
    "arp_scan",
    "virtual_ip",
    "port_forward_isolation",
    "listener_publication",
    "multicast_discovery",
    "mdns_advertisement",
)

_SERVICE_TYPE_RE = re.compile(r"^_[a-z0-9-]{1,32}\._(?:tcp|udp)(?:\.local\.)?$")
_HOST_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
_INSTANCE_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9 _-]{0,62})$")


class SidecarProtocolError(RuntimeError):
    """The helper request or response violated the constrained protocol."""


def _strict_json_loads(raw: bytes) -> dict[str, Any]:
    """Decode one JSON object while rejecting duplicates and non-finite values."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate object key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise ValueError(f"invalid JSON constant: {value}")

    decoded = json.loads(
        raw,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
    if not isinstance(decoded, dict):
        raise ValueError("request must be a JSON object")
    return decoded


class LinuxNetworkHelperClient(PrivilegedOperations):
    """Unprivileged sensor-side client for the Linux network helper."""

    def __init__(
        self,
        socket_path: str = DEFAULT_SOCKET_PATH,
        *,
        sensor_ip: str | None = None,
        rpc_timeout: float = RPC_TIMEOUT_SECONDS,
    ) -> None:
        self._socket_path = socket_path
        self._sensor_ip = sensor_ip or os.environ.get(
            "SQUIRRELOPS_SENSOR_BRIDGE_IP",
            "172.30.0.2",
        )
        ipaddress.IPv4Address(self._sensor_ip)
        self._rpc_timeout = rpc_timeout
        self._request_id = 0

    async def _call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> Any:
        self._request_id += 1
        request_id = self._request_id
        request: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            request["params"] = params
        payload = json.dumps(
            request,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        if len(payload) > MAX_REQUEST_BYTES:
            raise ValueError("network-helper request is too large")

        async def exchange() -> Any:
            reader, writer = await asyncio.open_unix_connection(self._socket_path)
            try:
                writer.write(payload)
                await writer.drain()
                response_line = await reader.readline()
                if not response_line or len(response_line) > MAX_REQUEST_BYTES:
                    raise SidecarProtocolError("invalid network-helper response size")
                response = _strict_json_loads(response_line)
                if (
                    response.get("jsonrpc") != "2.0"
                    or response.get("id") != request_id
                ):
                    raise SidecarProtocolError("invalid network-helper response")
                if "error" in response:
                    error = response["error"]
                    message = (
                        error.get("message", "unknown helper error")
                        if isinstance(error, dict)
                        else "unknown helper error"
                    )
                    raise SidecarProtocolError(str(message))
                if "result" not in response:
                    raise SidecarProtocolError("network-helper response has no result")
                return response["result"]
            finally:
                writer.close()
                await writer.wait_closed()

        return await asyncio.wait_for(
            exchange(),
            timeout=self._rpc_timeout if timeout is None else timeout,
        )

    async def is_available(self) -> bool:
        try:
            result = await self._call("ping", timeout=2.0)
        except Exception:
            return False
        return (
            isinstance(result, dict)
            and result.get("status") == "ok"
            and result.get("protocol_version") == PROTOCOL_VERSION
            and set(result.get("capabilities", ())) >= set(CAPABILITIES)
        )

    def listener_bind_address(self, advertised_ip: str) -> str:
        """Bind private backends only on the fixed sensor bridge address."""
        ipaddress.IPv4Address(advertised_ip)
        return self._sensor_ip

    async def arp_scan(self, subnet: str) -> list[tuple[str, str]]:
        result = await self._call("arp_scan", {"subnet": subnet})
        if not isinstance(result, list):
            raise SidecarProtocolError("invalid ARP result")
        entries: list[tuple[str, str]] = []
        for item in result:
            if not isinstance(item, dict):
                raise SidecarProtocolError("invalid ARP entry")
            ip = item.get("ip")
            mac = item.get("mac")
            if not isinstance(ip, str) or not isinstance(mac, str):
                raise SidecarProtocolError("invalid ARP entry")
            entries.append((ip, mac))
        return entries

    async def service_scan(
        self,
        targets: list[str],
        ports: list[int],
    ) -> list[ServiceResult]:
        """Use bounded, unprivileged TCP probes from the sensor container."""
        if len(targets) > MAX_SCAN_HOSTS or len(ports) > MAX_SCAN_PORTS:
            raise ValueError("service scan exceeds the configured bounds")
        if len(targets) * len(ports) > SERVICE_SCAN_MAX_PROBES:
            raise ValueError("service scan requests too many probes")
        if any(not isinstance(target, str) or not is_valid_ipv4(target) for target in targets):
            raise ValueError("service scan targets must be IPv4 addresses")
        if any(
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
            for port in ports
        ):
            raise ValueError("service scan ports must be integers in 1..65535")

        scanner = PortScanner(timeout_per_port=2.0, max_concurrent=32)
        scanned = await scanner.scan_with_banners(
            targets=targets,
            ports=ports,
            banner_timeout=2.0,
        )
        return [
            ServiceResult(ip=target, port=result.port, banner=result.banner)
            for target in targets
            for result in scanned.get(target, [])
        ]

    async def bind_listener(self, address: str, port: int) -> socket.socket:
        """Bind only an unprivileged socket inside the sensor namespace."""
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1024 <= port <= 65535
        ):
            raise PermissionError(
                "Linux sensor listeners must use an unprivileged backend port"
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

    async def start_dns_sniff(self, interface: str) -> None:
        del interface
        raise NotImplementedError("DNS capture is not implemented by the Linux helper")

    async def stop_dns_sniff(self) -> None:
        return None

    async def get_dns_queries(self, since: datetime) -> list[DNSQuery]:
        del since
        raise NotImplementedError("DNS capture is not implemented by the Linux helper")

    async def add_ip_alias(
        self,
        ip: str,
        interface: str = "eth0",
        mask: str = "255.255.255.255",
    ) -> bool:
        result = await self._call(
            "add_ip_alias",
            {"ip": ip, "interface": interface, "mask": mask},
        )
        return isinstance(result, dict) and result.get("success") is True

    async def remove_ip_alias(self, ip: str, interface: str = "eth0") -> bool:
        result = await self._call(
            "remove_ip_alias",
            {"ip": ip, "interface": interface},
        )
        return isinstance(result, dict) and result.get("success") is True

    async def setup_port_forwards(
        self,
        rules: list[dict],
        interface: str = "eth0",
        protected_endpoints: list[dict] | None = None,
    ) -> bool:
        if len(rules) > MAX_RULES:
            raise ValueError("too many port-forward rules")
        rewritten: list[dict[str, Any]] = []
        for rule in rules:
            if not isinstance(rule, dict):
                raise ValueError("port-forward rules must be objects")
            rewritten.append(
                {
                    "from_ip": rule.get("from_ip"),
                    "from_port": rule.get("from_port"),
                    # The caller cannot choose a host-side forwarding target.
                    "to_ip": self._sensor_ip,
                    "to_port": rule.get("to_port"),
                }
            )
        result = await self._call(
            "setup_port_forwards",
            {
                "rules": rewritten,
                "interface": interface,
                "protected_endpoints": protected_endpoints or [],
            },
        )
        return isinstance(result, dict) and result.get("success") is True

    async def clear_port_forwards(self) -> bool:
        result = await self._call("clear_port_forwards")
        return isinstance(result, dict) and result.get("success") is True

    async def publish_listener(self, listener_id: int, port: int) -> bool:
        if isinstance(listener_id, bool) or not isinstance(listener_id, int) or listener_id <= 0:
            raise ValueError("listener_id must be a positive integer")
        if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
            raise ValueError("published listeners must use ports 1024..65535")
        result = await self._call(
            "publish_listener",
            {"listener_id": listener_id, "port": port},
        )
        return isinstance(result, dict) and result.get("success") is True

    async def unpublish_listener(self, listener_id: int) -> bool:
        if isinstance(listener_id, bool) or not isinstance(listener_id, int) or listener_id <= 0:
            raise ValueError("listener_id must be a positive integer")
        result = await self._call(
            "unpublish_listener",
            {"listener_id": listener_id},
        )
        return isinstance(result, dict) and result.get("success") is True

    async def mdns_browse(
        self,
        service_types: list[str],
        timeout: float,
    ) -> list[dict[str, Any]]:
        result = await self._call(
            "mdns_browse",
            {"service_types": service_types, "timeout": timeout},
            timeout=min(max(timeout + 5.0, 5.0), RPC_TIMEOUT_SECONDS),
        )
        if not isinstance(result, list):
            raise SidecarProtocolError("invalid mDNS browse result")
        return result

    async def ssdp_msearch(self, timeout: float) -> list[tuple[str, str]]:
        result = await self._call(
            "ssdp_msearch",
            {"timeout": timeout},
            timeout=min(max(timeout + 5.0, 5.0), RPC_TIMEOUT_SECONDS),
        )
        if not isinstance(result, list):
            raise SidecarProtocolError("invalid SSDP result")
        responses: list[tuple[str, str]] = []
        for item in result:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("raw"), str)
                or not isinstance(item.get("source_ip"), str)
            ):
                raise SidecarProtocolError("invalid SSDP entry")
            responses.append((item["raw"], item["source_ip"]))
        return responses

    async def register_mdns(
        self,
        *,
        registration_id: str,
        virtual_ip: str,
        port: int,
        service_type: str,
        hostname: str,
        instance_name: str,
        properties: dict[str, str],
    ) -> bool:
        result = await self._call(
            "register_mdns",
            {
                "registration_id": registration_id,
                "virtual_ip": virtual_ip,
                "port": port,
                "service_type": service_type,
                "hostname": hostname,
                "instance_name": instance_name,
                "properties": properties,
            },
        )
        return isinstance(result, dict) and result.get("success") is True

    async def unregister_mdns(self, registration_prefix: str) -> bool:
        result = await self._call(
            "unregister_mdns",
            {"registration_prefix": registration_prefix},
        )
        return isinstance(result, dict) and result.get("success") is True


class LinuxNetworkHelperServer:
    """Host-network side of the constrained RPC boundary."""

    def __init__(
        self,
        *,
        socket_path: str = DEFAULT_SOCKET_PATH,
        allowed_uid: int = 10001,
        allowed_subnet: str,
        sensor_ip: str = "172.30.0.2",
        interface: str = "auto",
        operations: LinuxPrivilegedOps | None = None,
    ) -> None:
        if allowed_uid <= 0:
            raise ValueError("sensor UID must be non-root")
        self.socket_path = Path(socket_path)
        self.state_path = self.socket_path.with_name("network-helper-state.json")
        self.allowed_uid = allowed_uid
        self.allowed_subnet = ipaddress.IPv4Network(allowed_subnet, strict=False)
        self.sensor_ip = str(ipaddress.IPv4Address(sensor_ip))
        self.interface = interface
        self.operations = operations or LinuxPrivilegedOps()
        self._server: asyncio.AbstractServer | None = None
        self._owned_aliases: set[str] = set()
        self._mimic_rules: list[dict[str, Any]] = []
        self._protected_endpoints: list[dict[str, Any]] = []
        self._classic_listeners: dict[int, int] = {}
        self._zeroconf: AsyncZeroconf | None = None
        self._mdns_services: dict[str, ServiceInfo] = {}
        self._mdns_registrations: dict[str, dict[str, Any]] = {}
        self._dispatch_lock = asyncio.Lock()

    def _peer_uid(self, writer: asyncio.StreamWriter) -> int:
        transport_socket = writer.get_extra_info("socket")
        if transport_socket is None or not hasattr(socket, "SO_PEERCRED"):
            raise SidecarProtocolError("Linux peer credentials are unavailable")
        raw = transport_socket.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        _pid, uid, _gid = struct.unpack("3i", raw)
        return uid

    def _lan_ip(self, value: Any, field: str) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{field} must be an IPv4 string")
        address = ipaddress.IPv4Address(value)
        if address not in self.allowed_subnet:
            raise ValueError(f"{field} is outside the configured LAN subnet")
        return str(address)

    def _lan_subnet(self, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("subnet must be an IPv4 CIDR")
        network = ipaddress.IPv4Network(value, strict=False)
        if not network.subnet_of(self.allowed_subnet):
            raise ValueError("scan subnet is outside the configured LAN subnet")
        if network.num_addresses > MAX_SCAN_HOSTS + 2:
            raise ValueError("scan subnet is too large")
        return str(network)

    @staticmethod
    def _port(value: Any, field: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            raise ValueError(f"{field} must be an integer in 1..65535")
        return value

    def _effective_interface(self, requested: Any) -> str:
        if self.interface != "auto":
            return self.interface
        del requested
        result = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        tokens = result.stdout.split()
        interface = ""
        if result.returncode == 0 and "dev" in tokens:
            try:
                interface = tokens[tokens.index("dev") + 1]
            except IndexError as exc:
                raise ValueError("default route omitted its interface") from exc
        if not interface:
            host_ip = self._host_lan_ip()
            addresses = subprocess.run(
                ["ip", "-4", "-o", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            for line in addresses.stdout.splitlines():
                fields = line.split()
                if len(fields) >= 4 and fields[2] == "inet":
                    address = fields[3].split("/", 1)[0]
                    if address == host_ip:
                        interface = fields[1].split("@", 1)[0]
                        break
        if not interface:
            raise ValueError("could not resolve the host routed interface")
        if not interface.replace("-", "").replace("_", "").isalnum():
            raise ValueError("invalid default-route interface")
        return interface

    async def dispatch(self, method: str, params: dict[str, Any]) -> Any:
        """Validate and execute one allow-listed operation."""
        if method == "ping":
            if params:
                raise ValueError("ping does not accept parameters")
            return {
                "status": "ok",
                "protocol_version": PROTOCOL_VERSION,
                "capabilities": list(CAPABILITIES),
            }
        if method == "arp_scan":
            subnet = self._lan_subnet(params.get("subnet"))
            return [
                {"ip": ip, "mac": mac}
                for ip, mac in await self.operations.arp_scan(subnet)
                if ipaddress.IPv4Address(ip) in self.allowed_subnet
            ]
        if method == "add_ip_alias":
            ip = self._lan_ip(params.get("ip"), "ip")
            interface = self._effective_interface(params.get("interface"))
            mask = params.get("mask", "255.255.255.255")
            if mask != "255.255.255.255":
                raise ValueError("only host-route aliases are allowed")
            success = await self.operations.add_ip_alias(ip, interface, mask)
            if success:
                self._owned_aliases.add(ip)
                self._persist_state()
            return {"success": success}
        if method == "remove_ip_alias":
            ip = self._lan_ip(params.get("ip"), "ip")
            if ip not in self._owned_aliases:
                raise ValueError("cannot remove an alias not owned by this helper")
            interface = self._effective_interface(params.get("interface"))
            success = await self.operations.remove_ip_alias(ip, interface)
            if success:
                self._owned_aliases.discard(ip)
                self._persist_state()
            return {"success": success}
        if method == "setup_port_forwards":
            return await self._setup_port_forwards(params)
        if method == "clear_port_forwards":
            if params:
                raise ValueError("clear_port_forwards does not accept parameters")
            previous_rules = self._mimic_rules
            previous_endpoints = self._protected_endpoints
            self._mimic_rules = []
            self._protected_endpoints = []
            success = await self._sync_forwards()
            if not success:
                self._mimic_rules = previous_rules
                self._protected_endpoints = previous_endpoints
            else:
                self._persist_state()
            return {"success": success}
        if method == "publish_listener":
            listener_id = params.get("listener_id")
            if (
                isinstance(listener_id, bool)
                or not isinstance(listener_id, int)
                or listener_id <= 0
            ):
                raise ValueError("listener_id must be a positive integer")
            port = self._port(params.get("port"), "port")
            if port < 1024:
                raise ValueError("classic listener backends must be unprivileged")
            previous = self._classic_listeners.get(listener_id)
            self._classic_listeners[listener_id] = port
            success = await self._sync_forwards()
            if not success:
                if previous is None:
                    self._classic_listeners.pop(listener_id, None)
                else:
                    self._classic_listeners[listener_id] = previous
            else:
                self._persist_state()
            return {"success": success}
        if method == "unpublish_listener":
            listener_id = params.get("listener_id")
            if (
                isinstance(listener_id, bool)
                or not isinstance(listener_id, int)
                or listener_id <= 0
            ):
                raise ValueError("listener_id must be a positive integer")
            previous = self._classic_listeners.pop(listener_id, None)
            if previous is None:
                return {"success": True}
            success = await self._sync_forwards()
            if not success:
                self._classic_listeners[listener_id] = previous
            else:
                self._persist_state()
            return {"success": success}
        if method == "mdns_browse":
            return await self._mdns_browse(params)
        if method == "ssdp_msearch":
            return await self._ssdp_msearch(params)
        if method == "register_mdns":
            return await self._register_mdns(params)
        if method == "unregister_mdns":
            return await self._unregister_mdns(params)
        raise ValueError("method is not allowed")

    async def _setup_port_forwards(self, params: dict[str, Any]) -> dict[str, bool]:
        rules = params.get("rules")
        endpoints = params.get("protected_endpoints", [])
        if not isinstance(rules, list) or len(rules) > MAX_RULES:
            raise ValueError("rules must be a bounded list")
        if not isinstance(endpoints, list) or len(endpoints) > MAX_PROTECTED_ENDPOINTS:
            raise ValueError("protected_endpoints must be a bounded list")

        validated_rules: list[dict[str, Any]] = []
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) != {
                "from_ip",
                "from_port",
                "to_ip",
                "to_port",
            }:
                raise ValueError("invalid port-forward rule")
            if rule["to_ip"] != self.sensor_ip:
                raise ValueError("forward target must be the configured sensor")
            validated_rules.append(
                {
                    "from_ip": self._lan_ip(rule["from_ip"], "from_ip"),
                    "from_port": self._port(rule["from_port"], "from_port"),
                    "to_ip": self.sensor_ip,
                    "to_port": self._port(rule["to_port"], "to_port"),
                }
            )

        validated_endpoints: list[dict[str, Any]] = []
        for endpoint in endpoints:
            if not isinstance(endpoint, dict) or set(endpoint) != {"ip", "direct_ports"}:
                raise ValueError("invalid protected endpoint")
            direct_ports = endpoint["direct_ports"]
            if not isinstance(direct_ports, list):
                raise ValueError("direct_ports must be a list")
            validated_endpoints.append(
                {
                    "ip": self._lan_ip(endpoint["ip"], "protected endpoint"),
                    "direct_ports": [
                        self._port(port, "direct port") for port in direct_ports
                    ],
                }
            )

        interface = self._effective_interface(params.get("interface"))
        previous_rules = self._mimic_rules
        previous_endpoints = self._protected_endpoints
        self._mimic_rules = validated_rules
        self._protected_endpoints = validated_endpoints
        success = await self._sync_forwards(interface=interface)
        if not success:
            self._mimic_rules = previous_rules
            self._protected_endpoints = previous_endpoints
        else:
            self._persist_state()
        return {"success": success}

    def _host_lan_ip(self) -> str:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))
            address = str(ipaddress.IPv4Address(probe.getsockname()[0]))
        finally:
            probe.close()
        if ipaddress.IPv4Address(address) not in self.allowed_subnet:
            raise ValueError("host route address is outside the configured LAN subnet")
        return address

    async def _sync_forwards(self, *, interface: str | None = None) -> bool:
        classic_rules: list[dict[str, Any]] = []
        if self._classic_listeners:
            host_ip = self._host_lan_ip()
            classic_rules = [
                {
                    "from_ip": host_ip,
                    "from_port": port,
                    "to_ip": self.sensor_ip,
                    "to_port": port,
                }
                for port in sorted(set(self._classic_listeners.values()))
            ]
        all_rules = [*self._mimic_rules, *classic_rules]
        if not all_rules and not self._protected_endpoints:
            return await self.operations.clear_port_forwards()
        return await self.operations.setup_port_forwards(
            all_rules,
            interface=interface or self._effective_interface("eth0"),
            protected_endpoints=self._protected_endpoints,
        )

    def _state_payload(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "owned_aliases": sorted(self._owned_aliases),
            "mimic_rules": self._mimic_rules,
            "protected_endpoints": self._protected_endpoints,
            "classic_listeners": {
                str(key): value
                for key, value in sorted(self._classic_listeners.items())
            },
            "mdns_registrations": {
                key: value
                for key, value in sorted(self._mdns_registrations.items())
            },
        }

    def _persist_state(self) -> None:
        """Atomically persist only helper-owned network state."""
        payload = json.dumps(
            self._state_payload(),
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        if len(payload) > MAX_REQUEST_BYTES:
            raise RuntimeError("network-helper state exceeds its safety bound")
        temporary = self.state_path.with_suffix(".tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
        os.replace(temporary, self.state_path)
        os.chmod(self.state_path, 0o600)

    def _load_state(self) -> None:
        """Load and revalidate state that only the helper could write."""
        try:
            metadata = self.state_path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("network-helper state is not a regular file")
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise RuntimeError("network-helper state has unsafe ownership or mode")
        raw = self.state_path.read_bytes()
        if not raw or len(raw) > MAX_REQUEST_BYTES:
            raise RuntimeError("network-helper state has an invalid size")
        state = _strict_json_loads(raw)
        required_keys = {
            "schema_version",
            "owned_aliases",
            "mimic_rules",
            "protected_endpoints",
            "classic_listeners",
        }
        schema_version = state.get("schema_version")
        expected_keys = required_keys | (
            {"mdns_registrations"} if schema_version == 2 else set()
        )
        if set(state) != expected_keys or schema_version not in {1, 2}:
            raise RuntimeError("network-helper state schema is invalid")

        aliases = state["owned_aliases"]
        if not isinstance(aliases, list) or len(aliases) > MAX_PROTECTED_ENDPOINTS:
            raise RuntimeError("network-helper aliases are invalid")
        self._owned_aliases = {
            self._lan_ip(value, "owned alias") for value in aliases
        }

        rules = state["mimic_rules"]
        endpoints = state["protected_endpoints"]
        if not isinstance(rules, list) or not isinstance(endpoints, list):
            raise RuntimeError("network-helper forwarding state is invalid")
        # Reuse the same strict validators without touching the OS.
        if len(rules) > MAX_RULES or len(endpoints) > MAX_PROTECTED_ENDPOINTS:
            raise RuntimeError("network-helper forwarding state exceeds bounds")
        validated_rules: list[dict[str, Any]] = []
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) != {
                "from_ip",
                "from_port",
                "to_ip",
                "to_port",
            }:
                raise RuntimeError("network-helper forwarding rule is invalid")
            if rule["to_ip"] != self.sensor_ip:
                raise RuntimeError("network-helper forwarding target is invalid")
            validated_rules.append(
                {
                    "from_ip": self._lan_ip(rule["from_ip"], "from_ip"),
                    "from_port": self._port(rule["from_port"], "from_port"),
                    "to_ip": self.sensor_ip,
                    "to_port": self._port(rule["to_port"], "to_port"),
                }
            )
        validated_endpoints: list[dict[str, Any]] = []
        for endpoint in endpoints:
            if not isinstance(endpoint, dict) or set(endpoint) != {"ip", "direct_ports"}:
                raise RuntimeError("network-helper protected endpoint is invalid")
            direct_ports = endpoint["direct_ports"]
            if not isinstance(direct_ports, list):
                raise RuntimeError("network-helper direct ports are invalid")
            validated_endpoints.append(
                {
                    "ip": self._lan_ip(endpoint["ip"], "protected endpoint"),
                    "direct_ports": [
                        self._port(port, "direct port") for port in direct_ports
                    ],
                }
            )
        listeners = state["classic_listeners"]
        if not isinstance(listeners, dict) or len(listeners) > MAX_PROTECTED_ENDPOINTS:
            raise RuntimeError("network-helper listener state is invalid")
        validated_listeners: dict[int, int] = {}
        for raw_id, raw_port in listeners.items():
            if not isinstance(raw_id, str) or not raw_id.isascii() or not raw_id.isdigit():
                raise RuntimeError("network-helper listener ID is invalid")
            listener_id = int(raw_id)
            if listener_id <= 0:
                raise RuntimeError("network-helper listener ID is invalid")
            port = self._port(raw_port, "listener port")
            if port < 1024:
                raise RuntimeError("network-helper listener port is privileged")
            validated_listeners[listener_id] = port

        self._mimic_rules = validated_rules
        self._protected_endpoints = validated_endpoints
        self._classic_listeners = validated_listeners
        registrations = state.get("mdns_registrations", {})
        if (
            not isinstance(registrations, dict)
            or len(registrations) > MAX_PROTECTED_ENDPOINTS
        ):
            raise RuntimeError("network-helper mDNS state is invalid")
        validated_registrations: dict[str, dict[str, Any]] = {}
        for registration_id, spec in registrations.items():
            if not isinstance(spec, dict) or set(spec) != {
                "virtual_ip",
                "port",
                "service_type",
                "hostname",
                "instance_name",
                "properties",
            }:
                raise RuntimeError("network-helper mDNS registration is invalid")
            params = {**spec, "registration_id": registration_id}
            validated_id, validated_spec = self._validated_mdns_registration(params)
            validated_registrations[validated_id] = validated_spec
        self._mdns_registrations = validated_registrations

    @staticmethod
    def _bounded_timeout(value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("timeout must be a number")
        timeout = float(value)
        if not 0.1 <= timeout <= 10.0:
            raise ValueError("timeout must be between 0.1 and 10 seconds")
        return timeout

    @staticmethod
    def _service_type(value: Any) -> str:
        if not isinstance(value, str) or not _SERVICE_TYPE_RE.fullmatch(value):
            raise ValueError("invalid DNS-SD service type")
        return value if value.endswith(".local.") else f"{value}.local."

    @staticmethod
    def _host_label(value: Any, field: str) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{field} must be a string")
        label = value.rstrip(".").removesuffix(".local")
        if not _HOST_LABEL_RE.fullmatch(label):
            raise ValueError(f"invalid {field}")
        return label

    async def _mdns_browse(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        service_types = params.get("service_types")
        if not isinstance(service_types, list) or not 1 <= len(service_types) <= 32:
            raise ValueError("service_types must be a bounded list")
        validated = [self._service_type(item) for item in service_types]
        timeout = self._bounded_timeout(params.get("timeout"))
        from squirrelops_home_sensor.scanner.mdns_browser import MDNSBrowser

        results = await MDNSBrowser(
            browse_timeout=timeout,
            service_types=validated,
            delegate_to_helper=False,
        ).browse()
        return [
            {
                "ip": item.ip,
                "hostname": item.hostname,
                "service_types": sorted(item.service_types),
            }
            for item in results
            if ipaddress.IPv4Address(item.ip) in self.allowed_subnet
        ]

    async def _ssdp_msearch(self, params: dict[str, Any]) -> list[dict[str, str]]:
        timeout = self._bounded_timeout(params.get("timeout"))
        from squirrelops_home_sensor.scanner.ssdp_scanner import SSDPScanner

        responses = await SSDPScanner(
            collect_timeout=timeout,
        )._send_msearch_local()
        return [
            {"raw": raw, "source_ip": source_ip}
            for raw, source_ip in responses
            if ipaddress.IPv4Address(source_ip) in self.allowed_subnet
        ]

    def _validated_mdns_registration(
        self,
        params: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        registration_id = params.get("registration_id")
        if (
            not isinstance(registration_id, str)
            or not 1 <= len(registration_id) <= 128
            or not registration_id.replace(":", "").replace("-", "").isalnum()
        ):
            raise ValueError("invalid registration_id")
        virtual_ip = (
            self._host_lan_ip()
            if registration_id == "sensor"
            else self._lan_ip(params.get("virtual_ip"), "virtual_ip")
        )
        port = self._port(params.get("port"), "port")
        service_type = self._service_type(params.get("service_type"))
        hostname = self._host_label(params.get("hostname"), "hostname")
        instance_name = params.get("instance_name")
        if not isinstance(instance_name, str) or not _INSTANCE_RE.fullmatch(instance_name):
            raise ValueError("invalid instance_name")
        properties = params.get("properties", {})
        if not isinstance(properties, dict) or len(properties) > 32:
            raise ValueError("properties must be a bounded object")
        validated_properties: dict[str, str] = {}
        for key, value in properties.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or not 1 <= len(key) <= 64
                or len(value) > 256
            ):
                raise ValueError("invalid mDNS property")
            validated_properties[key] = value
        return registration_id, {
            "virtual_ip": virtual_ip,
            "port": port,
            "service_type": service_type,
            "hostname": hostname,
            "instance_name": instance_name,
            "properties": validated_properties,
        }

    async def _publish_mdns(
        self,
        registration_id: str,
        spec: dict[str, Any],
    ) -> None:
        if self._zeroconf is None:
            self._zeroconf = AsyncZeroconf()
        existing = self._mdns_services.pop(registration_id, None)
        if existing is not None:
            await self._zeroconf.async_unregister_service(existing)
        info = ServiceInfo(
            type_=spec["service_type"],
            name=f"{spec['instance_name']}.{spec['service_type']}",
            addresses=[socket.inet_aton(spec["virtual_ip"])],
            port=spec["port"],
            server=f"{spec['hostname']}.local.",
            properties=spec["properties"],
        )
        await self._zeroconf.async_register_service(info)
        self._mdns_services[registration_id] = info

    async def _register_mdns(self, params: dict[str, Any]) -> dict[str, bool]:
        registration_id, spec = self._validated_mdns_registration(params)
        await self._publish_mdns(registration_id, spec)
        self._mdns_registrations[registration_id] = spec
        self._persist_state()
        return {"success": True}

    async def _unregister_mdns(self, params: dict[str, Any]) -> dict[str, bool]:
        prefix = params.get("registration_prefix")
        if not isinstance(prefix, str) or not 1 <= len(prefix) <= 128:
            raise ValueError("invalid registration prefix")
        matching_keys = {
            key
            for key in (*self._mdns_services, *self._mdns_registrations)
            if key == prefix or key.startswith(f"{prefix}:")
        }
        for key in matching_keys:
            info = self._mdns_services.pop(key, None)
            if info is not None and self._zeroconf is not None:
                await self._zeroconf.async_unregister_service(info)
            self._mdns_registrations.pop(key, None)
        if matching_keys:
            self._persist_state()
        return {"success": True}

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        request_id: Any = None
        try:
            peer_uid = self._peer_uid(writer)
            raw = await asyncio.wait_for(
                reader.readline(),
                timeout=RPC_TIMEOUT_SECONDS,
            )
            if not raw or len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
                raise ValueError("request is empty, incomplete, or too large")
            request = _strict_json_loads(raw)
            request_id = request.get("id")
            if (
                set(request) - {"jsonrpc", "id", "method", "params"}
                or request.get("jsonrpc") != "2.0"
                or not isinstance(request_id, (int, str))
                or isinstance(request_id, bool)
                or not isinstance(request.get("method"), str)
            ):
                raise ValueError("invalid JSON-RPC request")
            params = request.get("params", {})
            if not isinstance(params, dict):
                raise ValueError("params must be an object")
            if peer_uid != self.allowed_uid and not (
                peer_uid == 0 and request["method"] == "ping"
            ):
                raise PermissionError("unauthorized network-helper peer")
            async with self._dispatch_lock:
                result = await self.dispatch(request["method"], params)
            response = {"jsonrpc": "2.0", "id": request_id, "result": result}
        except Exception as exc:
            logger.warning("Rejected network-helper request: %s", exc)
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32602, "message": str(exc)},
            }
        try:
            encoded = json.dumps(
                response,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
            writer.write(encoded[:MAX_REQUEST_BYTES])
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self._load_state()
        if (
            self._mimic_rules
            or self._protected_endpoints
            or self._classic_listeners
        ) and not await self._sync_forwards():
            raise RuntimeError("could not restore persisted network-helper state")
        for registration_id, spec in self._mdns_registrations.items():
            try:
                await self._publish_mdns(registration_id, spec)
            except Exception as exc:
                logger.warning(
                    "Could not restore mDNS registration %s: %s",
                    registration_id,
                    exc,
                )
        if self.socket_path.exists() or self.socket_path.is_socket():
            self.socket_path.unlink()
        self._server = await asyncio.start_unix_server(
            self._handle,
            path=str(self.socket_path),
            limit=MAX_REQUEST_BYTES,
        )
        # CAP_CHOWN is intentionally absent. The socket is connectable through
        # the dedicated volume, while SO_PEERCRED remains the authorization
        # boundary and accepts only the fixed sensor UID.
        os.chmod(self.socket_path, 0o666)
        logger.info("Linux network helper listening on %s", self.socket_path)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        # Do not remove aliases or packet-filter state merely because the
        # helper is restarting. The sensor withdraws its own state before a
        # normal stack shutdown; retaining state here keeps a helper-only
        # restart fail-closed and lets start() reconcile from the private
        # journal.
        if self._zeroconf is not None:
            for info in tuple(self._mdns_services.values()):
                with contextlib.suppress(Exception):
                    await self._zeroconf.async_unregister_service(info)
            self._mdns_services.clear()
            with contextlib.suppress(Exception):
                await self._zeroconf.async_close()
            self._zeroconf = None
        with contextlib.suppress(FileNotFoundError):
            self.socket_path.unlink()

    async def serve_forever(self) -> None:
        await self.start()
        assert self._server is not None
        try:
            await self._server.serve_forever()
        finally:
            await self.stop()


async def _healthcheck(socket_path: str) -> int:
    client = LinuxNetworkHelperClient(socket_path)
    return 0 if await client.is_available() else 1


def _server_from_environment() -> LinuxNetworkHelperServer:
    subnet = os.environ.get("SQUIRRELOPS_LAN_SUBNET", "").strip()
    if not subnet:
        raise RuntimeError("SQUIRRELOPS_LAN_SUBNET is required")
    return LinuxNetworkHelperServer(
        socket_path=os.environ.get(
            "SQUIRRELOPS_NETWORK_HELPER_SOCKET",
            DEFAULT_SOCKET_PATH,
        ),
        allowed_uid=int(os.environ.get("SQUIRRELOPS_SENSOR_UID", "10001")),
        allowed_subnet=subnet,
        sensor_ip=os.environ.get("SQUIRRELOPS_SENSOR_BRIDGE_IP", "172.30.0.2"),
        interface=os.environ.get("SQUIRRELOPS_NETWORK_INTERFACE", "auto"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SquirrelOps constrained Linux helper")
    parser.add_argument("--healthcheck", action="store_true")
    args = parser.parse_args(argv)
    socket_path = os.environ.get(
        "SQUIRRELOPS_NETWORK_HELPER_SOCKET",
        DEFAULT_SOCKET_PATH,
    )
    if args.healthcheck:
        return asyncio.run(_healthcheck(socket_path))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    asyncio.run(_server_from_environment().serve_forever())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
