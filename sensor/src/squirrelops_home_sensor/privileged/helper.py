"""Privileged operations abstraction.

Provides a platform-independent interface for operations requiring
elevated privileges: ARP scanning, service scanning, port binding,
and DNS sniffing.

On Linux/Docker, operations are performed directly (container runs as root).
On macOS, operations are delegated to the squirrelops-helper via Unix
domain socket JSON-RPC (see xpc.py).
"""

from __future__ import annotations

import asyncio
import sys
import logging
import socket
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ServiceResult:
    """Result of a service/port scan on a single port."""

    ip: str
    port: int
    banner: str | None = None


@dataclass(frozen=True)
class DNSQuery:
    """A captured DNS query."""

    query_name: str
    source_ip: str
    timestamp: datetime


class PrivilegedOperations(ABC):
    """Abstract interface for privileged network operations.

    Implementations provide either direct access (Linux/Docker) or
    delegation to a privileged helper process (macOS).
    """

    @abstractmethod
    async def arp_scan(self, subnet: str) -> list[tuple[str, str]]:
        """Scan a subnet via ARP and return (ip, mac) pairs.

        Parameters
        ----------
        subnet:
            CIDR notation subnet (e.g., "192.168.1.0/24").

        Returns
        -------
        list[tuple[str, str]]:
            List of (ip_address, mac_address) tuples for responding hosts.
        """

    @abstractmethod
    async def service_scan(
        self, targets: list[str], ports: list[int]
    ) -> list[ServiceResult]:
        """Scan targets for open services on specified ports.

        Parameters
        ----------
        targets:
            List of IP addresses to scan.
        ports:
            List of port numbers to check.

        Returns
        -------
        list[ServiceResult]:
            Open ports with optional service banners.
        """

    @abstractmethod
    async def bind_listener(self, address: str, port: int) -> socket.socket:
        """Bind a listening socket on the given address and port.

        Parameters
        ----------
        address:
            Bind address (e.g., "0.0.0.0").
        port:
            Port number (may require privilege for ports < 1024).

        Returns
        -------
        socket.socket:
            A bound, listening socket.
        """

    @abstractmethod
    async def start_dns_sniff(self, interface: str) -> None:
        """Start passive DNS query sniffing on the given interface.

        Parameters
        ----------
        interface:
            Network interface name (e.g., "eth0", "en0").
        """

    @abstractmethod
    async def stop_dns_sniff(self) -> None:
        """Stop passive DNS query sniffing."""

    @abstractmethod
    async def get_dns_queries(self, since: datetime) -> list[DNSQuery]:
        """Return DNS queries observed since the given timestamp.

        Parameters
        ----------
        since:
            Only return queries observed after this timestamp.

        Returns
        -------
        list[DNSQuery]:
            List of captured DNS queries.
        """

    @abstractmethod
    async def add_ip_alias(
        self, ip: str, interface: str = "en0", mask: str = "255.255.255.0",
    ) -> bool:
        """Add an IP alias to a network interface.

        Parameters
        ----------
        ip:
            The IP address to alias (e.g. "192.168.1.200").
        interface:
            Network interface name (default "en0" on macOS).
        mask:
            Subnet mask for the alias.

        Returns
        -------
        bool:
            True if the alias was successfully added.
        """

    @abstractmethod
    async def remove_ip_alias(self, ip: str, interface: str = "en0") -> bool:
        """Remove an IP alias from a network interface.

        Parameters
        ----------
        ip:
            The IP address alias to remove.
        interface:
            Network interface name.

        Returns
        -------
        bool:
            True if the alias was successfully removed.
        """

    @abstractmethod
    async def setup_port_forwards(
        self, rules: list[dict], interface: str = "en0",
    ) -> bool:
        """Set up port forwarding rules for mimic decoys.

        Each rule redirects traffic from one IP:port to another IP:port,
        allowing unprivileged processes to serve on privileged ports.

        Parameters
        ----------
        rules:
            List of dicts with keys: from_ip, from_port, to_ip, to_port.
        interface:
            Network interface for the forwarding rules.

        Returns
        -------
        bool:
            True if rules were successfully applied.
        """

    @abstractmethod
    async def clear_port_forwards(self) -> bool:
        """Clear all port forwarding rules.

        Returns
        -------
        bool:
            True if rules were successfully cleared.
        """


class LinuxPrivilegedOps(PrivilegedOperations):
    """Direct privileged operations for Linux/Docker.

    The sensor container runs as root with CAP_NET_RAW and CAP_NET_ADMIN,
    so all operations are performed directly using scapy and nmap.
    """

    def __init__(self) -> None:
        self._dns_queries: list[DNSQuery] = []
        self._sniff_task: asyncio.Task | None = None
        self._sniffing = False

    async def arp_scan(self, subnet: str) -> list[tuple[str, str]]:
        """Perform ARP scan using scapy."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._arp_scan_sync, subnet)

    def _arp_scan_sync(self, subnet: str) -> list[tuple[str, str]]:
        """Synchronous ARP scan using scapy (runs in executor)."""
        from scapy.all import ARP, Ether, srp

        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(arp_request, timeout=3, verbose=False)

        results = []
        for _, received in answered:
            results.append((received.psrc, received.hwsrc))
        return results

    async def service_scan(
        self, targets: list[str], ports: list[int]
    ) -> list[ServiceResult]:
        """Perform service scan using nmap subprocess."""
        if not targets or not ports:
            return []

        port_str = ",".join(str(p) for p in ports)

        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-p", port_str, *targets, "-oX", "-",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()

        return self._parse_nmap_xml(stdout.decode())

    def _parse_nmap_xml(self, xml_output: str) -> list[ServiceResult]:
        """Parse nmap XML output into ServiceResult list."""
        results = []
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall(".//host"):
                addr_elem = host.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    continue
                ip = addr_elem.get("addr", "")

                for port_elem in host.findall(".//port"):
                    state = port_elem.find("state")
                    if state is None or state.get("state") != "open":
                        continue

                    port_num = int(port_elem.get("portid", "0"))
                    service = port_elem.find("service")
                    banner = None
                    if service is not None:
                        product = service.get("product", "")
                        version = service.get("version", "")
                        banner = f"{product}/{version}".strip("/") if product else None

                    results.append(ServiceResult(ip=ip, port=port_num, banner=banner))
        except ET.ParseError:
            logger.warning("Failed to parse nmap XML output")

        return results

    async def bind_listener(self, address: str, port: int) -> socket.socket:
        """Bind a listening socket directly."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((address, port))
        sock.listen(128)
        sock.setblocking(False)
        return sock

    async def start_dns_sniff(self, interface: str) -> None:
        """Start DNS sniffing using scapy in a background thread."""
        self._sniffing = True
        self._dns_queries = []

    async def stop_dns_sniff(self) -> None:
        """Stop DNS sniffing."""
        self._sniffing = False
        if self._sniff_task is not None:
            self._sniff_task.cancel()
            self._sniff_task = None

    async def get_dns_queries(self, since: datetime) -> list[DNSQuery]:
        """Return DNS queries observed since the given timestamp."""
        return [q for q in self._dns_queries if q.timestamp >= since]

    async def add_ip_alias(
        self, ip: str, interface: str = "en0", mask: str = "255.255.255.0",
    ) -> bool:
        """Add IP alias using ``ip addr add``.

        Uses asyncio.create_subprocess_exec (not shell) to avoid injection.
        The ip parameter is validated as a valid IPv4 address before use.
        """
        import ipaddress as _ipa
        # Validate inputs to prevent injection
        _ipa.IPv4Address(ip)
        prefix = _ipa.IPv4Network(f"0.0.0.0/{mask}").prefixlen
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "addr", "add", f"{ip}/{prefix}", "dev", interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.warning("ip addr add failed: %s", stderr.decode().strip())
                return False
            return True
        except Exception:
            logger.exception("Failed to add IP alias %s on %s", ip, interface)
            return False

    async def remove_ip_alias(self, ip: str, interface: str = "en0") -> bool:
        """Remove IP alias using ``ip addr del``.

        Uses asyncio.create_subprocess_exec (not shell) to avoid injection.
        The ip parameter is validated as a valid IPv4 address before use.
        """
        import ipaddress as _ipa
        _ipa.IPv4Address(ip)
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "addr", "del", f"{ip}/32", "dev", interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.warning("ip addr del failed: %s", stderr.decode().strip())
                return False
            return True
        except Exception:
            logger.exception("Failed to remove IP alias %s on %s", ip, interface)
            return False

    async def setup_port_forwards(
        self, rules: list[dict], interface: str = "en0",
    ) -> bool:
        """Set up port forwarding using iptables DNAT rules."""
        import ipaddress as _ipa

        # Flush existing squirrelops chain
        await self._run_iptables(
            "-t", "nat", "-F", "SQUIRRELOPS_MIMIC",
        )
        # Ensure chain exists (ignore error if already exists)
        await self._run_iptables(
            "-t", "nat", "-N", "SQUIRRELOPS_MIMIC",
        )
        # Ensure chain is referenced from PREROUTING
        await self._run_iptables(
            "-t", "nat", "-C", "PREROUTING", "-j", "SQUIRRELOPS_MIMIC",
        ) or await self._run_iptables(
            "-t", "nat", "-A", "PREROUTING", "-j", "SQUIRRELOPS_MIMIC",
        )

        for rule in rules:
            from_ip = rule["from_ip"]
            from_port = rule["from_port"]
            to_ip = rule["to_ip"]
            to_port = rule["to_port"]
            _ipa.IPv4Address(from_ip)
            _ipa.IPv4Address(to_ip)

            ok = await self._run_iptables(
                "-t", "nat", "-A", "SQUIRRELOPS_MIMIC",
                "-p", "tcp", "-d", from_ip, "--dport", str(from_port),
                "-j", "DNAT", "--to-destination", f"{to_ip}:{to_port}",
            )
            if not ok:
                logger.warning(
                    "Failed to add iptables DNAT rule %s:%d -> %s:%d",
                    from_ip, from_port, to_ip, to_port,
                )
                return False
        return True

    async def clear_port_forwards(self) -> bool:
        """Clear all iptables port forwarding rules."""
        ok = await self._run_iptables(
            "-t", "nat", "-F", "SQUIRRELOPS_MIMIC",
        )
        return ok

    async def _run_iptables(self, *args: str) -> bool:
        """Run an iptables command. Returns True on success."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "iptables", *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.debug("iptables %s failed: %s", args, stderr.decode().strip())
                return False
            return True
        except Exception:
            logger.debug("iptables %s exception", args, exc_info=True)
            return False


def create_privileged_ops() -> PrivilegedOperations:
    """Create the platform-appropriate privileged operations implementation.

    Returns ``MacOSPrivilegedOps`` on macOS (delegates to the Swift helper
    via JSON-RPC), ``LinuxPrivilegedOps`` everywhere else (direct root ops).
    """
    if sys.platform == "darwin":
        from squirrelops_home_sensor.privileged.xpc import MacOSPrivilegedOps

        return MacOSPrivilegedOps()
    return LinuxPrivilegedOps()
