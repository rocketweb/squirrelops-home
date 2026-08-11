"""Privileged operations abstraction.

Provides a platform-independent interface for network operations, including
the subset that requires elevated privileges.

On Linux/Docker and macOS, privileged operations are delegated to narrowly
scoped companion processes over Unix sockets.  ``LinuxPrivilegedOps`` is the
host-side implementation used only inside the constrained Linux helper.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import shlex
import socket
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

import defusedxml.ElementTree as ET

from squirrelops_home_sensor.subprocess_security import trusted_executable

logger = logging.getLogger(__name__)

_MIMIC_CHAIN = "SQUIRRELOPS_MIMIC"


@dataclass(frozen=True)
class _IptablesJump:
    """One rule outside the owned chain that jumps or goes to it."""

    rule: str
    source_chain: str
    position: int


@dataclass(frozen=True)
class _OwnedIptablesState:
    """The SquirrelOps-owned subset of one iptables table."""

    chain_exists: bool
    rules: tuple[str, ...] = ()
    jumps: tuple[_IptablesJump, ...] = ()


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

    requires_active_alias_withdrawal_probe = False

    def listener_bind_address(self, advertised_ip: str) -> str:
        """Return the local address used for an advertised virtual address.

        Direct/macOS deployments own the virtual address in the sensor network
        namespace.  The constrained Linux deployment overrides this so the
        backend listens on the sensor bridge while the helper owns the LAN IP.
        """
        return advertised_ip

    async def publish_listener(self, listener_id: int, port: int) -> bool:
        """Publish a classic decoy listener when namespaces are separated."""
        del listener_id, port
        return True

    async def unpublish_listener(self, listener_id: int) -> bool:
        """Withdraw a classic decoy listener publication."""
        del listener_id
        return True

    async def is_available(self) -> bool:
        """Check whether privileged operations are available.

        Returns True by default. macOS implementation checks the helper socket.
        """
        return True

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
        self, ip: str, interface: str = "en0", mask: str = "255.255.255.255",
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
        self,
        rules: list[dict],
        interface: str = "en0",
        protected_endpoints: list[dict] | None = None,
    ) -> bool:
        """Set up port forwarding and virtual-IP isolation for mimic decoys.

        Each rule redirects traffic from one IP:port to another IP:port,
        allowing unprivileged processes to serve on privileged ports.
        Protected endpoints default-deny other inbound traffic so IP aliases
        do not expose unrelated services from the host network stack.

        Parameters
        ----------
        rules:
            List of dicts with keys: from_ip, from_port, to_ip, to_port.
        interface:
            Network interface for the forwarding rules.
        protected_endpoints:
            List of dicts with ``ip`` and ``direct_ports``.  Redirected ports
            are passed by their translation rule; only non-remapped ports
            should be directly allowed.

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
    """Host-side implementation used only by the constrained Linux helper."""

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
        """Perform service scan using nmap subprocess.

        Runs as root in the container, so it never trusts caller input: each
        target must be a valid IPv4 address (rejecting option-injection like a
        leading ``-`` or ``--script=``) and ports must be in range. The ``--``
        separator additionally stops nmap from treating any target as an option.
        """
        from squirrelops_home_sensor.netvalidation import is_valid_ipv4

        if not targets or not ports:
            return []

        for target in targets:
            if not is_valid_ipv4(target):
                raise ValueError(f"Invalid scan target: {target!r}")
        for port in ports:
            if not (1 <= int(port) <= 65535):
                raise ValueError(f"Invalid port: {port!r}")

        port_str = ",".join(str(p) for p in ports)

        # All options (including "-oX -") must precede "--"; targets follow it.
        proc = await asyncio.create_subprocess_exec(
            trusted_executable("nmap"),
            "-sV", "-p", port_str, "-oX", "-", "--", *targets,
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
        self, ip: str, interface: str = "en0", mask: str = "255.255.255.255",
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
                trusted_executable("ip"),
                "addr", "add", f"{ip}/{prefix}", "dev", interface,
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
                trusted_executable("ip"),
                "addr", "del", f"{ip}/32", "dev", interface,
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
        self,
        rules: list[dict],
        interface: str = "en0",
        protected_endpoints: list[dict] | None = None,
    ) -> bool:
        """Atomically replace forwarding and isolation rules using iptables-restore."""
        del interface  # Rules match the protected VIP on every inbound interface.
        nat_rules, filter_rules = self._build_mimic_rules(
            rules,
            protected_endpoints or [],
        )
        return await self._apply_iptables_transaction(
            nat_rules=nat_rules,
            filter_rules=filter_rules,
            include_owned_chains=True,
            clearing=False,
        )

    async def clear_port_forwards(self) -> bool:
        """Atomically remove owned rules while preserving unrelated host rules."""
        return await self._apply_iptables_transaction(
            nat_rules=[],
            filter_rules=[],
            include_owned_chains=False,
            clearing=True,
        )

    @staticmethod
    def _build_mimic_rules(
        rules: list[dict],
        protected_endpoints: list[dict],
    ) -> tuple[list[str], list[str]]:
        """Validate inputs and render rules for the two dedicated chains."""
        validated_rules: list[tuple[str, int, str, int]] = []
        for rule in rules:
            try:
                from_ip = rule["from_ip"]
                from_port = rule["from_port"]
                to_ip = rule["to_ip"]
                to_port = rule["to_port"]
            except (KeyError, TypeError) as exc:
                raise ValueError("Invalid port-forward rule") from exc
            if not isinstance(from_ip, str) or not isinstance(to_ip, str):
                raise ValueError("Port-forward addresses must be IPv4 strings")
            ipaddress.IPv4Address(from_ip)
            ipaddress.IPv4Address(to_ip)
            if (
                type(from_port) is not int
                or not 1 <= from_port <= 65535
                or type(to_port) is not int
                or not 1 <= to_port <= 65535
            ):
                raise ValueError("Port-forward ports must be integers in 1..65535")
            validated_rules.append((from_ip, from_port, to_ip, to_port))

        nat_rules = [
            f"-A {_MIMIC_CHAIN} -p tcp -d {from_ip} --dport {from_port} "
            f"-j DNAT --to-destination {to_ip}:{to_port}"
            for from_ip, from_port, to_ip, to_port in validated_rules
        ]

        filter_rules: list[str] = []
        # DNAT now crosses from the host namespace into the sensor's private
        # bridge. The same owned chain is attached to FORWARD as well as INPUT:
        # accept only the exact translated backends, while INPUT still protects
        # every non-translated port on the advertised virtual address.
        for _, _, to_ip, to_port in validated_rules:
            rule = (
                f"-A {_MIMIC_CHAIN} -m conntrack --ctstate DNAT "
                f"-p tcp -d {to_ip} --dport {to_port} -j ACCEPT"
            )
            if rule not in filter_rules:
                filter_rules.append(rule)
        for endpoint in protected_endpoints:
            try:
                endpoint_ip = endpoint["ip"]
                direct_ports = endpoint.get("direct_ports", [])
            except (KeyError, TypeError) as exc:
                raise ValueError("Invalid protected endpoint") from exc
            if not isinstance(endpoint_ip, str):
                raise ValueError("Protected endpoint address must be an IPv4 string")
            ipaddress.IPv4Address(endpoint_ip)
            if not isinstance(direct_ports, list):
                raise ValueError("Protected endpoint direct_ports must be a list")
            for port in direct_ports:
                if type(port) is not int or not 1 <= port <= 65535:
                    raise ValueError(
                        f"Invalid protected endpoint port: {port!r}"
                    )
                filter_rules.append(
                    f"-A {_MIMIC_CHAIN} -p tcp -d {endpoint_ip} "
                    f"--dport {port} -j ACCEPT"
                )
            filter_rules.append(
                f"-A {_MIMIC_CHAIN} -p icmp -d {endpoint_ip} "
                "--icmp-type echo-request -j ACCEPT"
            )
            filter_rules.append(
                f"-A {_MIMIC_CHAIN} -d {endpoint_ip} -j DROP"
            )
        return nat_rules, filter_rules

    async def _apply_iptables_transaction(
        self,
        *,
        nat_rules: list[str],
        filter_rules: list[str],
        include_owned_chains: bool,
        clearing: bool,
    ) -> bool:
        """Apply an owned-only no-flush transaction, restoring owned state on failure."""
        filter_snapshot = await self._capture_iptables_table("filter")
        nat_snapshot = await self._capture_iptables_table("nat")
        if filter_snapshot is None or nat_snapshot is None:
            return False

        try:
            previous_filter = self._parse_owned_iptables_state(
                filter_snapshot,
                table="filter",
            )
            previous_nat = self._parse_owned_iptables_state(
                nat_snapshot,
                table="nat",
            )
            target_filter = self._target_owned_iptables_state(
                built_in_chain="INPUT",
                additional_built_in_chains=("FORWARD",),
                owned_rules=filter_rules,
                include_owned_chain=include_owned_chains,
            )
            target_nat = self._target_owned_iptables_state(
                built_in_chain="PREROUTING",
                owned_rules=nat_rules,
                include_owned_chain=include_owned_chains,
            )
            next_filter = self._render_owned_iptables_transition(
                table="filter",
                current=previous_filter,
                target=target_filter,
            )
            next_nat = self._render_owned_iptables_transition(
                table="nat",
                current=previous_nat,
                target=target_nat,
            )
        except ValueError:
            logger.exception("Could not construct an atomic iptables transaction")
            return False

        if next_filter is None and next_nat is None:
            return True

        # Setup commits deny-all INPUT isolation before enabling DNAT. Clearing
        # removes DNAT before removing the now-unneeded INPUT protection.
        if clearing:
            payload = "".join(
                block for block in (next_nat, next_filter) if block is not None
            )
        else:
            payload = "".join(
                block for block in (next_filter, next_nat) if block is not None
            )

        if not await self._run_iptables_restore(payload, test=True):
            logger.error("Atomic iptables transaction failed validation")
            return False
        if await self._run_iptables_restore(payload, test=False):
            return True

        logger.error(
            "Atomic iptables transaction failed; restoring prior owned state"
        )
        await self._rollback_owned_iptables_state(
            previous_filter=previous_filter,
            previous_nat=previous_nat,
            clearing=clearing,
        )
        return False

    async def _rollback_owned_iptables_state(
        self,
        *,
        previous_filter: _OwnedIptablesState,
        previous_nat: _OwnedIptablesState,
        clearing: bool,
    ) -> None:
        """Best-effort rollback without restoring or overwriting host-owned rules."""
        filter_snapshot = await self._capture_iptables_table("filter")
        nat_snapshot = await self._capture_iptables_table("nat")
        if filter_snapshot is None or nat_snapshot is None:
            logger.critical(
                "Could not inspect iptables after a failed transaction; "
                "owned-state rollback was not attempted"
            )
            return

        try:
            current_filter = self._parse_owned_iptables_state(
                filter_snapshot,
                table="filter",
            )
            current_nat = self._parse_owned_iptables_state(
                nat_snapshot,
                table="nat",
            )
            rollback_filter = self._render_owned_iptables_transition(
                table="filter",
                current=current_filter,
                target=previous_filter,
            )
            rollback_nat = self._render_owned_iptables_transition(
                table="nat",
                current=current_nat,
                target=previous_nat,
            )
        except ValueError:
            logger.exception(
                "Could not construct the owned-state iptables rollback"
            )
            return

        if rollback_filter is None and rollback_nat is None:
            return

        # Reversing setup restores NAT while the new isolation remains active.
        # Reversing clear restores isolation before re-enabling the prior NAT.
        if clearing:
            payload = "".join(
                block
                for block in (rollback_filter, rollback_nat)
                if block is not None
            )
        else:
            payload = "".join(
                block
                for block in (rollback_nat, rollback_filter)
                if block is not None
            )

        if not await self._run_iptables_restore(payload, test=True):
            logger.critical("Owned-state iptables rollback failed validation")
            return
        if not await self._run_iptables_restore(payload, test=False):
            logger.critical("Could not confirm restoration of owned iptables state")

    @staticmethod
    def _extract_iptables_table(snapshot: str, table: str) -> str:
        """Extract one complete iptables-save table block."""
        lines = snapshot.splitlines()
        marker = f"*{table}"
        try:
            start = lines.index(marker)
            end = lines.index("COMMIT", start + 1)
        except ValueError as exc:
            raise ValueError(f"iptables-save output omitted the {table} table") from exc
        if any(line.startswith("*") for line in lines[start + 1:end]):
            raise ValueError(f"Malformed iptables-save output for {table}")
        return "\n".join(lines[start:end + 1]) + "\n"

    @classmethod
    def _parse_owned_iptables_state(
        cls,
        snapshot: str,
        *,
        table: str,
    ) -> _OwnedIptablesState:
        """Read only the owned chain and jumps from an iptables-save table."""
        block = cls._extract_iptables_table(snapshot, table).splitlines()
        chain_exists = False
        owned_rules: list[str] = []
        owned_jumps: list[_IptablesJump] = []
        positions: dict[str, int] = {}

        for line in block[1:-1]:
            if not line or line.startswith("#"):
                continue
            if line.startswith(":"):
                try:
                    chain_name = line[1:].split(maxsplit=1)[0]
                except IndexError as exc:
                    raise ValueError(
                        f"Malformed chain declaration in {table}"
                    ) from exc
                if chain_name == _MIMIC_CHAIN:
                    chain_exists = True
                continue

            try:
                tokens = shlex.split(line)
            except ValueError as exc:
                raise ValueError(
                    f"Malformed iptables-save rule in {table}"
                ) from exc
            if len(tokens) < 2 or tokens[0] != "-A":
                raise ValueError(f"Unexpected iptables-save rule in {table}")

            source_chain = tokens[1]
            positions[source_chain] = positions.get(source_chain, 0) + 1
            if source_chain == _MIMIC_CHAIN:
                owned_rules.append(line)
            elif cls._tokens_target_owned_chain(tokens):
                owned_jumps.append(
                    _IptablesJump(
                        rule=line,
                        source_chain=source_chain,
                        position=positions[source_chain],
                    )
                )

        if not chain_exists and (owned_rules or owned_jumps):
            raise ValueError(
                f"{table} references {_MIMIC_CHAIN} without declaring it"
            )
        return _OwnedIptablesState(
            chain_exists=chain_exists,
            rules=tuple(owned_rules),
            jumps=tuple(owned_jumps),
        )

    @staticmethod
    def _target_owned_iptables_state(
        *,
        built_in_chain: str,
        additional_built_in_chains: tuple[str, ...] = (),
        owned_rules: list[str],
        include_owned_chain: bool,
    ) -> _OwnedIptablesState:
        """Build the desired owned state without copying host-owned rules."""
        if not include_owned_chain:
            return _OwnedIptablesState(chain_exists=False)
        built_in_chains = (built_in_chain, *additional_built_in_chains)
        return _OwnedIptablesState(
            chain_exists=True,
            rules=tuple(owned_rules),
            jumps=tuple(
                _IptablesJump(
                    rule=f"-A {chain} -j {_MIMIC_CHAIN}",
                    source_chain=chain,
                    position=1,
                )
                for chain in built_in_chains
            ),
        )

    @classmethod
    def _render_owned_iptables_transition(
        cls,
        *,
        table: str,
        current: _OwnedIptablesState,
        target: _OwnedIptablesState,
    ) -> str | None:
        """Render a --noflush update that touches only the owned chain/jumps."""
        if current == target:
            return None
        if current.jumps and not current.chain_exists:
            raise ValueError(f"Invalid current owned state in {table}")
        if target.jumps and not target.chain_exists:
            raise ValueError(f"Invalid target owned state in {table}")

        lines = [f"*{table}"]
        if current.chain_exists or target.chain_exists:
            # Under iptables-restore --noflush, declaring an existing user
            # chain flushes that chain alone and leaves every other chain intact.
            lines.append(f":{_MIMIC_CHAIN} - [0:0]")

        lines.extend(cls._delete_iptables_rule(jump.rule) for jump in current.jumps)

        if target.chain_exists:
            lines.extend(
                cls._insert_iptables_rule(jump)
                for jump in target.jumps
            )
            lines.extend(target.rules)
        elif current.chain_exists:
            lines.append(f"-X {_MIMIC_CHAIN}")

        return "\n".join([*lines, "COMMIT", ""])

    @staticmethod
    def _delete_iptables_rule(rule: str) -> str:
        """Convert one iptables-save append rule to an exact delete command."""
        tokens = shlex.split(rule)
        if len(tokens) < 2 or tokens[0] != "-A":
            raise ValueError("Cannot delete malformed iptables-save rule")
        prefix = f"-A {tokens[1]}"
        if rule != prefix and not rule.startswith(f"{prefix} "):
            raise ValueError("Cannot preserve malformed iptables-save rule")
        return f"-D {tokens[1]}{rule[len(prefix):]}"

    @staticmethod
    def _insert_iptables_rule(jump: _IptablesJump) -> str:
        """Convert a saved jump to an insertion at its prior rule position."""
        tokens = shlex.split(jump.rule)
        if (
            len(tokens) < 2
            or tokens[0] != "-A"
            or tokens[1] != jump.source_chain
        ):
            raise ValueError("Cannot insert malformed iptables-save rule")
        prefix = f"-A {jump.source_chain}"
        if jump.rule != prefix and not jump.rule.startswith(f"{prefix} "):
            raise ValueError("Cannot preserve malformed iptables-save rule")
        return (
            f"-I {jump.source_chain} {jump.position}"
            f"{jump.rule[len(prefix):]}"
        )

    @staticmethod
    def _tokens_target_owned_chain(tokens: list[str]) -> bool:
        """Return whether parsed rule tokens jump or go to the owned chain."""
        return any(
            tokens[index] in {"-j", "--jump", "-g", "--goto"}
            and tokens[index + 1] == _MIMIC_CHAIN
            for index in range(len(tokens) - 1)
        )

    async def _capture_iptables_table(self, table: str) -> str | None:
        """Capture a table so its owned subset can be inspected."""
        try:
            proc = await asyncio.create_subprocess_exec(
                trusted_executable("iptables-save"),
                "-t",
                table,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.error(
                    "iptables-save %s failed: %s",
                    table,
                    stderr.decode(errors="replace").strip(),
                )
                return None
            return stdout.decode()
        except Exception:
            logger.exception("Could not capture the %s iptables table", table)
            return None

    async def _run_iptables_restore(self, payload: str, *, test: bool) -> bool:
        """Validate or apply an owned-only iptables-restore payload."""
        args = [trusted_executable("iptables-restore"), "--noflush", "-w", "5"]
        if test:
            args.append("--test")
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate(payload.encode())
            if proc.returncode != 0:
                logger.error(
                    "%s failed: %s",
                    "iptables-restore validation" if test else "iptables-restore",
                    stderr.decode(errors="replace").strip(),
                )
                return False
            return True
        except Exception:
            logger.exception(
                "%s failed",
                "iptables-restore validation" if test else "iptables-restore",
            )
            return False


def create_privileged_ops() -> PrivilegedOperations:
    """Create the platform-appropriate privileged operations implementation.

    Returns a Unix-socket client on both supported production platforms.
    """
    if sys.platform == "darwin":
        from squirrelops_home_sensor.privileged.xpc import MacOSPrivilegedOps

        return MacOSPrivilegedOps()
    from squirrelops_home_sensor.privileged.linux_sidecar import (
        DEFAULT_SOCKET_PATH,
        LinuxNetworkHelperClient,
    )

    return LinuxNetworkHelperClient(
        os.environ.get("SQUIRRELOPS_NETWORK_HELPER_SOCKET", DEFAULT_SOCKET_PATH)
    )
