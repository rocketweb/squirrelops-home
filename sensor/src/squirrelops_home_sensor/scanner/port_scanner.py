"""Async TCP connect port scanner with optional banner grabbing.

Replaces nmap for port detection in the scan loop. Uses asyncio TCP
connections with per-port timeouts and a semaphore to limit concurrency.
No root privileges required — this is a standard TCP connect scan.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass

from squirrelops_home_sensor.scanner.service_names import get_service_name

logger = logging.getLogger(__name__)

# Ports where we send a minimal HTTP probe instead of passive read
_HTTP_PROBE_PORTS = frozenset({80, 443, 8000, 8008, 8080, 8081, 8083, 8086, 8088, 8123, 8443, 8444, 8888, 9090})
_HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n"

_MAX_BANNER_LEN = 256


@dataclass(frozen=True)
class PortResult:
    """Result of scanning a single port with optional service metadata."""

    port: int
    service_name: str | None = None
    banner: str | None = None


class PortScanner:
    """Async TCP connect scanner with optional banner grabbing.

    Parameters
    ----------
    timeout_per_port:
        Seconds to wait for each TCP connection attempt.
    max_concurrent:
        Maximum simultaneous connection attempts across all hosts/ports.
    """

    def __init__(
        self,
        timeout_per_port: float = 2.0,
        max_concurrent: int = 100,
    ) -> None:
        self._timeout = timeout_per_port
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def scan(
        self,
        targets: list[str],
        ports: list[int],
    ) -> dict[str, list[int]]:
        """Scan targets for open TCP ports (no banner grabbing).

        Parameters
        ----------
        targets:
            IP addresses to scan.
        ports:
            Port numbers to check on each target.

        Returns
        -------
        dict[str, list[int]]:
            Mapping of IP address to sorted list of open ports.
            IPs with no open ports are omitted.
        """
        if not targets or not ports:
            return {}

        tasks = []
        for ip in targets:
            for port in ports:
                tasks.append(self._check_port(ip, port))

        results_list = await asyncio.gather(*tasks)

        open_ports: dict[str, list[int]] = defaultdict(list)
        for ip, port, is_open in results_list:
            if is_open:
                open_ports[ip].append(port)

        # Sort ports for deterministic output
        return {ip: sorted(port_list) for ip, port_list in open_ports.items()}

    async def scan_with_banners(
        self,
        targets: list[str],
        ports: list[int],
        banner_timeout: float = 3.0,
    ) -> dict[str, list[PortResult]]:
        """Scan targets for open TCP ports with service name lookup and banner grabbing.

        After TCP connect succeeds, attempts to read a banner (first bytes
        sent by the service). For HTTP-family ports, sends a minimal HEAD probe.
        Banner grabbing is best-effort — timeout just means banner=None.

        Parameters
        ----------
        targets:
            IP addresses to scan.
        ports:
            Port numbers to check on each target.
        banner_timeout:
            Seconds to wait for banner data after connection.

        Returns
        -------
        dict[str, list[PortResult]]:
            Mapping of IP address to list of PortResult (sorted by port).
            IPs with no open ports are omitted.
        """
        if not targets or not ports:
            return {}

        tasks = []
        for ip in targets:
            for port in ports:
                tasks.append(self._check_port_with_banner(ip, port, banner_timeout))

        results_list = await asyncio.gather(*tasks)

        open_ports: dict[str, list[PortResult]] = defaultdict(list)
        for ip, result in results_list:
            if result is not None:
                open_ports[ip].append(result)

        return {
            ip: sorted(results, key=lambda r: r.port)
            for ip, results in open_ports.items()
        }

    async def _check_port(
        self, ip: str, port: int
    ) -> tuple[str, int, bool]:
        """Check if a single port is open on the given IP.

        Returns (ip, port, is_open).
        """
        async with self._semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self._timeout,
                )
                writer.close()
                await writer.wait_closed()
                return (ip, port, True)
            except (
                asyncio.TimeoutError,
                ConnectionRefusedError,
                OSError,
            ):
                return (ip, port, False)

    async def _check_port_with_banner(
        self, ip: str, port: int, banner_timeout: float,
    ) -> tuple[str, PortResult | None]:
        """Check if a port is open and attempt to grab a banner.

        Returns (ip, PortResult) if open, (ip, None) if closed.
        """
        async with self._semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self._timeout,
                )
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return (ip, None)

            # Port is open — try banner grab
            banner = None
            try:
                banner = await self._grab_banner(reader, writer, port, banner_timeout)
            except Exception:
                pass  # Banner grab is best-effort

            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

            service_name = get_service_name(port)
            return (ip, PortResult(
                port=port,
                service_name=service_name,
                banner=banner,
            ))

    async def _grab_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port: int,
        timeout: float,
    ) -> str | None:
        """Attempt to read a service banner from an open connection."""
        try:
            if port in _HTTP_PROBE_PORTS:
                writer.write(_HTTP_PROBE)
                await writer.drain()

            raw = await asyncio.wait_for(
                reader.read(_MAX_BANNER_LEN),
                timeout=timeout,
            )

            if not raw:
                return None

            banner = _sanitize_banner(raw)
            return banner if banner else None

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
            return None


def _sanitize_banner(raw: bytes) -> str:
    """Decode and clean up raw banner bytes."""
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = raw.decode("latin-1", errors="replace")

    # Strip control chars except space/tab/newline, collapse whitespace
    cleaned = []
    for ch in text:
        if ch in ("\n", "\r", "\t"):
            cleaned.append(" ")
        elif ch.isprintable() or ch == " ":
            cleaned.append(ch)

    result = " ".join("".join(cleaned).split())  # collapse whitespace
    return result[:_MAX_BANNER_LEN]
