"""Shared network input validation: SSRF guards and scan-target checks.

These helpers protect privileged or server-side network operations from
attacker-influenced input: argument injection into nmap, scanning or
fetching arbitrary off-LAN / cloud-metadata endpoints, and so on. The home
sensor only ever talks to private LAN hosts, so the policy is deliberately
strict (private addresses and ``.local`` names only).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

_RFC1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_IPV6_UNIQUE_LOCAL = ipaddress.IPv6Network("fc00::/7")


def is_private_lan_address(value: str) -> bool:
    """Return True only for an address routable inside a private LAN."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return any(address in network for network in _RFC1918_NETWORKS)
    return address in _IPV6_UNIQUE_LOCAL


@dataclass(frozen=True)
class ResolvedLANURL:
    """A validated URL plus the exact addresses observed for this connection."""

    original_url: str
    hostname: str
    port: int
    addresses: tuple[str, ...]
    host_header: str

    @property
    def connect_ip(self) -> str:
        """Use one deterministic validated address for the actual socket."""
        return self.addresses[0]

    @property
    def pinned_url(self) -> str:
        """Return the original URL with its authority replaced by connect_ip."""
        parsed = urlparse(self.original_url)
        host = (
            f"[{self.connect_ip}]"
            if ":" in self.connect_ip
            else self.connect_ip
        )
        return urlunparse(parsed._replace(netloc=f"{host}:{self.port}"))


def resolve_lan_url(url: str) -> ResolvedLANURL | None:
    """Resolve and pin one private-LAN HTTP(S) URL.

    DNS names are limited to mDNS ``.local`` names. IPv6 link-local mDNS
    answers are ignored because they require an interface scope and are never
    selected for the socket. Every remaining address must satisfy the
    private-LAN policy; a mixed private/public response fails closed. Call this
    immediately before each new connection and use ``pinned_url`` or
    ``connect_ip`` for the socket to close DNS-rebinding races while retaining
    ``hostname`` for HTTP Host and TLS SNI.
    """
    if not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    raw_hostname = parsed.hostname
    if not raw_hostname:
        return None
    hostname = raw_hostname.rstrip(".").casefold()
    if not hostname:
        return None
    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        if not hostname.endswith(".local") or hostname == ".local":
            return None
        try:
            hostname.encode("ascii")
            answers = socket.getaddrinfo(
                hostname,
                port,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except (OSError, UnicodeError):
            return None
        addresses = tuple(
            dict.fromkeys(
                str(item[4][0]).split("%", 1)[0]
                for item in answers
                if item[0] in (socket.AF_INET, socket.AF_INET6)
                and item[4]
            )
        )
    else:
        addresses = (str(literal),)

    usable_addresses: list[str] = []
    for value in addresses:
        address = ipaddress.ip_address(value)
        if is_private_lan_address(value):
            usable_addresses.append(value)
        elif not (
            isinstance(address, ipaddress.IPv6Address)
            and address.is_link_local
        ):
            return None
    addresses = tuple(usable_addresses)
    if not addresses:
        return None

    display_host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if parsed.scheme == "https" else 80
    host_header = (
        display_host
        if port == default_port
        else f"{display_host}:{port}"
    )
    return ResolvedLANURL(
        original_url=url,
        hostname=hostname,
        port=port,
        addresses=addresses,
        host_header=host_header,
    )


def is_valid_ipv4(value: str) -> bool:
    """Return True only for a syntactically valid dotted-quad IPv4 address.

    Rejects hostnames, CIDR ranges, leading-dash option-injection strings,
    and anything containing shell metacharacters.
    """
    if not isinstance(value, str):
        return False
    try:
        ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return True


def is_safe_scan_target(value: str) -> bool:
    """Return True if ``value`` is a private LAN IPv4 safe to scan.

    Excludes public/global addresses (scan amplification / off-LAN SSRF),
    loopback, link-local (cloud metadata at 169.254.169.254), and multicast.
    """
    if not is_valid_ipv4(value):
        return False
    return is_private_lan_address(value)


def is_safe_lan_url(url: str) -> bool:
    """Return True if ``url`` is an http(s) URL pointing at a private LAN host.

    Used to gate server-side fetches (Home Assistant status, the LLM
    classifier endpoint) against SSRF. Only private IPs and ``.local`` mDNS
    names are allowed; public hosts, loopback, link-local (metadata),
    multicast, and non-http schemes are rejected.
    """
    if not isinstance(url, str):
        return False
    return resolve_lan_url(url) is not None
