"""Shared network input validation: SSRF guards and scan-target checks.

These helpers protect privileged or server-side network operations from
attacker-influenced input: argument injection into nmap, scanning or
fetching arbitrary off-LAN / cloud-metadata endpoints, and so on. The home
sensor only ever talks to private LAN hosts, so the policy is deliberately
strict (private addresses and ``.local`` names only).
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


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
    addr = ipaddress.IPv4Address(value)
    if addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return False
    return addr.is_private


def is_safe_lan_url(url: str) -> bool:
    """Return True if ``url`` is an http(s) URL pointing at a private LAN host.

    Used to gate server-side fetches (Home Assistant status, the LLM
    classifier endpoint) against SSRF. Only private IPs and ``.local`` mDNS
    names are allowed; public hosts, loopback, link-local (metadata),
    multicast, and non-http schemes are rejected.
    """
    if not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        # Non-IP hostname: only allow .local mDNS names.
        return hostname.endswith(".local")
    if addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return False
    return addr.is_private
