"""Scout Engine — deep service fingerprinting for discovered devices.

Probes every open port to capture what a potential intruder would see:
HTTP responses (status, headers, body), TLS certificate details,
and protocol-specific version strings (SSH, FTP, SMTP).

Results are stored as ServiceProfile records in the database and used
by the mimic template generator to create convincing decoy replicas.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

import aiosqlite
import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID

logger = logging.getLogger("squirrelops_home_sensor.scouts")

# Ports that serve HTTP and should get a full GET probe
_HTTP_PORTS: set[int] = {
    80, 443, 3000, 3001, 5000, 5173, 8000, 8008, 8080, 8081,
    8083, 8086, 8088, 8123, 8200, 8443, 8444, 8500, 8888, 9000, 9090,
}

# Ports that use TLS and should get certificate inspection
_TLS_PORTS: set[int] = {443, 8443, 993, 995, 8883}

# Protocol-specific ports for banner/version probing
_PROTOCOL_PORTS: dict[int, str] = {
    22: "ssh",
    21: "ftp",
    25: "smtp",
    587: "smtp",
    110: "pop3",
    143: "imap",
}

_MAX_BODY_SIZE = 2048  # 2KB body snippet
_MAX_FAVICON_SIZE = 64 * 1024
_HTTP_TIMEOUT = 5.0
_PROTO_TIMEOUT = 5.0
_TLS_TIMEOUT = 5.0
_PORT_PROBE_DEADLINE = 20.0


@dataclass
class ServiceProfile:
    """Complete service fingerprint for one device+port."""

    device_id: int
    ip_address: str
    port: int
    protocol: str = "tcp"
    service_name: str | None = None

    # HTTP probe results
    http_status: int | None = None
    http_headers: dict[str, str] | None = None
    http_body_snippet: str | None = None
    http_server_header: str | None = None
    favicon_hash: str | None = None
    favicon_body: bytes | None = None

    # TLS probe results
    tls_cn: str | None = None
    tls_issuer: str | None = None
    tls_not_after: str | None = None

    # Protocol probe results
    protocol_version: str | None = None

    scouted_at: str = ""


class ScoutEngine:
    """Orchestrates deep service fingerprinting for discovered devices."""

    def __init__(
        self,
        db: aiosqlite.Connection,
        max_concurrent: int = 20,
        http_timeout: float = _HTTP_TIMEOUT,
        probe_deadline: float = _PORT_PROBE_DEADLINE,
    ) -> None:
        if (
            isinstance(max_concurrent, bool)
            or not isinstance(max_concurrent, int)
            or not 1 <= max_concurrent <= 64
        ):
            raise ValueError("max_concurrent must be between 1 and 64")
        if (
            isinstance(http_timeout, bool)
            or not isinstance(http_timeout, (int, float))
            or not math.isfinite(http_timeout)
            or not 0 < http_timeout <= 30
        ):
            raise ValueError("http_timeout must be finite and between 0 and 30 seconds")
        if (
            isinstance(probe_deadline, bool)
            or not isinstance(probe_deadline, (int, float))
            or not math.isfinite(probe_deadline)
            or not 0 < probe_deadline <= 60
        ):
            raise ValueError("probe_deadline must be finite and between 0 and 60 seconds")
        self._db = db
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._http_timeout = float(http_timeout)
        self._probe_deadline = float(probe_deadline)

    async def scout_device(
        self, device_id: int, ip: str, ports: list[int],
    ) -> list[ServiceProfile]:
        """Probe all open ports on one device. Returns profiles."""
        tasks = []
        for port in ports:
            tasks.append(self._scout_port(device_id, ip, port))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        profiles = []
        for r in results:
            if isinstance(r, ServiceProfile):
                profiles.append(r)
            elif isinstance(r, Exception):
                logger.debug("Scout probe failed: %s", r)
        return profiles

    async def scout_all(
        self, device_ports: dict[tuple[int, str], list[int]],
    ) -> int:
        """Scout and reconcile one authoritative open-port inventory.

        Parameters
        ----------
        device_ports:
            Mapping of ``(device_id, ip_address)`` to list of open port numbers.

        Returns count of profiles created/updated.
        """
        count = 0
        all_tasks = []
        inventory_keys: set[tuple[int, int, str]] = set()
        for (device_id, ip), ports in device_ports.items():
            for port in ports:
                inventory_keys.add((device_id, port, "tcp"))
                all_tasks.append(self._scout_port(device_id, ip, port))

        results = await asyncio.gather(*all_tasks, return_exceptions=True)
        try:
            for r in results:
                if isinstance(r, ServiceProfile):
                    await self._persist_profile(r, commit=False)
                    count += 1
                elif isinstance(r, Exception):
                    logger.debug("Scout probe failed: %s", r)

            # The scheduler calls this method only after it has read the current
            # online/open-port inventory successfully. Remove profiles that no
            # longer exist in that authoritative snapshot, including every
            # profile when the successful snapshot is empty.
            await self._remove_profiles_not_in(inventory_keys)
            await self._db.commit()
        except Exception:
            await self._db.rollback()
            raise
        return count

    async def _remove_profiles_not_in(
        self,
        inventory_keys: set[tuple[int, int, str]],
    ) -> None:
        """Delete profiles absent from a successful current inventory."""
        cursor = await self._db.execute(
            "SELECT id, device_id, port, protocol FROM service_profiles"
        )
        stale_ids = [
            row["id"]
            for row in await cursor.fetchall()
            if (row["device_id"], row["port"], row["protocol"])
            not in inventory_keys
        ]
        if stale_ids:
            await self._db.executemany(
                "DELETE FROM service_profiles WHERE id = ?",
                [(profile_id,) for profile_id in stale_ids],
            )

    async def get_profiles_for_device(self, device_id: int) -> list[ServiceProfile]:
        """Load stored profiles from DB."""
        cursor = await self._db.execute(
            "SELECT * FROM service_profiles WHERE device_id = ? ORDER BY port",
            (device_id,),
        )
        rows = await cursor.fetchall()
        profiles = []
        for row in rows:
            profiles.append(ServiceProfile(
                device_id=row["device_id"],
                ip_address=row["ip_address"],
                port=row["port"],
                protocol=row["protocol"],
                service_name=row["service_name"],
                http_status=row["http_status"],
                http_headers=json.loads(row["http_headers"]) if row["http_headers"] else None,
                http_body_snippet=row["http_body_snippet"],
                http_server_header=row["http_server_header"],
                favicon_hash=row["favicon_hash"],
                favicon_body=row["favicon_body"],
                tls_cn=row["tls_cn"],
                tls_issuer=row["tls_issuer"],
                tls_not_after=row["tls_not_after"],
                protocol_version=row["protocol_version"],
                scouted_at=row["scouted_at"],
            ))
        return profiles

    async def get_all_profiles(self) -> list[ServiceProfile]:
        """Load all stored profiles from DB."""
        cursor = await self._db.execute(
            "SELECT * FROM service_profiles ORDER BY device_id, port"
        )
        rows = await cursor.fetchall()
        profiles = []
        for row in rows:
            profiles.append(ServiceProfile(
                device_id=row["device_id"],
                ip_address=row["ip_address"],
                port=row["port"],
                protocol=row["protocol"],
                service_name=row["service_name"],
                http_status=row["http_status"],
                http_headers=json.loads(row["http_headers"]) if row["http_headers"] else None,
                http_body_snippet=row["http_body_snippet"],
                http_server_header=row["http_server_header"],
                favicon_hash=row["favicon_hash"],
                favicon_body=row["favicon_body"],
                tls_cn=row["tls_cn"],
                tls_issuer=row["tls_issuer"],
                tls_not_after=row["tls_not_after"],
                protocol_version=row["protocol_version"],
                scouted_at=row["scouted_at"],
            ))
        return profiles

    async def get_mimic_candidates(
        self,
        count: int = 10,
        exclude_device_ids: set[int] | None = None,
    ) -> list[ServiceProfile]:
        """Return complete profiles for up to ``count`` candidate devices.

        ``count`` is a device count, not a profile-row count. The old query
        applied ``LIMIT`` directly to service rows, so a multi-port device
        consumed every slot and already-mimicked devices could starve all new
        candidates. Banner-only services are valid mimic inputs too.
        """
        if count <= 0:
            return []

        excluded = sorted(exclude_device_ids or set())
        exclusion_sql = ""
        params: list[int] = []
        if excluded:
            placeholders = ",".join("?" for _ in excluded)
            exclusion_sql = f"AND d.id NOT IN ({placeholders})"
            params.extend(excluded)
        params.append(count)

        cursor = await self._db.execute(
            f"""WITH candidate_devices AS (
                    SELECT
                        d.id AS device_id,
                        CASE d.device_type
                            WHEN 'smart_home' THEN 0
                            WHEN 'camera' THEN 1
                            WHEN 'media' THEN 2
                            WHEN 'printer' THEN 3
                            ELSE 4
                        END AS device_priority,
                        MIN(sp.port) AS first_port
                    FROM devices d
                    JOIN service_profiles sp ON sp.device_id = d.id
                    WHERE d.is_online = 1
                    AND (
                        sp.http_status IS NOT NULL
                        OR sp.protocol_version IS NOT NULL
                    )
                    {exclusion_sql}
                    GROUP BY d.id, d.device_type
                    ORDER BY device_priority, first_port, d.id
                    LIMIT ?
                )
                SELECT sp.*, cd.device_priority, cd.first_port
                FROM candidate_devices cd
                JOIN service_profiles sp ON sp.device_id = cd.device_id
                ORDER BY cd.device_priority, cd.first_port, cd.device_id, sp.port""",
            tuple(params),
        )
        rows = await cursor.fetchall()
        profiles = []
        for row in rows:
            profiles.append(ServiceProfile(
                device_id=row["device_id"],
                ip_address=row["ip_address"],
                port=row["port"],
                protocol=row["protocol"],
                service_name=row["service_name"],
                http_status=row["http_status"],
                http_headers=json.loads(row["http_headers"]) if row["http_headers"] else None,
                http_body_snippet=row["http_body_snippet"],
                http_server_header=row["http_server_header"],
                favicon_hash=row["favicon_hash"],
                favicon_body=row["favicon_body"],
                tls_cn=row["tls_cn"],
                tls_issuer=row["tls_issuer"],
                tls_not_after=row["tls_not_after"],
                protocol_version=row["protocol_version"],
                scouted_at=row["scouted_at"],
            ))
        return profiles

    # ------------------------------------------------------------------
    # Internal probe methods
    # ------------------------------------------------------------------

    async def _scout_port(
        self, device_id: int, ip: str, port: int,
    ) -> ServiceProfile:
        """Probe a single port with all applicable probes."""
        async with self._semaphore:
            now = datetime.now(UTC).isoformat()
            profile = ServiceProfile(
                device_id=device_id,
                ip_address=ip,
                port=port,
                scouted_at=now,
            )

            # Determine which probes to run
            is_http = port in _HTTP_PORTS
            is_tls = port in _TLS_PORTS
            is_proto = port in _PROTOCOL_PORTS

            probes: list[tuple[str, Callable[[], Awaitable[None]]]] = []
            if is_http:
                probes.append((
                    "http",
                    lambda: self._probe_http(
                        profile,
                        ip,
                        port,
                        use_tls=is_tls,
                    ),
                ))
            if is_tls:
                probes.append(("tls", lambda: self._probe_tls(profile, ip, port)))
            if is_proto and not is_http:
                probes.append((
                    "proto",
                    lambda: self._probe_protocol(profile, ip, port),
                ))

            # If no specific probe, try a generic banner read
            if not probes:
                probes.append((
                    "proto",
                    lambda: self._probe_protocol(profile, ip, port),
                ))

            try:
                # Bound the complete multi-probe lifecycle, not only individual
                # reads. A hostile port cannot monopolize a semaphore slot by
                # consuming each per-operation timeout in sequence.
                async with asyncio.timeout(self._probe_deadline):
                    for name, probe in probes:
                        try:
                            await probe()
                        except Exception as exc:
                            logger.debug(
                                "Probe %s failed for %s:%d: %s",
                                name,
                                ip,
                                port,
                                exc,
                            )
            except TimeoutError:
                logger.debug(
                    "Scout deadline exceeded for %s:%d after %.1fs",
                    ip,
                    port,
                    self._probe_deadline,
                )

            return profile

    async def _probe_http(
        self, profile: ServiceProfile, ip: str, port: int, use_tls: bool = False,
    ) -> None:
        """Full HTTP GET probe — captures status, headers, body snippet, favicon."""
        scheme = "https" if use_tls else "http"
        base_url = f"{scheme}://{ip}:{port}"

        # Do NOT follow redirects: the target is an untrusted LAN device, and a
        # 302 Location is a fingerprinting signal to record, not a URL to chase.
        # Following it (with verify=False) would let a rogue device redirect the
        # probe to loopback or off-LAN endpoints (SSRF). The sibling SSDP path is
        # already hardened this way.
        # Scouting intentionally fingerprints self-signed LAN services. These
        # requests contain no credentials and redirects stay disabled, so TLS
        # certificate identity is not used as an authorization boundary.
        async with httpx.AsyncClient(  # nosec B501
            timeout=self._http_timeout,
            verify=False,
            follow_redirects=False,
            trust_env=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "Accept-Encoding": "identity",
            },
        ) as client:
            # GET /
            try:
                async with asyncio.timeout(self._http_timeout):
                    async with client.stream("GET", f"{base_url}/") as resp:
                        profile.http_status = resp.status_code
                        profile.http_headers = dict(resp.headers)
                        profile.http_server_header = resp.headers.get("server")

                        payload = bytearray()
                        # Read the wire representation. A hostile device can
                        # ignore Accept-Encoding: identity and advertise a tiny
                        # compressed body that expands far beyond this cap.
                        async for chunk in resp.aiter_raw(
                            chunk_size=_MAX_BODY_SIZE
                        ):
                            remaining = _MAX_BODY_SIZE - len(payload)
                            payload.extend(chunk[:remaining])
                            if len(payload) >= _MAX_BODY_SIZE:
                                break
                        if payload:
                            encoding = resp.encoding or "utf-8"
                            try:
                                profile.http_body_snippet = bytes(payload).decode(
                                    encoding,
                                    errors="replace",
                                )
                            except LookupError:
                                profile.http_body_snippet = bytes(payload).decode(
                                    "utf-8",
                                    errors="replace",
                                )
            except Exception as exc:
                logger.debug("HTTP GET / failed for %s:%d: %s", ip, port, exc)
                return

            # GET /favicon.ico
            try:
                async with asyncio.timeout(self._http_timeout):
                    async with client.stream(
                        "GET",
                        f"{base_url}/favicon.ico",
                    ) as favicon_resp:
                        content_encoding = favicon_resp.headers.get(
                            "content-encoding",
                            "",
                        ).strip().casefold()
                        if (
                            favicon_resp.status_code == 200
                            and content_encoding in ("", "identity")
                        ):
                            payload = bytearray()
                            async for chunk in favicon_resp.aiter_raw(
                                chunk_size=8192
                            ):
                                if len(payload) + len(chunk) > _MAX_FAVICON_SIZE:
                                    payload.clear()
                                    break
                                payload.extend(chunk)
                            if payload:
                                favicon_body = bytes(payload)
                                profile.favicon_body = favicon_body
                                profile.favicon_hash = hashlib.md5(
                                    favicon_body,
                                    usedforsecurity=False,
                                ).hexdigest()
            except Exception:
                pass  # favicon is optional

    async def _probe_tls(
        self, profile: ServiceProfile, ip: str, port: int,
    ) -> None:
        """TLS certificate inspection — CN, issuer, expiry."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx),
                timeout=_TLS_TIMEOUT,
            )
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    cert_der = ssl_obj.getpeercert(binary_form=True)
                    if cert_der:
                        cert = x509.load_der_x509_certificate(cert_der)
                        common_names = cert.subject.get_attributes_for_oid(
                            NameOID.COMMON_NAME
                        )
                        organizations = cert.issuer.get_attributes_for_oid(
                            NameOID.ORGANIZATION_NAME
                        )
                        issuer_names = cert.issuer.get_attributes_for_oid(
                            NameOID.COMMON_NAME
                        )
                        # cryptography permits a bytes-valued NameAttribute
                        # only for X500_UNIQUE_IDENTIFIER. These directory
                        # string OIDs are therefore always decoded strings.
                        if common_names:
                            profile.tls_cn = cast(str, common_names[0].value)
                        if organizations:
                            profile.tls_issuer = cast(str, organizations[0].value)
                        elif issuer_names:
                            profile.tls_issuer = cast(str, issuer_names[0].value)
                        profile.tls_not_after = (
                            cert.not_valid_after_utc.isoformat()
                        )
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception as exc:
            logger.debug("TLS probe failed for %s:%d: %s", ip, port, exc)

    async def _probe_protocol(
        self, profile: ServiceProfile, ip: str, port: int,
    ) -> None:
        """Protocol-specific banner/version capture (SSH, FTP, SMTP, etc.)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=_PROTO_TIMEOUT,
            )
            try:
                data = await asyncio.wait_for(reader.read(512), timeout=3.0)
                if data:
                    text = data.decode("utf-8", errors="replace").strip()
                    # Limit to first line for version string
                    first_line = text.split("\n")[0].strip()
                    if first_line:
                        profile.protocol_version = first_line[:256]
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception as exc:
            logger.debug("Protocol probe failed for %s:%d: %s", ip, port, exc)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def _persist_profile(
        self, profile: ServiceProfile, *, commit: bool = True,
    ) -> None:
        """Upsert a service profile into the database.

        Parameters
        ----------
        commit:
            When ``False``, the caller is responsible for committing.
            Used by ``scout_all()`` to batch all writes into a single commit.
        """
        headers_json = json.dumps(profile.http_headers) if profile.http_headers else None

        await self._db.execute(
            """INSERT INTO service_profiles
               (device_id, ip_address, port, protocol, service_name,
                http_status, http_headers, http_body_snippet, http_server_header,
                favicon_hash, favicon_body, tls_cn, tls_issuer, tls_not_after,
                protocol_version, scouted_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(device_id, port, protocol) DO UPDATE SET
                   ip_address = excluded.ip_address,
                   service_name = excluded.service_name,
                   http_status = excluded.http_status,
                   http_headers = excluded.http_headers,
                   http_body_snippet = excluded.http_body_snippet,
                   http_server_header = excluded.http_server_header,
                   favicon_hash = excluded.favicon_hash,
                   favicon_body = excluded.favicon_body,
                   tls_cn = excluded.tls_cn,
                   tls_issuer = excluded.tls_issuer,
                   tls_not_after = excluded.tls_not_after,
                   protocol_version = excluded.protocol_version,
                   scouted_at = excluded.scouted_at""",
            (
                profile.device_id, profile.ip_address, profile.port,
                profile.protocol, profile.service_name,
                profile.http_status, headers_json, profile.http_body_snippet,
                profile.http_server_header, profile.favicon_hash,
                profile.favicon_body,
                profile.tls_cn, profile.tls_issuer, profile.tls_not_after,
                profile.protocol_version, profile.scouted_at,
            ),
        )
        if commit:
            await self._db.commit()
