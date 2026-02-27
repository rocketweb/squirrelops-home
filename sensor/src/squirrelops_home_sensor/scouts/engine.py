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
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import aiosqlite
import httpx

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
_HTTP_TIMEOUT = 5.0
_PROTO_TIMEOUT = 5.0
_TLS_TIMEOUT = 5.0


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
    ) -> None:
        self._db = db
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._http_timeout = http_timeout

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
        """Scout all devices with open ports.

        Parameters
        ----------
        device_ports:
            Mapping of ``(device_id, ip_address)`` to list of open port numbers.

        Returns count of profiles created/updated.
        """
        count = 0
        all_tasks = []
        for (device_id, ip), ports in device_ports.items():
            for port in ports:
                all_tasks.append(self._scout_port(device_id, ip, port))

        results = await asyncio.gather(*all_tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, ServiceProfile):
                await self._persist_profile(r)
                count += 1
            elif isinstance(r, Exception):
                logger.debug("Scout probe failed: %s", r)
        return count

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
                tls_cn=row["tls_cn"],
                tls_issuer=row["tls_issuer"],
                tls_not_after=row["tls_not_after"],
                protocol_version=row["protocol_version"],
                scouted_at=row["scouted_at"],
            ))
        return profiles

    async def get_mimic_candidates(self, count: int = 10) -> list[ServiceProfile]:
        """Return profiles that are good candidates for mimic decoys.

        Prioritizes profiles with rich HTTP data from smart_home/IoT devices.
        """
        cursor = await self._db.execute(
            """SELECT sp.*, d.device_type
               FROM service_profiles sp
               JOIN devices d ON d.id = sp.device_id
               WHERE sp.http_status IS NOT NULL
               ORDER BY
                   CASE d.device_type
                       WHEN 'smart_home' THEN 0
                       WHEN 'camera' THEN 1
                       WHEN 'media' THEN 2
                       WHEN 'printer' THEN 3
                       ELSE 4
                   END,
                   sp.port
               LIMIT ?""",
            (count,),
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
            now = datetime.now(timezone.utc).isoformat()
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

            tasks = []
            if is_http:
                tasks.append(("http", self._probe_http(profile, ip, port, use_tls=is_tls)))
            if is_tls:
                tasks.append(("tls", self._probe_tls(profile, ip, port)))
            if is_proto and not is_http:
                tasks.append(("proto", self._probe_protocol(profile, ip, port)))

            # If no specific probe, try a generic banner read
            if not tasks:
                tasks.append(("proto", self._probe_protocol(profile, ip, port)))

            for name, task in tasks:
                try:
                    await task
                except Exception as exc:
                    logger.debug("Probe %s failed for %s:%d: %s", name, ip, port, exc)

            return profile

    async def _probe_http(
        self, profile: ServiceProfile, ip: str, port: int, use_tls: bool = False,
    ) -> None:
        """Full HTTP GET probe — captures status, headers, body snippet, favicon."""
        scheme = "https" if use_tls else "http"
        base_url = f"{scheme}://{ip}:{port}"

        async with httpx.AsyncClient(
            timeout=self._http_timeout,
            verify=False,
            follow_redirects=True,
            max_redirects=2,
            headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
        ) as client:
            # GET /
            try:
                resp = await client.get(f"{base_url}/")
                profile.http_status = resp.status_code
                profile.http_headers = dict(resp.headers)
                profile.http_server_header = resp.headers.get("server")
                body = resp.text[:_MAX_BODY_SIZE] if resp.text else None
                profile.http_body_snippet = body
            except Exception as exc:
                logger.debug("HTTP GET / failed for %s:%d: %s", ip, port, exc)
                return

            # GET /favicon.ico
            try:
                favicon_resp = await client.get(f"{base_url}/favicon.ico")
                if favicon_resp.status_code == 200 and len(favicon_resp.content) > 0:
                    profile.favicon_hash = hashlib.md5(favicon_resp.content).hexdigest()
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
                    cert = ssl_obj.getpeercert(binary_form=False)
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", ()))
                        issuer = dict(x[0] for x in cert.get("issuer", ()))
                        profile.tls_cn = subject.get("commonName")
                        profile.tls_issuer = issuer.get("organizationName")
                        profile.tls_not_after = cert.get("notAfter")
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

    async def _persist_profile(self, profile: ServiceProfile) -> None:
        """Upsert a service profile into the database."""
        headers_json = json.dumps(profile.http_headers) if profile.http_headers else None

        await self._db.execute(
            """INSERT INTO service_profiles
               (device_id, ip_address, port, protocol, service_name,
                http_status, http_headers, http_body_snippet, http_server_header,
                favicon_hash, tls_cn, tls_issuer, tls_not_after,
                protocol_version, scouted_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(device_id, port, protocol) DO UPDATE SET
                   ip_address = excluded.ip_address,
                   service_name = COALESCE(excluded.service_name, service_profiles.service_name),
                   http_status = COALESCE(excluded.http_status, service_profiles.http_status),
                   http_headers = COALESCE(excluded.http_headers, service_profiles.http_headers),
                   http_body_snippet = COALESCE(excluded.http_body_snippet, service_profiles.http_body_snippet),
                   http_server_header = COALESCE(excluded.http_server_header, service_profiles.http_server_header),
                   favicon_hash = COALESCE(excluded.favicon_hash, service_profiles.favicon_hash),
                   tls_cn = COALESCE(excluded.tls_cn, service_profiles.tls_cn),
                   tls_issuer = COALESCE(excluded.tls_issuer, service_profiles.tls_issuer),
                   tls_not_after = COALESCE(excluded.tls_not_after, service_profiles.tls_not_after),
                   protocol_version = COALESCE(excluded.protocol_version, service_profiles.protocol_version),
                   scouted_at = excluded.scouted_at""",
            (
                profile.device_id, profile.ip_address, profile.port,
                profile.protocol, profile.service_name,
                profile.http_status, headers_json, profile.http_body_snippet,
                profile.http_server_header, profile.favicon_hash,
                profile.tls_cn, profile.tls_issuer, profile.tls_not_after,
                profile.protocol_version, profile.scouted_at,
            ),
        )
        await self._db.commit()
