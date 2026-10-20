"""Decoy profile compiler: every attacker-visible value is a seeded draw.

The decoy engine and the corpora it draws from are public. What an install
presents is a function of a 32-byte secret (the deployment secret already used
for the Studio persona) that never leaves the encrypted secret store. Reading
the source tells an attacker the space of possibilities; it does not tell them
where this install landed.

Draws are derived directly from HKDF output per field, never from a shared
PRNG stream, so observing one value says nothing about another and there is
no generator state to recover. Every draw stays inside its corpus, because a
random-looking value is itself a tell.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from functools import cache
from importlib import resources
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from squirrelops_home_sensor.decoys import corpora

PROFILE_SCHEMA = "squirrelops.decoy-profile/1"

_MIN_SEED_BYTES = 32
_DOMAIN = b"squirrelops.decoy.v1"
_CLASSIC_TYPES = ("file_share", "dev_server", "home_assistant")

# Listing timestamps are drawn inside this window so a fresh install does not
# present files all dated the day it was deployed.
_LISTING_EPOCH = datetime(2024, 1, 1, tzinfo=UTC)
_LISTING_WINDOW_DAYS = 600


def derive_key(seed: bytes, *parts: str, length: int = 32) -> bytes:
    """HKDF-SHA256 over the seed with a length-prefixed, domain-separated info.

    Length prefixes keep ``("ab", "c")`` and ``("a", "bc")`` apart.
    """
    if len(seed) < _MIN_SEED_BYTES:
        raise ValueError(f"Decoy seed must contain at least {_MIN_SEED_BYTES} bytes")
    info = bytearray(_DOMAIN)
    for part in parts:
        encoded = part.encode("utf-8")
        info += len(encoded).to_bytes(2, "big") + encoded
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=bytes(info),
    ).derive(seed)


def _uniform(key: bytes, n: int) -> int:
    """Map a key to ``[0, n)``. 64 bits over a small ``n`` is uniform enough."""
    if n <= 0:
        raise ValueError("draw space must be positive")
    return int.from_bytes(key[:8], "big") % n


def _weighted(key: bytes, entries: list[dict[str, Any]]) -> str:
    total = sum(int(entry["weight"]) for entry in entries)
    point = _uniform(key, total)
    for entry in entries:
        point -= int(entry["weight"])
        if point < 0:
            return str(entry["version"])
    return str(entries[-1]["version"])


@cache
def _corpus(name: str) -> dict[str, Any]:
    return json.loads(resources.files(corpora).joinpath(f"{name}.json").read_text("utf-8"))


@dataclass(frozen=True)
class ListingEntry:
    name: str
    is_dir: bool
    modified: datetime
    size: int | None


@dataclass(frozen=True)
class DecoyProfile:
    """Everything a classic decoy presents, computed once from the seed."""

    decoy_type: str
    server_software: str
    server_version: str
    server_header: str | None
    framework_software: str | None
    framework_version: str | None
    hostname: str
    app_version: str
    uptime_seconds: int
    listing: tuple[ListingEntry, ...] = ()
    schema: str = field(default=PROFILE_SCHEMA)

    def to_json(self) -> str:
        data = asdict(self)
        for entry in data["listing"]:
            entry["modified"] = entry["modified"].isoformat()
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> DecoyProfile:
        data = json.loads(raw)
        if data.get("schema") != PROFILE_SCHEMA:
            raise ValueError("unsupported decoy profile schema")
        listing = tuple(
            ListingEntry(
                name=str(entry["name"]),
                is_dir=bool(entry["is_dir"]),
                modified=datetime.fromisoformat(entry["modified"]),
                size=entry["size"],
            )
            for entry in data.pop("listing", [])
        )
        return cls(listing=listing, **data)


def compile_profile(
    seed: bytes,
    *,
    decoy_type: str,
    decoy_id: int,
    password_filename: str = "passwords.txt",
) -> DecoyProfile:
    """Compile the profile for one decoy on one install.

    ``decoy_id`` is part of every derivation so two decoys of the same type on
    one install do not present the same values.
    """
    if decoy_type not in _CLASSIC_TYPES:
        raise ValueError(f"no profile compiler for decoy type {decoy_type!r}")
    scope = (decoy_type, str(int(decoy_id)))

    def key(*parts: str) -> bytes:
        return derive_key(seed, *scope, *parts)

    versions = _corpus("versions")
    app_version = ".".join(
        str(1 + _uniform(key("app_version", "major"), 3))
        if index == 0
        else str(_uniform(key("app_version", str(index)), 20))
        for index in range(3)
    )
    uptime_seconds = 60 + _uniform(key("uptime"), 90 * 86400 - 60)

    if decoy_type == "file_share":
        version = _weighted(key("server_version"), versions["nginx"])
        return DecoyProfile(
            decoy_type=decoy_type,
            server_software="nginx",
            server_version=version,
            server_header=f"nginx/{version}",
            framework_software=None,
            framework_version=None,
            hostname="",
            app_version=app_version,
            uptime_seconds=uptime_seconds,
            listing=_compile_listing(key, password_filename),
        )

    if decoy_type == "dev_server":
        return DecoyProfile(
            decoy_type=decoy_type,
            server_software="express",
            server_version=_weighted(key("server_version"), versions["express"]),
            server_header=None,
            framework_software="next",
            framework_version=_weighted(key("framework_version"), versions["next"]),
            hostname="",
            app_version=app_version,
            uptime_seconds=uptime_seconds,
        )

    hostnames = _corpus("hostnames")["home_assistant"]
    return DecoyProfile(
        decoy_type=decoy_type,
        server_software="home_assistant",
        server_version=_weighted(key("server_version"), versions["home_assistant"]),
        server_header=None,
        framework_software=None,
        framework_version=None,
        hostname=hostnames[_uniform(key("hostname"), len(hostnames))],
        app_version=app_version,
        uptime_seconds=uptime_seconds,
    )


def _compile_listing(key, password_filename: str) -> tuple[ListingEntry, ...]:
    """Draw a directory listing: the bait is always present, the rest varies."""
    listing = _corpus("listing")
    files = [name for name in listing["files"] if name != password_filename]
    directories = [name for name in listing["directories"]]

    names: list[str] = [password_filename, ".ssh/"]
    extra = 1 + _uniform(key("listing", "count"), 5)  # 3 to 7 entries in total
    pool = files + directories
    for index in range(extra):
        if not pool:
            break
        pick = pool.pop(_uniform(key("listing", "pick", str(index)), len(pool)))
        names.append(pick)

    entries: list[ListingEntry] = []
    for index, name in enumerate(names):
        is_dir = name.endswith("/")
        day = _uniform(key("listing", "day", str(index)), _LISTING_WINDOW_DAYS)
        second = _uniform(key("listing", "second", str(index)), 86400)
        modified = _LISTING_EPOCH + timedelta(days=day, seconds=second)
        size: int | None = None
        if not is_dir:
            # Log-uniform between 200 bytes and about 5 MB.
            magnitude = 200 * (2 ** _uniform(key("listing", "size", str(index)), 15))
            size = magnitude + _uniform(key("listing", "size-jitter", str(index)), magnitude)
        entries.append(ListingEntry(name=name, is_dir=is_dir, modified=modified, size=size))

    stamps = sorted(entry.modified for entry in entries)
    if (stamps[-1] - stamps[0]).days < 7:
        # Spread a tight cluster so the listing does not look generated on one day.
        entries = [
            ListingEntry(
                name=entry.name,
                is_dir=entry.is_dir,
                modified=entry.modified + timedelta(days=10 * index),
                size=entry.size,
            )
            for index, entry in enumerate(entries)
        ]
    return tuple(entries)
