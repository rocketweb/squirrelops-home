"""Helpers for keeping system-created decoys out of device inventory."""

from __future__ import annotations

import aiosqlite

DECOY_DEVICE_FILTER = """NOT EXISTS (
    SELECT 1 FROM decoys dx
    WHERE dx.decoy_type = 'mimic'
      AND dx.bind_address = d.ip_address
)
AND NOT EXISTS (
    SELECT 1 FROM virtual_ips vip
    WHERE vip.ip_address = d.ip_address
      AND vip.released_at IS NULL
)"""


async def is_decoy_device_ip(db: aiosqlite.Connection, ip_address: str) -> bool:
    """Return true when an IP belongs to a system-created virtual decoy."""
    cursor = await db.execute(
        """SELECT 1
           FROM decoys
           WHERE decoy_type = 'mimic'
             AND bind_address = ?
           LIMIT 1""",
        (ip_address,),
    )
    if await cursor.fetchone() is not None:
        return True

    cursor = await db.execute(
        """SELECT 1
           FROM virtual_ips
           WHERE ip_address = ?
             AND released_at IS NULL
           LIMIT 1""",
        (ip_address,),
    )
    return await cursor.fetchone() is not None
