"""Read-only-to-product diagnostic: isolated in-memory DB, no real listeners.

Run with the extracted package's isolated Python. The final assertion expresses
the required invariant and intentionally fails on the affected candidate.
"""
import asyncio
import errno
import json
from pathlib import Path
from unittest.mock import AsyncMock

import aiosqlite
import squirrelops_home_sensor.decoys.orchestrator as implementation


async def main():
    origin = Path(implementation.__file__).resolve()
    if "shutdown-fix-extracted-20260929" not in str(origin):
        raise RuntimeError("Use the pinned extracted package runtime, not checkout imports")
    async with aiosqlite.connect(":memory:") as db:
        db.row_factory = aiosqlite.Row
        await db.execute("""CREATE TABLE decoys (
            id INTEGER PRIMARY KEY, name TEXT, decoy_type TEXT, bind_address TEXT,
            port INTEGER, status TEXT, config TEXT, created_at TEXT, updated_at TEXT,
            failure_count INTEGER DEFAULT 0, last_failure_at TEXT
        )""")
        for number, port in enumerate((445, 22, 11434, 1234, 8765), 1):
            await db.execute("INSERT INTO decoys (id,name,decoy_type,bind_address,port,status,config) VALUES (?,?, 'deep',?,?,'active','{}')",
                             (number, "Synthetic Studio", "192.168.1.240", port))
        await db.commit()
        manager = implementation.DecoyOrchestrator(
            event_bus=AsyncMock(), db=db, max_decoys=3, bind_address="192.168.1.115")
        manager._load_credentials = AsyncMock(return_value=[])
        # The mini already owns 445, 22 and 11434. Simulate bind failure without
        # touching any port or process. The real factory still creates objects.
        manager.deploy_decoy = AsyncMock(side_effect=OSError(errno.EADDRINUSE, "Synthetic occupied native port"))
        resumed = await manager.resume_active()
        rows = [dict(row) for row in await (await db.execute(
            "SELECT id,decoy_type,bind_address,port,status FROM decoys ORDER BY id")).fetchall()]
        attempted = [{"id": call.args[0].decoy_id, "factory_type": call.args[0].decoy_type,
                      "bind_address": call.args[0].bind_address, "port": call.args[0].port}
                     for call in manager.deploy_decoy.call_args_list]
        print(json.dumps({"module": str(origin), "resumed": resumed, "attempted": attempted, "after": rows}, indent=2))
        assert all(row["status"] == "active" for row in rows), "Classic resume changed deep-host restart intent"
        assert not attempted, "Classic resume attempted to own deep services"


if __name__ == "__main__":
    asyncio.run(main())
