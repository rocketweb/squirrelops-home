"""Run the ownership contract in either the editable or extracted sensor runtime."""

import os
import subprocess
import sys
import textwrap
from pathlib import Path


def test_restart_preserves_guest_rows_in_selected_runtime(tmp_path):
    # No pytest dependency in the packaged interpreter, no network or helper.
    # -I prevents the source checkout/PYTHONPATH from masking stale payloads.
    program = textwrap.dedent("""
        import asyncio
        import sys
        from unittest.mock import AsyncMock
        import aiosqlite
        import squirrelops_home_sensor.decoys.orchestrator as classic
        from squirrelops_home_sensor.db.migrations import apply_migrations

        print("SENSOR_MODULE=" + classic.__file__, flush=True)

        async def snapshot(db):
            cursor = await db.execute("SELECT * FROM decoys ORDER BY id")
            return [tuple(row) for row in await cursor.fetchall()]

        async def main():
            async with aiosqlite.connect(sys.argv[1]) as db:
                db.row_factory = aiosqlite.Row
                await apply_migrations(db)
                for port in (445, 22, 11434, 1234, 8765):
                    await db.execute(
                        "INSERT INTO decoys (name, decoy_type, bind_address, port, "
                        "status, created_at, updated_at) VALUES "
                        "('Studio', 'deep', '192.0.2.240', ?, 'active', 'before', 'before')",
                        (port,),
                    )
                await db.commit()
                before = await snapshot(db)

            # Repeat the upgrade/startup sequence, then an ordinary restart.
            for attempt in range(2):
                async with aiosqlite.connect(sys.argv[1]) as db:
                    db.row_factory = aiosqlite.Row
                    await apply_migrations(db)
                    manager = classic.DecoyOrchestrator(
                        db=db, event_bus=AsyncMock(), max_decoys=3,
                        bind_address="192.0.2.115",
                    )
                    manager.deploy_decoy = AsyncMock(side_effect=OSError("native port occupied"))
                    assert await manager.resume_active() == 0
                    assert await snapshot(db) == before, "Guest state changed during classic startup"
                    manager.deploy_decoy.assert_not_awaited()
                    await manager.stop_all()
            print("RESTART_OWNERSHIP_PASSED", flush=True)

        asyncio.run(main())
    """)
    interpreter = os.environ.get("SQUIRRELOPS_TEST_SENSOR_PYTHON", sys.executable)
    result = subprocess.run(
        [interpreter, "-I", "-c", program, str(tmp_path / "persisted.db")],
        capture_output=True, text=True, timeout=30,
    )
    if "SQUIRRELOPS_TEST_SENSOR_PYTHON" in os.environ:
        module = next(line.removeprefix("SENSOR_MODULE=") for line in result.stdout.splitlines()
                      if line.startswith("SENSOR_MODULE="))
        assert Path(module).resolve().is_relative_to(Path(interpreter).resolve().parent.parent)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESTART_OWNERSHIP_PASSED" in result.stdout
