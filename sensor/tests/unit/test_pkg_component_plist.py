"""macOS 27 pkgbuild omits the relocation key from its analyzed plist."""

import os
import plistlib
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(sys.platform != "darwin", reason="Uses macOS plist tools")
@pytest.mark.parametrize("existing", [None, True, False])
def test_app_component_always_disables_relocation(tmp_path, existing):
    component = {"RootRelativeBundlePath": "Applications/SquirrelOps Home.app"}
    if existing is not None:
        component["BundleIsRelocatable"] = existing
    path = tmp_path / "components.plist"
    path.write_bytes(plistlib.dumps([component]))
    script = (Path(__file__).resolve().parents[3] / "scripts/build-pkg.sh").read_text()
    command = next(line for line in script.splitlines() if
                   line.startswith("/usr/") and "BundleIsRelocatable" in line)
    result = subprocess.run(
        ["/bin/bash", "-c", command],
        env={**os.environ, "APP_COMPONENT_PLIST": str(path)},
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert plistlib.loads(path.read_bytes())[0]["BundleIsRelocatable"] is False
