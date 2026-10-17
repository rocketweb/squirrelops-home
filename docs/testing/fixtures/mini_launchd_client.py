"""Same bounded client, pinned only to the launchd-budget candidate."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("client", Path(__file__).with_name("mini_upgrade_client.py"))
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
client.PACKAGE_SHA = "3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c"

if __name__ == "__main__":
    raise SystemExit(client.main())
