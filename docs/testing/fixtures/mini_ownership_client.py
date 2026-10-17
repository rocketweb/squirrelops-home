"""Use the bounded existing client only with ownership-fix readiness evidence."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("ownership_client_base", Path(__file__).with_name("mini_upgrade_client.py"))
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
client.PACKAGE_SHA = "2d5f4d287ca3ce971fd201f539d27a9272431f160a5a5debddc8d1b0b4dc7c82"

if __name__ == "__main__":
    raise SystemExit(client.main())
