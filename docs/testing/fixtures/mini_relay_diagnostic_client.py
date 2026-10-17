"""One laptop protocol attempt for the exact diagnostic package and Mini boot."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("client", Path(__file__).with_name("mini_upgrade_client.py"))
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
client.PACKAGE_SHA = "3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea"
client.VIPS = {"192.168.1.240"}
validate_original = client.validate_inputs


def validate_inputs(endpoints, login, status, now):
    client.require(status.get("test_scope") == "mini-relay-diagnostics-240"
                   and status.get("test_vips") == ["192.168.1.240"]
                   and status.get("boot_seconds") == 1790777754
                   and status.get("configuration_unchanged") is True
                   and status.get("config_change_verified") is True,
                   "Wrong diagnostic server scope, boot or configuration")
    ip = validate_original(endpoints, login, status, now)
    client.require(len(endpoints["mappings"]) == 5
                   and {row["port"] for row in endpoints["mappings"]} == {22, 445, 1234, 11434, 8765}
                   and len({row["backend"] for row in endpoints["mappings"]}) == 5,
                   "Only five exact diagnostic mappings are approved")
    return ip


client.validate_inputs = validate_inputs

if __name__ == "__main__":
    raise SystemExit(client.main())
