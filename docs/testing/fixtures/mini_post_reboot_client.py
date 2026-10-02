"""Bounded laptop probes for the reviewed .240-only post-reboot mini session."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("client", Path(__file__).with_name("mini_upgrade_client.py"))
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
client.PACKAGE_SHA = "3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c"
client.VIPS = {"192.168.1.240"}
validate_original = client.validate_inputs


def validate_inputs(endpoints, login, status, now):
    client.require(status.get("test_scope") == "mini-post-reboot-240"
                   and status.get("test_vips") == ["192.168.1.240"]
                   and status.get("boot_seconds") == 1790777754
                   and status.get("config_change_verified") is True,
                   "Wrong post-reboot server scope, boot, or configuration")
    return validate_original(endpoints, login, status, now)


client.validate_inputs = validate_inputs

if __name__ == "__main__":
    raise SystemExit(client.main())
