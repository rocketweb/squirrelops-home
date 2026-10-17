"""One approved retest after the operator's narrow temporary guest rule. No installer."""
import argparse
import importlib.util
import json
from pathlib import Path
import signal

spec = importlib.util.spec_from_file_location("window", Path(__file__).with_name("mini_installed_protocol_window.py"))
window = importlib.util.module_from_spec(spec)
spec.loader.exec_module(window)
base, relay, post = window.base, window.relay, window.post
require = window.require

CLEANUP = Path("/Library/SquirrelOps/acceptance-backups/mini-protocol-20261001.1px9by6q/cleanup.json")
CLEANUP_SHA = "796977f62c6f4e67bf1350c7f2094ebce8325a5f01b75583ea6f9343f523d7c0"
CONSENT = "START APPROVED FILTER RETEST"


def validate_cleanup(receipt):
    require(receipt.get("phase") == "stopped" and receipt.get("pf_enabled") is False
            and receipt.get("test_scope") == relay.SCOPE
            and receipt.get("test_vips") == ["192.168.1.240"]
            and receipt.get("boot_seconds") == post.BOOT
            and all(receipt.get(key) is True for key in (
                "configuration_unchanged", "config_change_verified", "installation_retained",
                "test_data_retained", "aliases_absent", "guest_stopped",
                "original_listener_endpoints_present", "own_pf_reference_released")),
            "Previous protocol cleanup is not verified")


class FilterRetest(window.InstalledProtocolWindow):
    staging_prefix = "squirrelops-mini-filter-retest"
    backup_prefix = "mini-filter-retest-20261001."
    results_prefix = "squirrelops-mini-filter-retest-results."
    claim_prefix = "protocol-filter-approved"
    input_names = (*window.InstalledProtocolWindow.input_names, "mini_filter_retest.py")

    def preflight(self):
        for parent in (CLEANUP.parent.parent.parent, CLEANUP.parent.parent, CLEANUP.parent):
            base.safe_directory(parent)
        base.safe_file(CLEANUP)
        require(base.digest(CLEANUP) == CLEANUP_SHA, "Durable protocol cleanup receipt changed")
        validate_cleanup(json.loads(CLEANUP.read_text()))
        # This run replaces the ancestor's older cleanup receipt, not its host
        # checks. Invoke the actual base class through this verified hierarchy.
        relay.RelayDiagnosticUpgrade.preflight(self)

    def confirm_scope(self):
        print("One approved retest of the installed build. No reinstall or restart test.", flush=True)
        print("Confirm your 30-minute rule is active: this guest executable, incoming TCP from 192.168.1.7 only.", flush=True)
        print("No Little Snitch changes are made by this script. Do not broaden or make the allowance permanent.", flush=True)
        print("Fresh private backups preserve all seven saved decoys. Existing classic auto-deployment may run.", flush=True)
        print("Only .240 is tested. No Studio, .241, configuration or SQL changes.", flush=True)
        print("After one laptop run, press Return: stop services, withdraw aliases, restore disabled jobs, release only our PF reference.", flush=True)
        print(f"Type {CONSENT} to start, or Return to stop:", flush=True)
        require(input().strip() == CONSENT, "Filter retest not confirmed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps(dict(mode="plan_only", host="100.108.203.27", boot_seconds=post.BOOT,
                              package_sha256=relay.PACKAGE_SHA, test_scope=relay.SCOPE,
                              test_vips=["192.168.1.240"], installed_only=True, install=False,
                              restart_test=False, third_party_filter_changes=False,
                              observe_seconds=1200, confirmation=CONSENT), indent=2))
        return

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("Operator interrupted session")

    signal.signal(signal.SIGTERM, interrupted)
    FilterRetest(args.run).run()


if __name__ == "__main__":
    main()
