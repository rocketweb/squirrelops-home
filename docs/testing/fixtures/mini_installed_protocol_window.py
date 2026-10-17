"""One attended protocol window on the installed Mini build. Never installs a package."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import signal

spec = importlib.util.spec_from_file_location("relay", Path(__file__).with_name("mini_relay_diagnostic_acceptance.py"))
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
base, upgrade, single, post = relay.base, relay.upgrade, relay.single, relay.post
require = base.require

CLEANUP = Path("/Library/SquirrelOps/acceptance-backups/mini-relay-20260930.m06dh5r3/"
               "relay-reference-cleanup-20261001.nbvt6vy_/cleanup.json")
CLEANUP_SHA = "8b2832aee1663b1b26b989c949e37a88cc215468f0b14902462adc104767142b"
CONSENT = "START INSTALLED BUILD AND TEST 240"


def validate_cleanup(receipt):
    require(receipt.get("phase") == "stopped" and receipt.get("pf_enabled") is False
            and receipt.get("test_scope") == "mini-relay-reference-cleanup-240"
            and receipt.get("boot_seconds") == post.BOOT
            and receipt.get("package_sha256") == relay.PACKAGE_SHA
            and receipt.get("reviewed_decoy_count") == 7
            and all(receipt.get(key) is True for key in (
                "own_pf_reference_released", "guest_stopped", "aliases_absent", "jobs_disabled",
                "configuration_unchanged")), "Previous cleanup is not verified")


class InstalledProtocolWindow(relay.RelayDiagnosticUpgrade):
    old_executables = relay.RelayDiagnosticUpgrade.new_executables
    receipt_time = 1790818368
    staging_prefix = "squirrelops-mini-protocol"
    backup_prefix = "mini-protocol-20261001."
    results_prefix = "squirrelops-mini-protocol-results."
    claim_prefix = "protocol"
    input_names = (*relay.RelayDiagnosticUpgrade.input_names, "mini_installed_protocol_window.py")

    def command(self, args, **kwargs):
        require(args[0] not in {"/usr/sbin/installer", "/usr/bin/install"},
                "Installer and local-test opt-in are outside the protocol-only scope")
        return super().command(args, **kwargs)

    def preflight(self):
        for directory in (CLEANUP.parent.parent.parent, CLEANUP.parent.parent, CLEANUP.parent):
            base.safe_directory(directory)
        base.safe_file(CLEANUP)
        require(base.digest(CLEANUP) == CLEANUP_SHA, "Durable cleanup receipt changed")
        validate_cleanup(json.loads(CLEANUP.read_text()))
        super().preflight()

    def confirm_scope(self):
        print("Start the installed diagnostic build once; permit one bounded laptop run. No reinstall or restart test.", flush=True)
        print("Verified backups retained. Existing discovery/auto-deployment can run; seven saved decoys are preserved.", flush=True)
        print("Only .240 is tested. No Studio, .241, Little Snitch or configuration changes.", flush=True)
        print("After tests, stop services, withdraw owned aliases, restore both disabled jobs and release only this PF reference.", flush=True)
        print(f"Type {CONSENT} to approve, or Return to stop:", flush=True)
        require(input().strip() == CONSENT, "Protocol window not approved")

    def install_package(self):
        raise RuntimeError("No package installation permitted in this window")

    def install(self):
        # Historical runner name; this override performs startup only.
        require(self.upgrade_approved and self.backup_verified, "Approval and verified backup required")
        self.validate_existing()
        self.verify_intent()
        self.check_effective_pool(single.CONFIG)
        require(self.inspect_empty_pf() == self.pf_baseline, "PF policy changed")
        self.check_conflicts()
        self.claim = self.backup.parent / f"{self.claim_prefix}-{post.BOOT}-{relay.PACKAGE_SHA[:12]}-attempt.json"
        single.private_write(self.claim, json.dumps({"backup": str(self.backup),
                                                    "package_sha256": relay.PACKAGE_SHA}).encode())
        enabled = self.command(["/sbin/pfctl", "-E"])
        self.token = base.parse_pf_token(enabled.stdout + enabled.stderr)
        single.private_write(self.backup / "pf-reference-token", (self.token + "\n").encode())
        require(re.search(r"^Status:\s+Enabled\b", self.pf(["-s", "info"]), re.M), "PF enable not verified")
        self.enable_for_install()  # Restores only the two verified disabled overrides.
        # Arm inherited teardown before the first service load, including partial startup.
        self.install_started = True
        self.publish("starting", package_sha256=relay.PACKAGE_SHA, installed_only=True)
        for job in ("com.squirrelops.helper", "com.squirrelops.sensor"):
            self.command(["/bin/launchctl", "bootstrap", "system", "/Library/LaunchDaemons/" + job + ".plist"])
        self.wait_until_ready()
        self.snapshot("after-start")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps({"mode": "plan_only", "host": "100.108.203.27", "boot_seconds": post.BOOT,
                          "package_sha256": relay.PACKAGE_SHA, "test_scope": relay.SCOPE,
                          "test_vips": [single.VIP], "installed_only": True, "install": False,
                          "restart_test": False, "configuration_edits": 0, "database_recovery": False,
                          "observe_seconds": 1200, "confirmation": CONSENT}, indent=2))
        return

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("Operator interrupted session")

    signal.signal(signal.SIGTERM, interrupted)
    InstalledProtocolWindow(args.run).run()


if __name__ == "__main__":
    main()
