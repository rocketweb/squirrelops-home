"""Pinned resolver upgrade and one restart/LAN window. Plan-only by default."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import signal

spec = importlib.util.spec_from_file_location("relay", Path(__file__).with_name("mini_relay_diagnostic_acceptance.py"))
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
base, upgrade, post = relay.base, relay.upgrade, relay.post
require = base.require
PREVIOUS_PACKAGE_SHA = relay.PACKAGE_SHA
PACKAGE_SHA = "47774088cd9eadc5aaddf38949e00a8b8f6eeb56c2192a5a72830d06d84a8aec"
SCOPE = "mini-guest-resolver-240"
CONSENT = "INSTALL RESOLVER FIX AND TEST 240"
BASE = Path("/Library/SquirrelOps/acceptance-backups")
CLAIM = BASE / "protocol-smb-diagnostic-1790777754-3d18ebac2fae-attempt.json"
CLEANUP_SHA = "4cd666f50c23dd87fda61f04e41f9aa41d42c2f176e959e682f6719a1dc1e286"
BUNDLE = base.APP / "Contents/Resources/DeceptionGuest"
OLD_MANIFEST_SHA = "a8bf96c81c1eb25b63a6a9316044032b4842457ff472b0199da5aeb22ed77b2b"
NEW_MANIFEST_SHA = "cdbb8bcb53f4d3fc8c04703c7c5fce6b9903a38b263b8290a0fb7ba608b8e13f"

# This is a private module instance. Historical runners and their pins stay intact.
relay.PACKAGE_SHA = PACKAGE_SHA
relay.SCOPE = SCOPE


def backup_from_claim(claim):
    require(isinstance(claim, dict) and claim.get("package_sha256") == PREVIOUS_PACKAGE_SHA
            and isinstance(claim.get("backup"), str), "Wrong prior claim")
    path = Path(claim["backup"])
    require(path.parent == BASE and re.fullmatch(r"mini-smb-20261001\.[A-Za-z0-9_-]+", path.name),
            "Wrong prior backup")
    return path


def validate_cleanup(receipt):
    require(isinstance(receipt, dict) and receipt.get("phase") == "stopped"
            and receipt.get("test_scope") == "mini-relay-diagnostics-240"
            and receipt.get("diagnostic_scope") == "mini-smb-only-diagnostic-240"
            and receipt.get("test_vips") == ["192.168.1.240"]
            and receipt.get("boot_seconds") == post.BOOT and receipt.get("pf_enabled") is False
            and all(receipt.get(key) is True for key in (
                "configuration_unchanged", "config_change_verified", "installation_retained",
                "test_data_retained", "aliases_absent", "guest_stopped",
                "original_listener_endpoints_present", "own_pf_reference_released")),
            "Previous SMB cleanup is not verified")


def verify_bundle(expected_manifest):
    # Loaded only from the checksum-pinned private packaged interpreter.
    # The production validator streams hashes with separate kernel/initramfs bounds.
    from squirrelops_home_sensor.decoys.deep.guest_bundle import load_guest_bundle
    post.check_payload(BUNDLE / "manifest.json", expected_manifest)
    load_guest_bundle(BUNDLE, trusted_uids={0})


class ResolverUpgrade(relay.RelayDiagnosticUpgrade):
    package_sha = PACKAGE_SHA
    old_executables = {**relay.RelayDiagnosticUpgrade.new_executables,
                       BUNDLE / "manifest.json": OLD_MANIFEST_SHA}
    new_executables = {
        **relay.RelayDiagnosticUpgrade.new_executables,
        base.APP / "Contents/MacOS/SquirrelOpsHome":
            "132ccbe57823481da159e15b2bf0a0140994bb911c3d659a0c815515855d7efe",
        BUNDLE / "manifest.json": NEW_MANIFEST_SHA,
    }
    receipt_time = 1790818368
    staging_prefix = "squirrelops-mini-resolver"
    backup_prefix = "mini-resolver-20261001."
    results_prefix = "squirrelops-mini-resolver-results."
    input_names = (*relay.RelayDiagnosticUpgrade.input_names, "mini_resolver_acceptance.py")

    def preflight(self):
        for path in (BASE.parent, BASE):
            base.safe_directory(path)
        base.safe_file(CLAIM)
        require(CLAIM.stat().st_size <= 65536, "Oversized prior claim")
        backup = backup_from_claim(json.loads(CLAIM.read_text()))
        base.safe_directory(backup)
        receipt = backup / "cleanup.json"
        base.safe_file(receipt)
        require(base.digest(receipt) == CLEANUP_SHA, "Previous cleanup receipt changed")
        validate_cleanup(json.loads(receipt.read_text()))
        super().preflight()

    def validate_existing(self):
        super().validate_existing()
        verify_bundle(OLD_MANIFEST_SHA)

    def wait_until_ready(self):
        verify_bundle(NEW_MANIFEST_SHA)
        super().wait_until_ready()

    def confirm_scope(self):
        print("Install the pinned resolver fix, test one normal restart, then one bounded laptop protocol run.", flush=True)
        print("Verified private backups retained. Preserve seven decoys and .240-only configuration; no SQL edits.", flush=True)
        print("Existing discovery/auto-deployment may run; new host listeners are retained and reported.", flush=True)
        print("Both apps stay closed. No Studio, .241 or Little Snitch changes. Leave new prompts unanswered.", flush=True)
        print("Confirm the existing guest-only incoming rule from 192.168.1.7 is still active; this script does not change it.", flush=True)
        print("After one client run, Return stops services, removes aliases, restores disabled jobs and releases only our PF reference.", flush=True)
        print("The new installation and data remain. Failure retains evidence; no automatic downgrade or force-kill.", flush=True)
        print(f"Type {CONSENT} to approve, or Return to stop:", flush=True)
        require(input().strip() == CONSENT, "Resolver upgrade not approved")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps(dict(mode="plan_only", host="100.108.203.27", boot_seconds=post.BOOT,
                              package_sha256=PACKAGE_SHA, test_scope=SCOPE, test_vips=["192.168.1.240"],
                              configuration_edits=0, database_recovery=False, normal_restart=True,
                              restore_disabled_jobs=True, third_party_filter_rule_changes=False,
                              confirmation=CONSENT), indent=2))
        return

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("Operator interrupted session")

    signal.signal(signal.SIGTERM, interrupted)
    ResolverUpgrade(args.run).run()


if __name__ == "__main__":
    main()
