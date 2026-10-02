"""One SMB-only diagnostic window on the installed build; no installer or filter edits."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import signal

spec = importlib.util.spec_from_file_location("previous", Path(__file__).with_name("mini_filter_retest.py"))
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)
base, relay, post = previous.base, previous.relay, previous.post
require = previous.require
BASE = Path("/Library/SquirrelOps/acceptance-backups")
CLAIM = BASE / "protocol-filter-approved-1790777754-3d18ebac2fae-attempt.json"
CLEANUP_SHA = "23e496726d24f1e81acce52328128dfdac963d567772b8cef613c203e943ce6c"
SCOPE = "mini-smb-only-diagnostic-240"
CONSENT = "START ONE SMB DIAGNOSTIC"


def backup_from_claim(claim):
    require(isinstance(claim, dict) and claim.get("package_sha256") == relay.PACKAGE_SHA
            and isinstance(claim.get("backup"), str), "Wrong prior claim")
    path = Path(claim["backup"])
    require(path.parent == BASE and re.fullmatch(r"mini-filter-retest-20261001\.[A-Za-z0-9_-]+", path.name),
            "Wrong prior backup")
    return path


class SMBDiagnostic(previous.FilterRetest):
    staging_prefix = "squirrelops-mini-smb"
    backup_prefix = "mini-smb-20261001."
    results_prefix = "squirrelops-mini-smb-results."
    claim_prefix = "protocol-smb-diagnostic"
    input_names = (*previous.FilterRetest.input_names, "mini_smb_diagnostic_window.py")

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
        previous.validate_cleanup(json.loads(receipt.read_text()))
        relay.RelayDiagnosticUpgrade.preflight(self)

    def publish(self, phase, **fields):
        super().publish(phase, diagnostic_scope=SCOPE, **fields)

    def confirm_scope(self):
        print("One SMB-only diagnostic of the installed build. No installer, restart test, or filter changes.", flush=True)
        print("One anonymous laptop share-listing client, up to 45 seconds; no credentials or file operations.", flush=True)
        print("Both apps stay closed. Preserve seven decoys, .240-only configuration, native services and backups.", flush=True)
        print("Existing discovery/auto-deployment may run. No Studio or .241 tests.", flush=True)
        print("Leave new Little Snitch prompts unanswered. This script never renews or broadens a rule.", flush=True)
        print("After the client, Return stops services, withdraws aliases and releases only this run's PF reference.", flush=True)
        print(f"Type {CONSENT} to start, or Return to stop:", flush=True)
        require(input().strip() == CONSENT, "SMB diagnostic not confirmed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps(dict(mode="plan_only", diagnostic_scope=SCOPE, host="100.108.203.27",
                              installed_only=True, install=False, third_party_filter_changes=False,
                              observe_seconds=1200, client_max_seconds=45, confirmation=CONSENT)))
        return

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("Operator interrupted session")

    signal.signal(signal.SIGTERM, interrupted)
    SMBDiagnostic(args.run).run()


if __name__ == "__main__":
    main()
