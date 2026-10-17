"""Only future-load disablement is authorized before the attended reboot."""
import importlib.util
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("hold", Path(__file__).with_name("mini_maintenance_hold.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MaintenanceHoldTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.session = m.MaintenanceHold(self.root)

    def prepared(self):
        s = self.session
        s.revalidate = Mock()
        s.hold_state = Mock(return_value=dict.fromkeys(m.recovery.upgrade.JOBS, True))
        s.command = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        return s

    def test_shared_backup_does_not_run_failed_native_probe(self):
        s = self.session
        with patch.object(m.recovery.Recovery, "backup_preflight") as backup, \
                patch.object(m.recovery, "native_probe") as probe, \
                patch.object(s, "record_baseline") as record:
            s.preflight()
        backup.assert_called_once_with()
        record.assert_called_once_with()
        probe.assert_not_called()

    def test_failed_backup_cannot_reach_disable(self):
        s = self.session
        with patch.object(m.recovery.Recovery, "backup_preflight", side_effect=RuntimeError("backup failed")), \
                patch.object(s, "hold_for_reboot") as hold, self.assertRaises(SystemExit):
            s.run_hold()
        hold.assert_not_called()
        self.assertFalse(s.mutation_started)

    def test_only_two_exact_disables_and_pending_receipt(self):
        s = self.prepared()
        s.hold_for_reboot()
        self.assertEqual([call.args[0] for call in s.command.call_args_list], [
            ["/bin/launchctl", "disable", "system/" + job] for job in m.recovery.upgrade.JOBS])
        self.assertEqual(s.revalidate.call_args_list[0].kwargs, {"held": False})
        self.assertEqual(s.revalidate.call_args_list[-1].kwargs, {"held": True})
        receipt = json.loads((self.root / "pending-reboot.json").read_text())
        self.assertEqual(receipt["phase"], "disabled_pending_attended_reboot")
        self.assertFalse(receipt["stopped_state_verified"])
        self.assertFalse((self.root / "held-stopped.json").exists())

    def test_disable_failure_stops_without_success_or_inverse(self):
        s = self.prepared()
        s.command.side_effect = RuntimeError("disable failed")
        with self.assertRaisesRegex(RuntimeError, "disable failed"):
            s.hold_for_reboot()
        self.assertTrue(s.mutation_started)
        self.assertEqual(s.command.call_count, 1)
        self.assertFalse((self.root / "pending-reboot.json").exists())

    def test_unverified_disable_stops_without_success(self):
        s = self.prepared()
        s.hold_state.return_value = dict.fromkeys(m.recovery.upgrade.JOBS, False)
        with self.assertRaisesRegex(RuntimeError, "not verified"):
            s.hold_for_reboot()
        self.assertFalse((self.root / "pending-reboot.json").exists())

    def test_drift_before_disables_does_not_mutate(self):
        s = self.prepared()
        s.revalidate.side_effect = RuntimeError("baseline drift")
        with self.assertRaisesRegex(RuntimeError, "baseline drift"):
            s.hold_for_reboot()
        s.command.assert_not_called()
        self.assertFalse(s.mutation_started)

    def test_drift_after_disables_does_not_claim_stopped(self):
        s = self.prepared()
        s.revalidate.side_effect = [None, RuntimeError("runtime drift")]
        with self.assertRaisesRegex(RuntimeError, "runtime drift"):
            s.hold_for_reboot()
        self.assertEqual(s.command.call_count, 2)
        self.assertFalse((self.root / "pending-reboot.json").exists())

    def test_plan_mode_never_runs_host_operations(self):
        with patch.object(m, "MaintenanceHold") as hold, patch("sys.argv", ["hold"]):
            m.main()
        hold.assert_not_called()

    def test_bootstrap_pins_every_input_and_uses_new_entrypoint(self):
        directory = Path(__file__).parent
        bootstrap = (directory / "prepare-mini-maintenance-reboot.sh").read_text()
        paths = {name: directory / name for name in (
            "mini_acceptance.py", "mini_upgrade_acceptance.py", "mini_ownership_acceptance.py",
            "mini_launchd_acceptance.py", "mini_reboot_recovery.py", "mini_maintenance_hold.py")}
        paths["approved-scope.md"] = directory.parent / "2026-09-30-mini-maintenance-reboot-scope.md"
        for name, path in paths.items():
            self.assertIn(f"verify_digest {name} {hashlib.sha256(path.read_bytes()).hexdigest()}", bootstrap)
        self.assertIn('"$task_dir/mini_maintenance_hold.py" --run "$task_dir"', bootstrap)
        self.assertNotIn('"$task_dir/mini_reboot_recovery.py" --run', bootstrap)

    def actual_validation(self):
        s = self.session
        s.sensor_pid, s.helper_pid = 887, 888
        s.original_rows = {887: {"uid": 309, "parent": 1, "executable": str(m.recovery.RUNTIME)},
                           888: {"uid": 0, "parent": 1, "executable": str(m.recovery.base.HELPER)}}
        s.config_digest = hashlib.sha256(b"config").hexdigest()
        s.plist_digests = dict.fromkeys(m.JOBS, hashlib.sha256(b"plist").hexdigest())
        s.ledger_bytes = b"ledger"
        s.policy, s.references = {"guard": "present"}, "private"
        s.assert_boot = Mock()
        s.hold_state = Mock(return_value=dict.fromkeys(m.JOBS, False))
        s.rows = Mock(return_value=s.original_rows)
        s.job = Mock(side_effect=lambda job: f"system/{job} = {{\n\tpid = {887 if job == m.JOBS[0] else 888}\n}}")
        s.owned = Mock(return_value=["192.168.1.240"])
        s.inventory_policy = Mock(return_value=s.policy)
        s.pf_enabled = Mock(return_value=True)
        s.pf = Mock(return_value=s.references)
        def checked(path, *args):
            if path.name == "config.yaml":
                return b"config"
            if path.suffix == ".plist":
                return b"plist"
            return b"ledger"
        self.bytes_patch = patch.object(m.recovery, "checked_bytes", side_effect=checked)
        self.bytes_patch.start()
        self.addCleanup(self.bytes_patch.stop)
        return s

    def test_actual_revalidation_checks_expected_override_state(self):
        s = self.actual_validation()
        s.revalidate(held=False)
        with self.assertRaisesRegex(RuntimeError, "override drift"):
            s.revalidate(held=True)
        s.hold_state.return_value = dict.fromkeys(m.JOBS, True)
        s.revalidate(held=True)

    def test_actual_revalidation_rejects_runtime_drift(self):
        s = self.actual_validation()
        s.rows.return_value = {}
        with self.assertRaisesRegex(RuntimeError, "Runtime drift"):
            s.revalidate(held=False)

    def test_actual_revalidation_rejects_configuration_drift(self):
        s = self.actual_validation()
        s.config_digest = "changed"
        with self.assertRaisesRegex(RuntimeError, "Config drift"):
            s.revalidate(held=False)

    def test_actual_revalidation_rejects_pf_drift(self):
        s = self.actual_validation()
        s.pf.return_value = "changed"
        with self.assertRaisesRegex(RuntimeError, "PF state drift"):
            s.revalidate(held=False)


if __name__ == "__main__":
    unittest.main()
