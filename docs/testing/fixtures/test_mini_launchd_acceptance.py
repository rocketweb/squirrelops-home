"""Local continuation guards; no privileged operations or installed files."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("launchd_acceptance", Path(__file__).with_name("mini_launchd_acceptance.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LaunchdAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.session = module.LaunchdUpgrade(self.root)
        self.rows = [{"id": ident, "port": port, "status": "active", "decoy_type": "deep",
                      "bind_address": "192.168.1.240", "retired_at": None, "host_id": 7,
                      "is_primary": ident == 1} for ident, port in module.ownership.EXPECTED.items()]
        self.intent = [(row["id"], "deep", "192.168.1.240", row["port"], "active") for row in self.rows]
        self.intent += [(6, "dev_server", "192.168.1.115", 60556, "active")]

    def test_active_rows_only_no_second_recovery(self):
        module.validate_active_rows(self.rows)
        for field, value in (("status", "stopped"), ("id", 99), ("port", 99), ("bind_address", "192.168.1.115"),
                             ("retired_at", "today"), ("decoy_type", "mimic"), ("host_id", 99), ("is_primary", False)):
            rows = copy.deepcopy(self.rows)
            rows[0][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                module.validate_active_rows(rows)
        for rows in (self.rows[:-1], self.rows + [self.rows[0]]):
            with self.assertRaises(RuntimeError):
                module.validate_active_rows(rows)

    def test_shutdown_plist_exact_finite_budget_and_identity(self):
        good = {"Label": "com.squirrelops.sensor", "UserName": "_squirrelops", "ExitTimeOut": 60}
        module.validate_shutdown_plist(good)
        for key, value in (("ExitTimeOut", None), ("ExitTimeOut", 0), ("ExitTimeOut", 5), ("ExitTimeOut", "60"),
                           ("ExitTimeOut", 60.0), ("Label", "other"), ("UserName", "root")):
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                module.validate_shutdown_plist({**good, key: value})

    def test_prepare_is_read_only_and_preserves_restored_rows(self):
        session = self.session
        session.upgrade_approved = session.backup_verified = True
        session.backup = self.root
        session.original_rows, session.original_intent = self.rows, self.intent
        with patch.object(session, "checked_rows", return_value=self.rows), \
                patch.object(session, "read_intent", return_value=self.intent), \
                patch.object(module.ownership, "restore_five") as restore, \
                patch.object(module.ownership.sqlite3, "connect") as connect:
            session.prepare_upgrade()
        restore.assert_not_called()
        connect.assert_not_called()

    def test_prepare_requires_approval_and_verified_backup(self):
        for approved, backup in ((False, True), (True, False)):
            self.session.upgrade_approved, self.session.backup_verified = approved, backup
            self.session.backup = self.root
            with self.subTest(approved=approved), patch.object(self.session, "checked_rows") as checked, self.assertRaises(RuntimeError):
                self.session.prepare_upgrade()
            checked.assert_not_called()

    def test_prepare_rejects_drift_since_preview(self):
        self.session.upgrade_approved = self.session.backup_verified = True
        self.session.backup = self.root
        self.session.original_rows = self.rows
        with patch.object(self.session, "checked_rows", return_value=[]), self.assertRaisesRegex(RuntimeError, "changed after preview"):
            self.session.prepare_upgrade()

    def test_classic_intent_damage_is_not_hidden_by_healthy_studio(self):
        self.session.original_intent = self.intent
        changed = self.intent[:-1] + [(*self.intent[-1][:-1], "stopped")]
        with patch.object(self.session, "read_intent", return_value=changed), self.assertRaisesRegex(RuntimeError, "Persisted decoy"):
            self.session.verify_intent()

    def test_sensor_exit_after_45_seconds_still_passes(self):
        with patch.object(self.session, "service_loaded", side_effect=[True, True, False]), \
                patch.object(self.session, "command") as command, patch.object(module.time, "sleep"), \
                patch.object(module.time, "monotonic", side_effect=[0, 46, 65]):
            self.session.stop_job("com.squirrelops.sensor")
        command.assert_called_once_with(["/bin/launchctl", "bootout", "system/com.squirrelops.sensor"], check=False, timeout=90)

    def test_sensor_stuck_after_70_fails_closed(self):
        with patch.object(self.session, "service_loaded", return_value=True), patch.object(self.session, "command"), \
                patch.object(module.time, "monotonic", side_effect=[0, 71]), self.assertRaisesRegex(RuntimeError, "retain protection"):
            self.session.stop_job("com.squirrelops.sensor")

    def test_absent_job_does_not_bootout_and_unknown_label_is_rejected(self):
        with patch.object(self.session, "service_loaded", return_value=False), patch.object(self.session, "command") as command:
            self.session.stop_job("com.squirrelops.sensor")
        command.assert_not_called()
        with patch.object(self.session, "command") as command, self.assertRaisesRegex(RuntimeError, "Unexpected stop"):
            self.session.stop_job("com.apple.other")
        command.assert_not_called()

    def test_bad_installed_timeout_blocks_readiness(self):
        with patch.object(module.base, "safe_file"), patch.object(module.base, "safe_directory"), \
                patch.object(Path, "read_bytes", return_value=b"invalid"), patch.object(module.plistlib, "loads", return_value={}), \
                patch.object(module.upgrade.Upgrade, "wait_until_ready") as ready, self.assertRaisesRegex(RuntimeError, "60 seconds"):
            self.session.wait_until_ready()
        ready.assert_not_called()

    def test_default_plan_has_no_host_operations(self):
        result = subprocess.run([sys.executable, module.__file__], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["package_sha256"], module.PACKAGE_SHA)
        self.assertFalse(plan["database_recovery"])
        self.assertTrue(plan["normal_restart"])
        self.assertEqual(plan["sensor_exit_timeout"], 60)

    def test_reference_exception_cannot_publish_command_token(self):
        secret = "123456789012345"
        error = subprocess.TimeoutExpired(["/sbin/pfctl", "-X", secret], 30)
        with patch.object(module.upgrade.Upgrade, "release_reference", side_effect=error):
            with self.assertRaises(RuntimeError) as raised:
                self.session.release_reference()
        self.assertNotIn(secret, str(raised.exception))

    def test_current_artifact_receipt_and_template_are_pinned(self):
        self.assertEqual(self.session.receipt_time, 1790731448)
        self.assertNotEqual(self.session.package_sha, module.ownership.PACKAGE_SHA)
        self.assertIn(module.base.SENSOR / "com.squirrelops.sensor.plist", self.session.new_executables)
        self.assertEqual(self.session.install.__func__, module.ownership.OwnershipUpgrade.install)

    def test_laptop_wrapper_uses_the_same_candidate_without_running(self):
        path = Path(__file__).with_name("mini_launchd_client.py")
        client_spec = importlib.util.spec_from_file_location("launchd_client", path)
        wrapper = importlib.util.module_from_spec(client_spec)
        with patch.object(subprocess, "run") as run:
            client_spec.loader.exec_module(wrapper)
        run.assert_not_called()
        self.assertEqual(wrapper.client.PACKAGE_SHA, module.PACKAGE_SHA)


if __name__ == "__main__":
    unittest.main()
