"""Local guard tests; all system operations are mocked."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("mini_upgrade", Path(__file__).with_name("mini_upgrade_acceptance.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class UpgradeGuards(unittest.TestCase):
    def setUp(self):
        self.session = module.Upgrade(Path("/unused"))

    def test_os_distnoted_is_not_a_surviving_sensor(self):
        self.assertEqual(module.runtime_pids("309 27648 /usr/sbin/distnoted\n"), [])

    def test_unknown_service_process_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "Unexpected service process"):
            module.runtime_pids("309 12 /tmp/unrecognized\n")

    def test_launchd_error_is_not_service_absence(self):
        with self.assertRaisesRegex(RuntimeError, "uncertain"):
            module.loaded_result(subprocess.CompletedProcess([], 1, "", "permission denied"), "com.squirrelops.sensor")

    def test_known_runtimes_are_detected_and_other_users_are_not_touched(self):
        value = f"309 3 {module.GUEST}\n309 4 {module.VM}\n309 5 {module.RUNTIME}\n501 6 {module.VM}\n"
        self.assertEqual(module.runtime_pids(value), [3, 4, 5])

    def test_product_running_under_wrong_uid_is_rejected(self):
        for command in (module.GUEST, str(module.RUNTIME), str(module.base.APP / "Contents/MacOS/SquirrelOpsHome")):
            with self.subTest(command=command), self.assertRaises(RuntimeError):
                module.runtime_pids("501 7 " + command)

    def test_malformed_process_inventory_is_rejected(self):
        for text in ("bad", "309 ? missing", "unknown 5 /bin/sh"):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                module.runtime_pids(text)

    def test_exact_launchd_absence_and_presence(self):
        label = "com.squirrelops.sensor"
        self.assertFalse(module.loaded_result(subprocess.CompletedProcess([], 113, "", f'Could not find service "{label}"'), label))
        self.assertTrue(module.loaded_result(subprocess.CompletedProcess([], 0, f"system/{label} = {{", ""), label))
        for label, stdout in ((label, ""), ("unrelated", "system/unrelated = {")):
            with self.assertRaises(RuntimeError):
                module.loaded_result(subprocess.CompletedProcess([], 0, stdout, ""), label)

    def test_delayed_launchd_exit_is_polled(self):
        with patch.object(self.session, "service_loaded", side_effect=[True, True, False]), \
                patch.object(self.session, "command") as command, patch.object(module.time, "sleep"):
            self.session.stop_job("com.squirrelops.sensor")
        command.assert_called_once_with(["/bin/launchctl", "bootout", "system/com.squirrelops.sensor"], check=False, timeout=90)

    def test_launchd_timeout_fails_closed(self):
        with patch.object(self.session, "service_loaded", return_value=True), \
                patch.object(self.session, "command"), patch.object(module.time, "monotonic", side_effect=[0, 50]):
            with self.assertRaisesRegex(RuntimeError, "remains loaded"):
                self.session.stop_job("com.squirrelops.sensor")

    def test_no_backup_no_install(self):
        with patch.object(self.session, "command") as command, self.assertRaisesRegex(RuntimeError, "backup"):
            self.session.install()
        command.assert_not_called()

    def test_policy_drift_prevents_install(self):
        self.session.backup_verified = True
        self.session.backup = Path("/unused")
        self.session.pf_baseline = {"before": {}}
        with patch.object(self.session, "inspect_empty_pf", return_value={"after": {}}), \
                patch.object(self.session, "command") as command, self.assertRaisesRegex(RuntimeError, "policy changed"):
            self.session.install()
        command.assert_not_called()

    def test_single_use_guard_prevents_second_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.session.backup = root / "backup"
            self.session.backup_verified = True
            self.session.pf_baseline = {}
            (root / "upgrade-541fc783c41f-attempt.json").write_text("existing evidence")
            with patch.object(self.session, "validate_existing"), patch.object(self.session, "check_conflicts"), \
                    patch.object(self.session, "inspect_empty_pf", return_value={}), \
                    patch.object(self.session, "command") as command, self.assertRaises(FileExistsError):
                self.session.install()
            command.assert_not_called()
            self.assertEqual((root / "upgrade-541fc783c41f-attempt.json").read_text(), "existing evidence")

    def test_uncertain_installer_retains_protection(self):
        self.session.install_in_progress = True
        with patch.object(self.session, "command") as command, self.assertRaisesRegex(RuntimeError, "uncertain"):
            self.session.stop()
        command.assert_not_called()

    def test_preflight_failure_does_not_stop_existing_product(self):
        with patch.object(self.session, "command") as command:
            self.session.stop()
        command.assert_not_called()

    def test_lingering_guest_prevents_alias_withdrawal_and_reference_release(self):
        self.session.install_started = True
        self.session.token = "1234"
        with patch.object(self.session, "publish"), patch.object(self.session, "owned", return_value=["192.168.1.240"]), \
                patch.object(self.session, "stop_job"), patch.object(self.session, "processes", return_value=[123]), \
                patch.object(module.time, "monotonic", side_effect=[0, 70]), patch.object(self.session, "rpc") as rpc, \
                patch.object(self.session, "release_reference") as release:
            with self.assertRaisesRegex(RuntimeError, "runtime remains"):
                self.session.stop()
        rpc.assert_not_called()
        release.assert_not_called()
        self.assertEqual(self.session.token, "1234")

    def test_safe_cleanup_orders_withdrawal_before_clear_and_release(self):
        self.session.install_started = True
        self.session.token = "1234"
        self.session.pf_baseline = {}
        events = []
        def command(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, "", "")
        with patch.object(self.session, "publish"), patch.object(self.session, "owned", side_effect=[[], ["192.168.1.240"], []]), \
                patch.object(self.session, "stop_job", side_effect=lambda label: events.append("stop:" + label)), \
                patch.object(self.session, "processes", return_value=[]), patch.object(self.session, "command", side_effect=command), \
                patch.object(self.session, "service_loaded", side_effect=[True, False, False]), \
                patch.object(self.session, "rpc", side_effect=lambda method, params: events.append(method)), \
                patch.object(self.session, "assert_no_test_network", side_effect=lambda: events.append("aliases_absent")), \
                patch.object(self.session, "inspect_empty_pf", return_value={}), patch.object(self.session, "host_baseline"), \
                patch.object(self.session, "release_reference", side_effect=lambda: events.append("release")), \
                patch.object(self.session, "pf", return_value="Status: Disabled\n"):
            self.session.stop()
        self.assertLess(events.index("stop:com.squirrelops.sensor"), events.index("removeIPAlias"))
        self.assertLess(events.index("removeIPAlias"), events.index("aliases_absent"))
        self.assertLess(events.index("aliases_absent"), events.index("clearPortForwards"))
        self.assertLess(events.index("stop:com.squirrelops.helper"), events.index("release"))

    def test_reference_release_requires_own_token_and_never_retries_uncertain_release(self):
        self.session.token = "1234"
        with patch.object(self.session, "pf", return_value="9123456"), patch.object(self.session, "command") as command:
            with self.assertRaisesRegex(RuntimeError, "missing"):
                self.session.release_reference()
        command.assert_not_called()
        self.session.token = "1234"
        with patch.object(self.session, "pf", return_value="1234"), \
                patch.object(self.session, "command", side_effect=RuntimeError("uncertain")) as command:
            with self.assertRaises(RuntimeError):
                self.session.release_reference()
            self.session.release_reference()
        command.assert_called_once_with(["/sbin/pfctl", "-X", "1234"])

    def test_empty_product_anchor_is_only_permitted_policy_difference(self):
        original = {"": {"children": ["com.apple"], "-sr": "anchor", "-sn": "nat"},
                    "com.apple": {"children": [], "-sr": "", "-sn": ""}}
        after = json.loads(json.dumps(original))
        after["com.apple"]["children"] = [module.PRODUCT_ANCHOR]
        after[module.PRODUCT_ANCHOR] = {"children": [], "-sr": "", "-sn": ""}
        self.assertTrue(module.empty_policy_matches(original, after))
        after[module.PRODUCT_ANCHOR]["-sr"] = "pass in all"
        self.assertFalse(module.empty_policy_matches(original, after))
        after[module.PRODUCT_ANCHOR]["-sr"] = ""
        after["com.apple"]["children"].append("com.apple/new")
        self.assertFalse(module.empty_policy_matches(original, after))

    def test_backup_manifest_preserves_links_without_following_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "content").write_text("synthetic content")
            (root / "outside-link").symlink_to("/does-not-exist")
            values = module.tree_manifest(root)
            self.assertEqual(values["outside-link"]["kind"], "link")
            self.assertEqual(values["outside-link"]["target"], "/does-not-exist")
            self.assertEqual(values["content"]["sha256"], module.base.digest(root / "content"))

    def test_socket_aware_backup_copies_durable_siblings_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / "source", root / "copy"
            source.mkdir()
            (source / "config").write_text("private fixture")
            (source / "run").mkdir()
            # Synthetic socket metadata avoids starting an actual listener.
            (source / "run/socket").write_text("not copied")
            items = module.tree_manifest(source)
            items["run/socket"] = {"kind": "socket", "omitted": True}
            def copy(args, **kwargs):
                shutil.copy2(args[1], args[2])
            with patch.object(module.os, "chown"):
                module.copy_durable(source, target, items, copy)
            self.assertEqual((target / "config").read_text(), "private fixture")
            self.assertFalse((target / "run/socket").exists())

    def test_recorded_pf_snapshot_and_corruptions(self):
        fixture = Path(__file__).parent.parent / "evidence/2026-09-29-mini/after.json"
        if not fixture.is_file():
            self.skipTest("Requires retained private Mini PF snapshot")
        snapshot = json.loads(fixture.read_text())
        mappings = module.verify_guarded_snapshot(snapshot)
        self.assertEqual({m["port"] for m in mappings}, {22, 445, 11434, 1234, 8765})
        for field, before, after in (("pf_rules", "user = 309", "user = 0"),
                                     ("pf_nat", "rdr on", "rdr pass on"),
                                     ("pf_rules", "block drop", "pass"),
                                     ("pf_nat", "50708", "50799")):
            broken = {**snapshot, field: snapshot[field].replace(before, after)}
            with self.subTest(field=field, before=before), self.assertRaises(RuntimeError):
                module.verify_guarded_snapshot(broken)

    def test_readonly_default_plan(self):
        result = subprocess.run([str(Path(__import__('sys').executable)), str(Path(module.__file__))],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["mode"], "plan_only")


if __name__ == "__main__":
    unittest.main()
