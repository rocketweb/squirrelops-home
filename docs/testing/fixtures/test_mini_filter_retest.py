"""Approved filter retest checks; all host operations are mocked."""
from contextlib import ExitStack
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("filter_retest", Path(__file__).with_name("mini_filter_retest.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class FilterRetestTests(unittest.TestCase):
    def test_actual_cleanup_and_rejection(self):
        path = Path(__file__).parents[1] / "evidence/2026-10-01-mini-installed-protocol/cleanup-status.json"
        if not path.is_file():
            self.skipTest("Requires retained private Mini cleanup evidence")
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), m.CLEANUP_SHA)
        receipt = json.loads(path.read_text())
        m.validate_cleanup(receipt)
        for key, value in (("phase", "ready_for_tests"), ("pf_enabled", True), ("pf_enabled", 0),
                           ("test_scope", "other"), ("boot_seconds", 0), ("test_vips", ["192.168.1.241"]),
                           ("own_pf_reference_released", False), ("guest_stopped", False),
                           ("aliases_absent", False), ("configuration_unchanged", False),
                           ("config_change_verified", False), ("installation_retained", False),
                           ("test_data_retained", False), ("original_listener_endpoints_present", False)):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                m.validate_cleanup({**receipt, key: value})

    def test_inherits_verified_start_and_stop_not_installer(self):
        self.assertIs(m.FilterRetest.install, m.window.InstalledProtocolWindow.install)
        self.assertIs(m.FilterRetest.stop, m.window.InstalledProtocolWindow.stop)
        self.assertIs(m.FilterRetest.release_reference, m.window.InstalledProtocolWindow.release_reference)
        self.assertEqual(m.FilterRetest.old_executables, m.FilterRetest.new_executables)
        self.assertEqual(m.FilterRetest.receipt_time, 1790818368)

    def test_new_claim_is_exclusive_and_preserves_old_claim(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            runner = m.FilterRetest(root)
            runner.backup = root / "backup"
            runner.backup.mkdir()
            runner.backup_verified = runner.upgrade_approved = True
            runner.pf_baseline = {}
            old = root / f"protocol-{m.post.BOOT}-{m.relay.PACKAGE_SHA[:12]}-attempt.json"
            old.write_text("preserve")
            for name in ("validate_existing", "verify_intent", "check_effective_pool", "check_conflicts"):
                stack.enter_context(patch.object(runner, name))
            stack.enter_context(patch.object(runner, "inspect_empty_pf", return_value={}))
            command = stack.enter_context(patch.object(runner, "command", side_effect=RuntimeError("stop before PF")))
            with self.assertRaisesRegex(RuntimeError, "stop before PF"):
                runner.install()
            self.assertEqual(runner.claim.name, f"protocol-filter-approved-{m.post.BOOT}-{m.relay.PACKAGE_SHA[:12]}-attempt.json")
            self.assertEqual(old.read_text(), "preserve")
            command.reset_mock()
            with self.assertRaises(FileExistsError):
                runner.install()
            command.assert_not_called()

    def test_new_preflight_requires_exact_durable_receipt(self):
        runner = m.FilterRetest(Path("/private/var/root/squirrelops-mini-filter-retest.fixture"))
        with patch.object(m.base, "safe_directory"), patch.object(m.base, "safe_file"), patch.object(m.base, "digest", return_value="drift"), patch.object(m.relay.RelayDiagnosticUpgrade, "preflight") as parent:
            with self.assertRaises(RuntimeError):
                runner.preflight()
            parent.assert_not_called()

    def test_confirmation_states_manual_rule_and_one_run(self):
        runner = m.FilterRetest(Path("/tmp/fixture"))
        with patch("builtins.input", return_value=m.CONSENT), patch("builtins.print") as output:
            runner.confirm_scope()
        text = " ".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("30-minute", text)
        self.assertIn("192.168.1.7", text)
        self.assertIn("No Little Snitch changes", text)
        with patch("builtins.input", return_value=""), patch("builtins.print"), self.assertRaises(RuntimeError):
            runner.confirm_scope()

    def test_bootstrap_pins_all_inputs(self):
        root = Path(__file__).parent
        text = (root / "start-mini-filter-retest.sh").read_text()
        names = re.search(r"for name in (.+); do", text).group(1).split()
        pins = dict(re.findall(r"^verify_digest (\S+) ([a-f0-9]{64})$", text, re.M))
        self.assertEqual(set(names), set(pins))
        self.assertEqual(set(pins), {*m.FilterRetest.input_names, "candidate.pkg"})
        self.assertEqual(pins.pop("candidate.pkg"), m.relay.PACKAGE_SHA)
        for name, expected in pins.items():
            path = root / name
            if name == "approved-scope.md":
                path = root.parent / "2026-10-01-mini-filter-retest-scope.md"
            elif name == "single-ip-config.yaml":
                path = root / "mini-single-ip-config.yaml"
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected, name)

    def test_plan_only(self):
        import sys
        result = subprocess.run([sys.executable, "-I", "-B", m.__file__], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["confirmation"], m.CONSENT)
        self.assertTrue(plan["installed_only"])
        self.assertFalse(plan["install"] or plan["restart_test"] or plan["third_party_filter_changes"])


if __name__ == "__main__":
    unittest.main()
