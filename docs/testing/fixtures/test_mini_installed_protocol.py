"""Start-only protocol window checks. All host operations are mocked."""
from contextlib import ExitStack
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("window", Path(__file__).with_name("mini_installed_protocol_window.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class InstalledProtocolTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.session = module.InstalledProtocolWindow(self.root)
        self.session.backup = self.root / "private"
        self.session.backup.mkdir()
        self.session.public = self.root / "public"
        self.session.public.mkdir()

    def test_actual_cleanup_receipt_and_fail_closed_variants(self):
        path = Path(__file__).parent.parent / "evidence/2026-09-30-mini-relay-idle/cleanup-complete.json"
        if not path.is_file():
            self.skipTest("Requires retained private Mini cleanup evidence")
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), module.CLEANUP_SHA)
        receipt = json.loads(path.read_text())
        module.validate_cleanup(receipt)
        for key, bad in (("phase", "needs_review"), ("pf_enabled", True), ("pf_enabled", 0),
                         ("boot_seconds", 0), ("reviewed_decoy_count", 8), ("package_sha256", "other"),
                         ("test_scope", "other"), ("own_pf_reference_released", False),
                         ("guest_stopped", False), ("aliases_absent", False), ("jobs_disabled", False),
                         ("configuration_unchanged", False)):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                module.validate_cleanup({**receipt, key: bad})

    def test_installed_hash_and_receipt_baseline(self):
        self.assertEqual(self.session.old_executables, self.session.new_executables)
        self.assertEqual(self.session.receipt_time, 1790818368)
        self.assertEqual(self.session.config_sha, module.single.NEW_CONFIG_SHA)

    def test_no_installer_or_opt_in_dispatch(self):
        with patch.object(module.base.Session, "command") as dispatch:
            for args in (["/usr/sbin/installer", "-pkg", "candidate.pkg", "-target", "/"],
                         ["/usr/bin/install", "-m", "600", "/dev/null", "/var/db/com.squirrelops.allow-local-test"]):
                with self.assertRaises(RuntimeError):
                    self.session.command(args)
            with self.assertRaises(RuntimeError):
                self.session.install_package()
        dispatch.assert_not_called()

    def test_approval_and_backup_required(self):
        for approved, backed_up in ((False, True), (True, False)):
            self.session.upgrade_approved, self.session.backup_verified = approved, backed_up
            with patch.object(self.session, "command") as command, self.assertRaises(RuntimeError):
                self.session.install()
            command.assert_not_called()

    def checks(self, stack):
        self.session.upgrade_approved = self.session.backup_verified = True
        self.session.pf_baseline = {}
        for name in ("validate_existing", "verify_intent", "check_effective_pool", "check_conflicts"):
            stack.enter_context(patch.object(self.session, name))
        stack.enter_context(patch.object(self.session, "inspect_empty_pf", return_value={}))

    def test_conflict_prevents_all_mutations(self):
        with ExitStack() as stack:
            self.checks(stack)
            stack.enter_context(patch.object(self.session, "check_conflicts", side_effect=RuntimeError("ARP reply")))
            command = stack.enter_context(patch.object(self.session, "command"))
            with self.assertRaises(RuntimeError):
                self.session.install()
        command.assert_not_called()
        self.assertFalse(self.session.install_started)

    def test_consumed_claim_prevents_all_mutations(self):
        (self.root / f"protocol-{module.post.BOOT}-{module.relay.PACKAGE_SHA[:12]}-attempt.json").touch()
        with ExitStack() as stack:
            self.checks(stack)
            command = stack.enter_context(patch.object(self.session, "command"))
            with self.assertRaises(FileExistsError):
                self.session.install()
        command.assert_not_called()

    def startup(self, *, fail_sensor=False):
        order = []

        def command(args, **_kwargs):
            if args == ["/sbin/pfctl", "-E"]:
                self.assertTrue(self.session.claim.is_file())
                order.append("pf_enable")
                return subprocess.CompletedProcess(args, 0, "Token : 123\n", "")
            self.assertTrue(self.session.install_started)
            self.assertFalse(self.session.install_in_progress)
            self.assertEqual(args[:3], ["/bin/launchctl", "bootstrap", "system"])
            order.append(Path(args[-1]).name)
            if fail_sensor and "sensor" in args[-1]:
                raise RuntimeError("bootstrap failed")
            return subprocess.CompletedProcess(args, 0, "", "")

        with ExitStack() as stack:
            self.checks(stack)
            stack.enter_context(patch.object(self.session, "command", side_effect=command))
            stack.enter_context(patch.object(self.session, "pf", return_value="Status: Enabled"))
            stack.enter_context(patch.object(self.session, "enable_for_install", side_effect=lambda: order.append("enable_jobs")))
            stack.enter_context(patch.object(self.session, "wait_until_ready", side_effect=lambda: order.append("ready")))
            stack.enter_context(patch.object(self.session, "snapshot"))
            installer = stack.enter_context(patch.object(self.session, "install_package"))
            restart = stack.enter_context(patch.object(self.session, "restart_check"))
            if fail_sensor:
                with self.assertRaisesRegex(RuntimeError, "bootstrap failed"):
                    self.session.install()
            else:
                self.session.install()
            installer.assert_not_called()
            restart.assert_not_called()
        return order

    def test_starts_only_two_existing_jobs_in_order(self):
        self.assertEqual(self.startup(), ["pf_enable", "enable_jobs", "com.squirrelops.helper.plist",
                                         "com.squirrelops.sensor.plist", "ready"])
        self.assertEqual((self.session.backup / "pf-reference-token").read_text(), "123\n")
        status = json.loads((self.session.public / "status.json").read_text())
        self.assertEqual(status["phase"], "starting")
        self.assertTrue(status["installed_only"])

    def test_partial_start_keeps_shutdown_armed_and_reference_retained(self):
        self.assertEqual(self.startup(fail_sensor=True)[-1], "com.squirrelops.sensor.plist")
        self.assertTrue(self.session.install_started)
        self.assertEqual(self.session.token, "123")

    def test_real_release_chain_uses_correct_base(self):
        self.session.token = "123"
        calls = []

        def command(args, **_kwargs):
            calls.append(args)
            output = "TOKENS: 123" if self.session.token else "No pf starter references held"
            return subprocess.CompletedProcess(args, 0, output, "")

        with patch.object(self.session, "restore_hold") as hold, patch.object(self.session, "command", side_effect=command):
            self.session.release_reference()
        hold.assert_called_once()
        self.assertEqual(calls, [["/sbin/pfctl", "-s", "References"], ["/sbin/pfctl", "-X", "123"],
                                 ["/sbin/pfctl", "-s", "References"]])

    def test_plan_only(self):
        result = subprocess.run([sys.executable, "-I", "-B", module.__file__], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertTrue(plan["installed_only"])
        self.assertFalse(plan["install"] or plan["restart_test"] or plan["database_recovery"])

    def test_bootstrap_pins_every_input(self):
        root = Path(__file__).parent
        text = (root / "start-mini-installed-protocol.sh").read_text()
        copies = re.search(r"for name in (.+); do", text).group(1).split()
        pins = dict(re.findall(r"^verify_digest (\S+) ([a-f0-9]{64})$", text, re.M))
        self.assertEqual(set(copies), set(pins))
        self.assertEqual(set(pins), {*module.InstalledProtocolWindow.input_names, "candidate.pkg"})
        self.assertEqual(pins.pop("candidate.pkg"), module.relay.PACKAGE_SHA)
        for name, expected in pins.items():
            path = root / name
            if name == "approved-scope.md":
                path = root.parent / "2026-10-01-mini-installed-protocol-scope.md"
            elif name == "single-ip-config.yaml":
                path = root / "mini-single-ip-config.yaml"
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected, name)


if __name__ == "__main__":
    unittest.main()
