"""Disposable/mocked acceptance-runner tests. Never contact a host or invoke sudo."""
from contextlib import ExitStack
from datetime import datetime, timezone
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


module = load("mini_relay_diagnostic_acceptance")
client_module = load("mini_relay_diagnostic_client")


class IntentAndExport(unittest.TestCase):
    def test_seven_baseline_rows_are_preserved(self):
        self.assertEqual(module.validate_intent(module.EXPECTED_INTENT), [])
        for rows in (module.EXPECTED_INTENT[:-1], [*module.EXPECTED_INTENT, module.EXPECTED_INTENT[0]],
                     [[1, "deep", "192.168.1.240", 445, "stopped"], *module.EXPECTED_INTENT[1:]]):
            with self.subTest(rows=rows), self.assertRaises(RuntimeError):
                module.validate_intent(rows, additions=True)

    def test_automatic_host_listener_is_retained_after_start_not_at_baseline(self):
        extra = [8, "dev_server", "192.168.1.115", 60123, "active"]
        rows = [*module.EXPECTED_INTENT, extra]
        with self.assertRaises(RuntimeError):
            module.validate_intent(rows)
        self.assertEqual(module.validate_intent(rows, additions=True), [extra])
        self.assertEqual(rows[-1], extra)

    def test_new_virtual_hosts_and_native_ports_are_not_accepted(self):
        for extra in ([8, "deep", "192.168.1.240", 8080, "active"],
                      [8, "dev_server", "192.168.1.241", 60123, "active"],
                      [8, "dev_server", "192.168.1.115", 22, "active"],
                      [8, "mimic", "192.168.1.115", 60123, "active"],
                      [8, "dev_server", "192.168.1.115", True, "active"]):
            with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                module.validate_intent([*module.EXPECTED_INTENT, extra], additions=True)

    def test_export_omits_arbitrary_log_text_and_old_records(self):
        line = ("2026-09-30 15:00:00,123 [INFO] squirrelops_home_sensor.decoys.deep.guest_runtime: "
                "Guest relay checkpoint stage=accepted service=22 connection=1 sequence=3 errno=0 direction=none")
        raw = "password=private\n" + line + "\n" + line.replace("15:00:00", "14:59:59")
        records = module.checkpoints(raw, "2026-09-30 15:00:00")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["connection"], 1)
        self.assertNotIn("private", json.dumps(records))
        for invalid in (line + " payload=private", line.replace("accepted", "private"),
                        line.replace("sequence=3", "sequence=514"), line.replace("errno=0", "errno=9999999999"),
                        line.replace("service=22", "service=80"), line.replace("[INFO]", "[WARNING]")):
            with self.subTest(line=invalid):
                self.assertEqual(module.checkpoints(invalid, "2026-09-30"), [])

    def test_export_is_bounded_and_accepts_both_directions(self):
        line = ("2026-09-30 15:00:00,123 [INFO] squirrelops_home_sensor.decoys.deep.guest_runtime: "
                "Guest relay checkpoint stage=first_read service=445 connection=1 sequence=3 errno=0 direction=")
        for direction in ("client_to_guest", "guest_to_client"):
            self.assertEqual(module.checkpoints(line + direction, "2026-09-30")[0]["direction"], direction)
        self.assertEqual(len(module.checkpoints((line + "none\n") * 2000, "2026-09-30")), 1539)

    def test_plan_has_no_mutations(self):
        result = subprocess.run([sys.executable, module.__file__], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["test_vips"], ["192.168.1.240"])
        self.assertEqual(plan["configuration_edits"], 0)
        self.assertFalse(plan["database_recovery"])
        self.assertFalse(plan["third_party_filter_rule_changes"])

    def test_socket_export_keeps_only_scoped_guest_tcp_queues(self):
        raw = ("p123\nccom.squir\nu309\nf5\nn192.168.1.240:50001->192.168.1.7:40000\n"
               "TST=ESTABLISHED\nTQR=238\nTQS=0\nf6\nn192.168.1.240:50002\nTST=LISTEN\n"
               "p124\ncother\nu501\nf5\nn192.168.1.240:50001\nTST=LISTEN\n"
               "p125\ncother\nu309\nf5\nn192.168.1.115:12345->203.0.113.1:443\nTST=ESTABLISHED\n")
        rows = module.socket_metadata(raw)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], {"pid": 123, "local_port": 50001, "client_port": 40000,
                                   "state": "ESTABLISHED", "receive_queue": 238, "send_queue": 0})
        self.assertEqual(rows[1]["state"], "LISTEN")
        self.assertNotIn("203.0.113", json.dumps(rows))

    def test_bootstrap_pins_every_input_before_private_python_execution(self):
        root = Path(__file__).parent
        text = (root / "start-mini-relay-diagnostic-acceptance.sh").read_text()
        pins = dict(re.findall(r"^verify_digest (\S+) ([a-f0-9]{64})$", text, re.M))
        self.assertEqual(set(pins), {*module.RelayDiagnosticUpgrade.input_names, "candidate.pkg"})
        self.assertEqual(pins.pop("candidate.pkg"), module.PACKAGE_SHA)
        for name, expected in pins.items():
            path = root / name
            if name == "approved-scope.md":
                path = root.parent / "2026-09-30-mini-relay-diagnostic-scope.md"
            elif name == "single-ip-config.yaml":
                path = root / "mini-single-ip-config.yaml"
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected, name)
        self.assertLess(text.index("verify_digest approved-scope.md"), text.index("/usr/sbin/pkgutil --expand-full"))
        self.assertIn('"$runtime" -I -B', text)


class SessionGuards(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.session = module.RelayDiagnosticUpgrade(self.root)
        self.session.backup = self.root / "private"
        self.session.backup.mkdir()
        self.session.public = self.root / "public"
        self.session.public.mkdir()

    def test_new_scope_and_unchanged_configuration_are_published(self):
        self.session.publish("preflight")
        result = json.loads((self.session.public / "status.json").read_text())
        self.assertEqual(result["test_scope"], module.SCOPE)
        self.assertTrue(result["configuration_unchanged"])
        self.assertEqual(self.session.config_sha, module.single.NEW_CONFIG_SHA)
        self.assertFalse(self.session.config_change_started)
        self.assertEqual((self.session.public / "status.json").read_bytes(),
                         (self.session.backup / "status.json").read_bytes())

    def test_preflight_requires_empty_ownership_not_old_stale_ledger(self):
        with patch.object(self.session, "owned", return_value=[]):
            self.session.check_stale_ledger()
        for entries in (["192.168.1.240"], ["192.168.1.241"]):
            with patch.object(self.session, "owned", return_value=entries), self.assertRaises(RuntimeError):
                self.session.check_stale_ledger()

    def test_install_requires_approval_and_backup(self):
        for approved, backed_up in ((False, True), (True, False)):
            self.session.upgrade_approved, self.session.backup_verified = approved, backed_up
            with patch.object(self.session, "command") as command, self.assertRaises(RuntimeError):
                self.session.install_package()
            command.assert_not_called()

    def mocked_install(self, stack):
        self.session.upgrade_approved = self.session.backup_verified = True
        self.session.pf_baseline = {}
        for name in ("validate_existing", "verify_intent", "check_effective_pool", "check_conflicts"):
            stack.enter_context(patch.object(self.session, name))
        stack.enter_context(patch.object(self.session, "inspect_empty_pf", return_value={}))

    def test_one_shot_claim_precedes_mutation(self):
        (self.root / f"relay-{module.post.BOOT}-{module.PACKAGE_SHA[:12]}-attempt.json").touch()
        with ExitStack() as stack:
            self.mocked_install(stack)
            command = stack.enter_context(patch.object(self.session, "command"))
            with self.assertRaises(FileExistsError):
                self.session.install_package()
        command.assert_not_called()

    def test_installer_failure_preserves_reference_without_config_or_sql_edit(self):
        order = []
        def command(args, **kwargs):
            if args == ["/sbin/pfctl", "-E"]:
                order.append("pf_enable")
                return subprocess.CompletedProcess(args, 0, "Token : 123\n", "")
            if args[0] == "/usr/bin/install":
                order.append("local_test_marker")
                return subprocess.CompletedProcess(args, 0, "", "")
            if args[0] == "/usr/sbin/installer":
                order.append("installer")
                return subprocess.CompletedProcess(args, 1, "private failure", "")
            self.fail(str(args))
        with ExitStack() as stack:
            self.mocked_install(stack)
            stack.enter_context(patch.object(self.session, "command", side_effect=command))
            stack.enter_context(patch.object(self.session, "pf", return_value="Status: Enabled\n"))
            stack.enter_context(patch.object(self.session, "enable_for_install", side_effect=lambda: order.append("enable_jobs")))
            change = stack.enter_context(patch.object(module.single, "replace_config"))
            restart = stack.enter_context(patch.object(self.session, "restart_check"))
            with self.assertRaisesRegex(RuntimeError, "Installer failed"):
                self.session.install()
        self.assertEqual(order, ["pf_enable", "enable_jobs", "local_test_marker", "installer"])
        change.assert_not_called()
        restart.assert_not_called()
        self.assertEqual(self.session.token, "123")
        self.assertTrue(self.session.install_started)
        self.assertFalse(self.session.install_in_progress)

    def test_surviving_guest_blocks_restart_bootstrap(self):
        with patch.object(self.session, "snapshot"), patch.object(self.session, "verify_intent"), \
                patch.object(self.session, "stop_job"), patch.object(self.session, "processes", return_value=[123]), \
                patch.object(module.time, "monotonic", side_effect=[0, 61]), \
                patch.object(self.session, "command") as command, self.assertRaisesRegex(RuntimeError, "survived"):
            self.session.restart_check()
        command.assert_not_called()

    def test_failed_hold_restore_never_releases_protection(self):
        with patch.object(self.session, "restore_hold", side_effect=RuntimeError("not stopped")), \
                patch.object(module.launchd.LaunchdUpgrade, "release_reference") as release, self.assertRaises(RuntimeError):
            self.session.release_reference()
        release.assert_not_called()

    def test_real_release_chain_restores_hold_then_releases_owned_reference(self):
        # Do not mock the borrowed LaunchdUpgrade method: that hid its invalid
        # zero-argument super() call on a PostRebootUpgrade instance.
        token = "123456789012345"
        self.session.token = token
        order = []

        def command(args, **_kwargs):
            order.append(args)
            if args == ["/sbin/pfctl", "-s", "References"]:
                text = "TOKENS: " + token if self.session.token else "No pf starter references held"
                return subprocess.CompletedProcess(args, 0, text, "")
            if args == ["/sbin/pfctl", "-X", token]:
                self.assertIsNone(self.session.token)
                return subprocess.CompletedProcess(args, 0, "", "")
            self.fail("Unexpected command")

        with patch.object(self.session, "restore_hold", side_effect=lambda: order.append("hold")), \
                patch.object(self.session, "command", side_effect=command):
            self.session.release_reference()
        self.assertEqual(order, ["hold", ["/sbin/pfctl", "-s", "References"],
                                 ["/sbin/pfctl", "-X", token], ["/sbin/pfctl", "-s", "References"]])

    def test_release_failure_redacts_token_and_does_not_retry(self):
        token = "123456789012345"
        self.session.token = token
        calls = []

        def command(args, **_kwargs):
            calls.append(args)
            if args == ["/sbin/pfctl", "-s", "References"]:
                return subprocess.CompletedProcess(args, 0, "TOKENS: " + token, "")
            raise subprocess.TimeoutExpired(args, 30)

        with patch.object(self.session, "restore_hold"), \
                patch.object(self.session, "command", side_effect=command):
            with self.assertRaises(RuntimeError) as error:
                self.session.release_reference()
            self.assertNotIn(token, str(error.exception))
            self.assertIsNone(self.session.token)
            self.session.release_reference()
        self.assertEqual(calls, [["/sbin/pfctl", "-s", "References"], ["/sbin/pfctl", "-X", token]])

    def test_baseline_addition_guard_switches_only_after_install(self):
        extra = [8, "dev_server", "192.168.1.115", 60123, "active"]
        with patch.object(self.session, "read_intent", return_value=[*module.EXPECTED_INTENT, extra]):
            with self.assertRaises(RuntimeError):
                self.session.verify_intent()
            self.session.install_started = True
            self.assertEqual(self.session.verify_intent(), [extra])

    @unittest.skipUnless(os.environ.get("SQUIRRELOPS_TEST_RELAY_PACKAGE_EXPANDED"), "Requires exact diagnostic package")
    def test_exact_new_payload_hashes_with_simulated_install_ownership(self):
        expanded = Path(os.environ["SQUIRRELOPS_TEST_RELAY_PACKAGE_EXPANDED"])
        self.assertTrue(expanded.is_absolute())
        for installed, expected in {**self.session.new_executables, module.upgrade.RUNTIME: module.upgrade.PYTHON_SHA}.items():
            component = "sensor.pkg" if installed.is_relative_to(module.base.SENSOR) else "app.pkg"
            payload = expanded / component / "Payload" / installed.relative_to("/")
            if installed == module.base.HELPER:
                payload = expanded / "app.pkg/Payload/Applications/SquirrelOps Home.app/Contents/Library/LaunchServices/com.squirrelops.helper"
            actual = payload.lstat()
            root_info = os.stat_result((*actual[:4], 0, 0, *actual[6:]))
            with self.subTest(path=str(installed)), patch.object(module.post.Path, "lstat", return_value=root_info), \
                    patch.object(module.post.os, "fstat", return_value=root_info):
                module.post.check_payload(payload, expected)


class ClientGuards(unittest.TestCase):
    def inputs(self):
        now = 1790794800
        endpoints = {"guest_ip": "192.168.1.240", "mappings": [
            {"ip": "192.168.1.240", "port": port, "backend": 50000 + i}
            for i, port in enumerate((22, 445, 1234, 11434, 8765))]}
        login = {"ip": "192.168.1.240", "username": "buildbot", "password": "Juniper!123456"}
        status = {"phase": "ready_for_tests", "sensor_uid": 309, "remaining_seconds": 1100,
                  "package_sha256": module.PACKAGE_SHA, "test_scope": module.SCOPE,
                  "test_vips": ["192.168.1.240"], "boot_seconds": module.post.BOOT,
                  "configuration_unchanged": True, "config_change_verified": True,
                  "time": datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        return endpoints, login, status, now

    def test_valid_diagnostic_scope(self):
        self.assertEqual(client_module.validate_inputs(*self.inputs()), "192.168.1.240")

    def test_wrong_scope_boot_or_old_candidate_is_rejected(self):
        for key, value in (("test_scope", "mini-post-reboot-240"), ("boot_seconds", 1),
                           ("configuration_unchanged", False), ("config_change_verified", False),
                           ("test_vips", ["192.168.1.241"]), ("package_sha256", "old"),
                           ("remaining_seconds", 599), ("phase", "stopped")):
            endpoints, login, status, now = self.inputs()
            status[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                client_module.validate_inputs(endpoints, login, status, now)

    def test_extra_and_aliased_backends_are_rejected(self):
        endpoints, login, status, now = self.inputs()
        endpoints["mappings"].append({"ip": "192.168.1.240", "port": 8080, "backend": 51000})
        with self.assertRaises(RuntimeError):
            client_module.validate_inputs(endpoints, login, status, now)
        endpoints["mappings"].pop()
        endpoints["mappings"][1]["backend"] = endpoints["mappings"][0]["backend"]
        with self.assertRaises(RuntimeError):
            client_module.validate_inputs(endpoints, login, status, now)

    def test_stale_readiness_never_authorizes_traffic(self):
        endpoints, login, status, now = self.inputs()
        with self.assertRaisesRegex(RuntimeError, "Stale"):
            client_module.validate_inputs(endpoints, login, status, now + 31)


if __name__ == "__main__":
    unittest.main()
