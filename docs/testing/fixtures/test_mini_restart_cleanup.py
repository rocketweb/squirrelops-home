"""Local cleanup guards: every host operation is replaced by a test double."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("restart_cleanup", Path(__file__).with_name("mini_restart_cleanup.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def result(stdout="", code=0, stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class RestartCleanupTests(unittest.TestCase):
    def setUp(self):
        self.session = module.RestartCleanup(Path("/unused"))

    @staticmethod
    def records():
        listeners = {"command": module.upgrade.LISTENERS, "exit": 0, "stderr": "", "stdout":
                     "u0\nn*:22\nn*:445\nn*:5900\nu501\nn192.168.1.115:11434\nn127.0.0.1:49199\n"}
        rows = [listeners.copy(), listeners.copy()]
        for flags in (["-s", "Anchors"], ["-sr"], ["-sn"]):
            rows.append({"command": ["/sbin/pfctl", *flags], "exit": 0, "stdout": "", "stderr": ""})
        rows.extend([
            {"command": ["/sbin/pfctl", "-E"], "exit": 0, "stdout": "Token : 12345\n", "stderr": ""},
            {"command": ["/usr/sbin/installer", "-pkg", str(module.STAGE / "candidate.pkg"), "-target", "/"],
             "exit": 0, "stdout": "", "stderr": ""},
        ])
        return rows

    def test_multiple_equal_native_snapshots_are_unambiguous(self):
        listeners, pf = module.recover_baseline(self.records(), "12345")
        self.assertEqual(len(listeners), 5)
        self.assertEqual(pf, {"": {"children": [], "-sr": "", "-sn": ""}})

    def test_changed_native_baseline_stops(self):
        rows = self.records()
        rows[1]["stdout"] += "u999\nn*:999\n"
        with self.assertRaisesRegex(RuntimeError, "inconsistent"):
            module.recover_baseline(rows, "12345")

    def test_reference_binding_and_malformed_token(self):
        for token in ("999", "", "1 2", "1" * 21):
            with self.subTest(token=token), self.assertRaises(RuntimeError):
                module.recover_baseline(self.records(), token)

    def test_released_reference_or_repeated_enable_stops(self):
        for command in (["/sbin/pfctl", "-X", "12345"], ["/sbin/pfctl", "-E"]):
            rows = self.records() + [{"command": command}]
            with self.subTest(command=command), self.assertRaises(RuntimeError):
                module.recover_baseline(rows, "12345")

    def test_wrong_package_stage_or_failed_install_stops(self):
        rows = self.records()
        rows[-1]["command"][2] = "/private/var/root/unrelated/candidate.pkg"
        with self.assertRaisesRegex(RuntimeError, "installation evidence"):
            module.recover_baseline(rows, "12345")
        rows = self.records()
        rows[-1]["exit"] = 1
        with self.assertRaisesRegex(RuntimeError, "installation evidence"):
            module.recover_baseline(rows, "12345")

    def test_missing_or_conflicting_pf_inventory_stops(self):
        rows = self.records()
        rows.pop(3)
        with self.assertRaisesRegex(RuntimeError, "Missing original PF"):
            module.recover_baseline(rows, "12345")
        rows = self.records()
        rows.insert(3, {"command": ["/sbin/pfctl", "-sr"], "exit": 0, "stdout": "changed", "stderr": ""})
        with self.assertRaisesRegex(RuntimeError, "PF reads differ"):
            module.recover_baseline(rows, "12345")

    def test_nested_pf_error_not_accepted_as_empty(self):
        rows = self.records()
        rows[3]["stderr"] = "pfctl: DIOCGETRULES: Invalid argument\n"
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            module.recover_baseline(rows, "12345")

    def test_process_path_uid_and_start_time_bound(self):
        for identity, start in (("501 " + module.upgrade.GUEST, module.STARTED),
                                ("309 /usr/sbin/sshd", module.STARTED),
                                ("309 " + module.upgrade.GUEST, "a different start")):
            with self.subTest(identity=identity, start=start), patch.object(self.session, "command", side_effect=[
                result(identity), result(start)
            ]), self.assertRaises(RuntimeError):
                self.session.process_identity(65802)

    def test_original_identity_and_absence(self):
        with patch.object(self.session, "command", side_effect=[result("309 " + module.upgrade.GUEST), result(module.STARTED)]):
            self.assertEqual(self.session.process_identity(65802), (309, module.upgrade.GUEST, module.STARTED))
        with patch.object(self.session, "command", return_value=result(code=1)):
            self.assertIsNone(self.session.process_identity(65802))

    def test_unrelated_process_cannot_be_signaled(self):
        with patch.object(self.session, "assert_sensor_absent"), patch.object(module.os, "kill") as kill:
            with self.assertRaisesRegex(RuntimeError, "two recorded"):
                self.session.terminate_recorded(65499)
        kill.assert_not_called()

    def test_restarted_sensor_is_never_stopped(self):
        with patch.object(self.session, "service_loaded", return_value=True), patch.object(self.session, "command") as command:
            with self.assertRaisesRegex(RuntimeError, "Sensor restarted"):
                self.session.stop_job("com.squirrelops.sensor")
        command.assert_not_called()

    def test_new_guest_prevents_signal(self):
        with patch.object(self.session, "service_loaded", return_value=False), \
                patch.object(self.session, "processes", return_value=[777]), patch.object(module.os, "kill") as kill:
            with self.assertRaisesRegex(RuntimeError, "New runtime"):
                self.session.terminate_recorded(65802)
        kill.assert_not_called()

    def test_timeout_uses_only_sigterm_and_never_teardown(self):
        with patch.object(self.session, "assert_sensor_absent"), patch.object(self.session, "process_identity", return_value=(309, "guest", "start")), \
                patch.object(module.time, "monotonic", side_effect=[0, 46]), patch.object(module.os, "kill") as kill:
            with self.assertRaisesRegex(RuntimeError, "no force-kill"):
                self.session.terminate_recorded(65802)
        kill.assert_called_once_with(65802, module.signal.SIGTERM)

    def test_guests_stop_before_existing_teardown(self):
        events = []
        with patch.object(self.session, "verify_containment", side_effect=lambda: events.append("verify")), \
                patch.object(self.session, "publish"), patch.object(self.session, "assert_sensor_absent"), \
                patch.object(self.session, "terminate_recorded", side_effect=lambda pid: events.append(pid)), \
                patch.object(self.session, "processes", return_value=[]), \
                patch.object(self.session, "stop", side_effect=lambda: events.append("teardown")):
            self.session.cleanup_runtime()
        self.assertEqual(events, ["verify", 65802, 65804, "teardown"])
        self.assertTrue(self.session.install_started)

    def test_guest_or_containment_failure_does_not_teardown(self):
        for method in ("verify_containment", "terminate_recorded"):
            with self.subTest(method=method), patch.object(self.session, "verify_containment"), \
                    patch.object(self.session, "publish"), patch.object(self.session, "terminate_recorded"), \
                    patch.object(self.session, method, side_effect=RuntimeError("injected")), patch.object(self.session, "stop") as stop:
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    self.session.cleanup_runtime()
                stop.assert_not_called()

    def test_release_timeout_still_redacts_saved_token(self):
        self.session.token = None
        self.session.private_reference = "123456789012345"
        self.session.public = Path("/unused-public")
        error = subprocess.TimeoutExpired(["/sbin/pfctl", "-X", self.session.private_reference], 30)
        with patch.object(self.session, "preflight_cleanup", side_effect=error), \
                patch.object(self.session, "publish") as publish, patch("builtins.print") as output, patch.object(module.os, "umask"):
            with self.assertRaises(SystemExit):
                self.session.run_cleanup()
        self.assertNotIn(self.session.private_reference, str(publish.call_args_list) + str(output.call_args_list))

    def test_plan_mode_is_read_only(self):
        with patch("sys.argv", ["mini_restart_cleanup.py"]), patch("builtins.print"), \
                patch.object(module.base.subprocess, "run") as run, patch.object(module.os, "kill") as kill:
            module.main()
        run.assert_not_called()
        kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
