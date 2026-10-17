"""Local-only cleanup guard tests; no real root operations or network activity."""
import importlib.util
from pathlib import Path
from contextlib import ExitStack
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("mini_cleanup", Path(__file__).with_name("mini_cleanup.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.session = module.Cleanup(Path("/unused"))

    def test_launchd_delayed_disappearance_is_waited_for(self):
        with patch.object(self.session, "service_loaded", side_effect=[True, True, True, False]), \
                patch.object(self.session, "command") as command, patch.object(module.time, "sleep"):
            self.session.stop_job("com.squirrelops.helper")
        command.assert_called_once_with(["/bin/launchctl", "bootout", "system/com.squirrelops.helper"],
                                        check=False, timeout=30)

    def test_absent_job_does_not_bootout(self):
        with patch.object(self.session, "service_loaded", return_value=False), \
                patch.object(self.session, "command") as command:
            self.session.stop_job("com.squirrelops.helper")
        command.assert_not_called()

    def test_stuck_job_does_not_pass(self):
        with patch.object(self.session, "service_loaded", return_value=True), \
                patch.object(self.session, "command"), patch.object(module.time, "sleep"), \
                patch.object(module.time, "monotonic", side_effect=[0, 31]):
            with self.assertRaisesRegex(RuntimeError, "remains loaded"):
                self.session.stop_job("com.squirrelops.helper")

    def test_unknown_launchd_error_is_not_absence(self):
        with patch.object(self.session, "command", return_value=subprocess.CompletedProcess([], 1, "", "permission denied")):
            with self.assertRaisesRegex(RuntimeError, "uncertain"):
                self.session.service_loaded("com.squirrelops.helper")

    def test_reference_is_private_numeric_and_exact(self):
        self.assertEqual(module.parse_reference("12345\n"), "12345")
        self.assertTrue(module.reference_present("501 12345 timestamp", "12345"))
        self.assertFalse(module.reference_present("501 9123456 timestamp", "12345"))
        for value in ("", "1 2", "Token: 1", "1; -d", "1" * 21):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                module.parse_reference(value)

    def test_changed_process_is_not_signaled(self):
        self.session.identities[27646] = "original"
        with patch.object(self.session, "process_identity", return_value="replacement"), \
                patch.object(module.os, "kill") as kill:
            with self.assertRaisesRegex(RuntimeError, "snapshot"):
                self.session.terminate_recorded(27646)
        kill.assert_not_called()

    def test_distnoted_cannot_be_signaled(self):
        with patch.object(module.os, "kill") as kill:
            with self.assertRaisesRegex(RuntimeError, "two recorded"):
                self.session.terminate_recorded(27648)
        kill.assert_not_called()

    def test_runtime_graceful_exit(self):
        self.session.identities[27646] = "original"
        with patch.object(self.session, "process_identity", side_effect=["original", "original", None]), \
                patch.object(module.os, "kill") as kill, patch.object(module.time, "sleep"):
            self.session.terminate_recorded(27646)
        kill.assert_called_once_with(27646, module.signal.SIGTERM)

    def test_runtime_timeout_never_force_kills(self):
        self.session.identities[27646] = "original"
        with patch.object(self.session, "process_identity", return_value="original"), \
                patch.object(module.os, "kill") as kill, \
                patch.object(module.time, "monotonic", side_effect=[0, 46]):
            with self.assertRaisesRegex(RuntimeError, "no force-kill"):
                self.session.terminate_recorded(27646)
        kill.assert_called_once_with(27646, module.signal.SIGTERM)

    def test_recorded_pid_with_wrong_uid_or_path_is_rejected(self):
        for stdout in ("501 " + module.GUEST, "309 /usr/sbin/sshd"):
            with self.subTest(stdout=stdout), patch.object(self.session, "command", return_value=
                    subprocess.CompletedProcess([], 0, stdout, "")), self.assertRaisesRegex(RuntimeError, "identity changed"):
                self.session.process_identity(27646)

    def test_new_service_process_prevents_cleanup(self):
        with patch.object(self.session, "command", return_value=subprocess.CompletedProcess([], 0, "999\n", "")):
            with self.assertRaisesRegex(RuntimeError, "New service process"):
                self.session.verify_processes()

    @staticmethod
    def records():
        return [
            {"command": module.LISTENERS, "exit": 0, "stdout":
             "u0\nn*:22\nn*:445\nn*:5900\nu501\nn192.168.1.115:11434\nn127.0.0.1:49199\n", "stderr": ""},
            {"command": ["/sbin/pfctl", "-E"], "exit": 0, "stdout": "Token : 12345\n", "stderr": ""},
            {"command": ["/usr/sbin/installer", "-pkg", "/private/var/root/squirrelops-mini-acceptance.fixture/candidate.pkg",
                         "-target", "/"], "exit": 0, "stdout": "", "stderr": ""}]

    def test_baseline_reference_binding(self):
        self.assertEqual(len(module.recover_baseline(self.records(), "12345")), 5)
        with self.assertRaisesRegex(RuntimeError, "acquisition"):
            module.recover_baseline(self.records(), "987")

    def test_prior_release_or_failed_install_is_not_retried(self):
        records = self.records()
        records.append({"command": ["/sbin/pfctl", "-X", "12345"]})
        with self.assertRaisesRegex(RuntimeError, "release was attempted"):
            module.recover_baseline(records, "12345")
        records = self.records()
        records[-1]["exit"] = 1
        with self.assertRaisesRegex(RuntimeError, "installer evidence"):
            module.recover_baseline(records, "12345")

    def exercise_cleanup(self, fail=None):
        session = self.session
        session.token = "12345"
        events = []
        released = False
        owned_calls = 0

        def record(name):
            events.append(name)
            if fail == name:
                raise RuntimeError("injected " + name)

        def command(args, **kwargs):
            nonlocal released
            if args == module.LISTENERS:
                return subprocess.CompletedProcess(args, 0, "u501\nn*:22\n", "")
            self.assertEqual(args, ["/sbin/pfctl", "-X", "12345"])
            record("release")
            released = True
            return subprocess.CompletedProcess(args, 0, "", "")

        def owned():
            nonlocal owned_calls
            owned_calls += 1
            return ["192.168.1.240"] if owned_calls == 1 else []

        def pf(args):
            return ("PID TOKEN TIME\n501 12345 now\n" if not released else "PID TOKEN TIME\n") \
                if args == ["-s", "References"] else "Status: Disabled\n"

        with ExitStack() as stack:
            replacements = {
                "publish": lambda phase, **fields: record(phase),
                "service_loaded": lambda label: False,
                "verify_processes": lambda: record("process_check"),
                "terminate_recorded": lambda pid: record("terminate_" + str(pid)),
                "process_identity": lambda pid: None,
                "command": command,
                "owned": owned,
                "rpc": lambda method, params: record(method),
                "assert_no_test_network": lambda: record("network_absent"),
                "stop_job": lambda label: record("helper_stopped"),
                "inspect_empty_pf": lambda: record("empty_pf"),
                "verify_host_baseline": lambda: record("host_parity"),
                "pf": pf,
            }
            for name, replacement in replacements.items():
                stack.enter_context(patch.object(session, name, side_effect=replacement))
            stack.enter_context(patch("builtins.print"))
            if fail:
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    session.cleanup_runtime()
            else:
                session.cleanup_runtime()
        return events

    def test_release_is_last_after_guards_withdrawal_and_parity(self):
        events = self.exercise_cleanup()
        ordered = ["terminate_27646", "terminate_27647", "setupPortForwards", "removeIPAlias",
                   "network_absent", "clearPortForwards", "helper_stopped", "empty_pf", "host_parity", "release", "stopped"]
        positions = [events.index(name) for name in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIsNone(self.session.token)

    def test_each_incomplete_step_preserves_reference_and_no_success(self):
        for step in ("process_check", "terminate_27646", "terminate_27647", "setupPortForwards",
                     "removeIPAlias", "network_absent", "clearPortForwards", "helper_stopped", "empty_pf", "host_parity"):
            with self.subTest(step=step):
                events = self.exercise_cleanup(fail=step)
                self.assertNotIn("release", events)
                self.assertNotIn("stopped", events)
                self.assertEqual(self.session.token, "12345")

    def test_restarted_sensor_prevents_any_signal_or_rpc(self):
        with patch.object(self.session, "publish"), patch.object(self.session, "service_loaded", return_value=True), \
                patch.object(self.session, "terminate_recorded") as terminate, patch.object(self.session, "rpc") as rpc:
            with self.assertRaisesRegex(RuntimeError, "Sensor restarted"):
                self.session.cleanup_runtime()
        terminate.assert_not_called()
        rpc.assert_not_called()

    def test_plan_mode_has_no_host_calls(self):
        with patch.object(module.os, "kill") as kill, patch.object(module.base.subprocess, "run") as run, \
                patch("sys.argv", ["mini_cleanup.py"]), patch("builtins.print"):
            module.main()
        kill.assert_not_called()
        run.assert_not_called()

    def test_timeout_output_redacts_private_reference(self):
        self.session.token = "123456789012345"
        self.session.public = Path("/unused-public")
        error = subprocess.TimeoutExpired(["/sbin/pfctl", "-X", self.session.token], 30)
        with patch.object(self.session, "preflight_cleanup", side_effect=error), \
                patch.object(self.session, "publish") as publish, patch("builtins.print") as output, \
                patch.object(module.os, "umask"):
            with self.assertRaises(SystemExit):
                self.session.run_cleanup()
        self.assertNotIn(self.session.token, str(publish.call_args_list) + str(output.call_args_list))


if __name__ == "__main__":
    unittest.main()
