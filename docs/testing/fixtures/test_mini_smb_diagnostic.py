"""SMB-only diagnostic boundaries; no product or LAN traffic in these tests."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


c = load("mini_smb_diagnostic_client")
w = load("mini_smb_diagnostic_window")


class ClientTests(unittest.TestCase):
    def inputs(self):
        status = dict(phase="ready_for_tests", diagnostic_scope=c.SCOPE,
                      test_scope="mini-relay-diagnostics-240", test_vips=[c.VIP],
                      boot_seconds=1790777754, sensor_uid=309, package_sha256=c.PACKAGE_SHA,
                      configuration_unchanged=True, config_change_verified=True,
                      time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), remaining_seconds=1100)
        endpoints = dict(guest_ip=c.VIP, mappings=[
            dict(ip=c.VIP, port=port, backend=50000 + index)
            for index, port in enumerate((22, 445, 1234, 11434, 8765))])
        return endpoints, status

    def test_fresh_exact_inputs_and_drift_rejection(self):
        endpoints, status = self.inputs()
        c.validate_inputs(endpoints, status, time.time())
        for field, value in (("phase", "stopped"), ("diagnostic_scope", "other"),
                             ("package_sha256", "other"), ("boot_seconds", 0),
                             ("remaining_seconds", 599), ("sensor_uid", 0),
                             ("configuration_unchanged", False), ("config_change_verified", False),
                             ("test_scope", "other"), ("test_vips", ["192.168.1.241"]),
                             ("time", "2026-09-30T11:00:00Z")):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                c.validate_inputs(endpoints, {**status, field: value}, time.time())
        for bad in ({**endpoints, "guest_ip": "192.168.1.241"},
                    {**endpoints, "mappings": endpoints["mappings"][:-1]},
                    {**endpoints, "mappings": endpoints["mappings"] + endpoints["mappings"][:1]}):
            with self.assertRaises(RuntimeError):
                c.validate_inputs(bad, status, time.time())

    def test_one_fixed_anonymous_smb_command_no_credential_reuse(self):
        args = c.command()
        self.assertEqual(args[0], "/usr/bin/smbclient")
        self.assertEqual(args[args.index("-L") + 1], "//192.168.1.240")
        self.assertEqual(args[args.index("-p") + 1], "445")
        self.assertEqual(args[args.index("-I") + 1], "192.168.1.240")
        self.assertEqual(args[args.index("-U") + 1], "%")
        self.assertIn("--use-kerberos=off", args)
        self.assertIn("--configfile=/dev/null", args)
        self.assertNotIn("-c", args)
        self.assertNotIn("login.json", Path(c.__file__).read_text())

    def test_sanitized_events_do_not_copy_untrusted_text(self):
        raw = ("secret=do-not-export\nConnecting to 192.168.1.240 at port 445\n"
               "negotiated dialect[SMB3_11] against [private-host]\n"
               "Anonymous login successful\nSharename Type Comment\n"
               " Engineering Disk private-comment\n Builds Disk secret\n"
               "session setup failed: NT_STATUS_LOGON_FAILURE\n")
        events = c.classify(raw)
        self.assertIn({"stage": "connect_attempt"}, events)
        self.assertIn({"stage": "dialect", "value": "SMB3_11"}, events)
        self.assertIn({"stage": "anonymous_session"}, events)
        self.assertIn({"stage": "share_seen", "value": "Engineering"}, events)
        self.assertIn({"stage": "status", "value": "NT_STATUS_LOGON_FAILURE"}, events)
        self.assertNotRegex(json.dumps(events), "secret|private-host|private-comment|do-not-export")

    def test_capture_is_timed_and_private_raw_output_is_bounded(self):
        events = []
        raw = io.StringIO()
        result = c.capture([sys.executable, "-u", "-c", "import time; print('Anonymous login successful'); time.sleep(10)"],
                           raw, events.append, duration=0.15)
        self.assertTrue(result["timed_out"])
        self.assertLess(result["elapsed_seconds"], 3)
        self.assertTrue(any(event.get("stage") == "anonymous_session" for event in events))
        self.assertIn("elapsed_seconds", json.loads(raw.getvalue().splitlines()[0]))

    def test_output_budget_stops_only_child(self):
        result = c.capture([sys.executable, "-c", "print('x' * 200000)"], io.StringIO(), lambda _row: None,
                           duration=2, byte_limit=4096)
        self.assertTrue(result["output_limited"])
        self.assertLessEqual(result["captured_bytes"], 4096)

    def test_normal_exit_and_fragmented_share_lines(self):
        events = []
        script = "import os,time; os.write(1,b'  Engineer'); time.sleep(.02); os.write(1,b'ing Disk\\n Builds Disk\\n')"
        result = c.capture([sys.executable, "-c", script], io.StringIO(), events.append, duration=2)
        self.assertEqual(result["exit"], 0)
        self.assertFalse(result["timed_out"] or result["output_limited"])
        self.assertEqual({row["value"] for row in events if row["stage"] == "share_seen"}, {"Engineering", "Builds"})

    def test_stdout_eof_does_not_terminate_a_normally_exiting_client(self):
        script = "import os,time; os.close(1); os.close(2); time.sleep(.1)"
        result = c.capture([sys.executable, "-c", script], io.StringIO(), lambda _row: None, duration=2)
        self.assertEqual(result["exit"], 0)

    def test_exclusive_results_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.jsonl"
            with c.exclusive_result(path) as stream:
                stream.write("preserve\n")
            with self.assertRaises(FileExistsError):
                c.exclusive_result(path)
            self.assertEqual(path.read_text(), "preserve\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_plan_only_does_not_launch_client(self):
        result = subprocess.run([sys.executable, "-I", "-B", c.__file__], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["client_invocations"], 1)
        self.assertEqual(plan["max_seconds"], 45)
        self.assertFalse(plan["credentials"] or plan["file_operations"])


class WindowTests(unittest.TestCase):
    def test_receipt_pin_and_inherited_start_cleanup(self):
        path = Path(__file__).parents[1] / "evidence/2026-10-01-mini-filter-retest/cleanup-status.json"
        if not path.is_file():
            self.skipTest("Requires retained private Mini cleanup evidence")
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), w.CLEANUP_SHA)
        w.previous.validate_cleanup(json.loads(path.read_text()))
        for name in ("install", "stop", "release_reference", "observe"):
            self.assertIs(getattr(w.SMBDiagnostic, name), getattr(w.previous.FilterRetest, name))
        self.assertEqual(w.SMBDiagnostic.claim_prefix, "protocol-smb-diagnostic")

    def test_claim_cannot_resolve_other_backup(self):
        good = dict(package_sha256=w.relay.PACKAGE_SHA,
                    backup=str(w.BASE / "mini-filter-retest-20261001.fixture"))
        self.assertEqual(w.backup_from_claim(good).parent, w.BASE)
        for bad in ({**good, "package_sha256": "other"}, {**good, "backup": "/tmp/fixture"},
                    {**good, "backup": str(w.BASE / "mini-filter-retest-20261001.x/../secret")}, {}):
            with self.assertRaises(RuntimeError):
                w.backup_from_claim(bad)

    def test_drift_rejected_before_host_preflight(self):
        runner = w.SMBDiagnostic(Path("/tmp/fixture"))
        with patch.object(w.base, "safe_directory"), patch.object(w.base, "safe_file"), \
             patch.object(w, "CLAIM", Path(__file__)), \
             patch.object(Path, "read_text", return_value=json.dumps(dict(package_sha256=w.relay.PACKAGE_SHA,
                       backup=str(w.BASE / "mini-filter-retest-20261001.fixture")))), \
             patch.object(w.base, "digest", return_value="changed"), \
             patch.object(w.relay.RelayDiagnosticUpgrade, "preflight") as parent:
            with self.assertRaises(RuntimeError):
                runner.preflight()
            parent.assert_not_called()

    def test_adds_diagnostic_scope_without_replacing_cleanup(self):
        runner = w.SMBDiagnostic(Path("/tmp/fixture"))
        with patch.object(w.relay.RelayDiagnosticUpgrade, "publish") as publish:
            runner.publish("stopped", pf_enabled=False)
        publish.assert_called_once_with("stopped", diagnostic_scope=c.SCOPE, pf_enabled=False)

    def test_bootstrap_pins_every_input(self):
        root = Path(__file__).parent
        text = (root / "start-mini-smb-diagnostic.sh").read_text()
        names = re.search(r"for name in (.+); do", text).group(1).split()
        pins = dict(re.findall(r"^verify_digest (\S+) ([a-f0-9]{64})$", text, re.M))
        self.assertEqual(set(names), set(pins))
        self.assertEqual(set(pins), {*w.SMBDiagnostic.input_names, "candidate.pkg"})
        self.assertEqual(pins.pop("candidate.pkg"), w.relay.PACKAGE_SHA)
        for name, digest in pins.items():
            path = root / name
            if name == "approved-scope.md":
                path = root.parent / "2026-10-01-mini-smb-diagnostic-scope.md"
            elif name == "single-ip-config.yaml":
                path = root / "mini-single-ip-config.yaml"
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest, name)

    def test_window_plan_only(self):
        result = subprocess.run([sys.executable, "-I", "-B", w.__file__], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertFalse(plan["install"] or plan["third_party_filter_changes"])
        self.assertEqual(plan["diagnostic_scope"], c.SCOPE)


if __name__ == "__main__":
    unittest.main()
