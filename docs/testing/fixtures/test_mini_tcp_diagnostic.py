"""Disposable loopback and injected guard tests. No root or remote operations."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("diagnostic", Path(__file__).with_name("mini_tcp_diagnostic.py"))
diag = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diag)


class Guards(unittest.TestCase):
    def test_changed_script_v3_banner(self):
        self.assertEqual(diag.BANNER, b"SquirrelOps TCP diagnostic v3\r\n")

    def test_shared_deadline_uses_explicit_os_clock(self):
        with patch.object(diag.time, "monotonic", side_effect=AssertionError("process-relative clock")), \
                patch.object(diag.time, "clock_gettime", return_value=1234.5) as shared:
            self.assertEqual(diag.clock(), 1234.5)
        shared.assert_called_once_with(time.CLOCK_MONOTONIC)

    def test_plan_does_not_run_commands(self):
        with patch.object(diag.subprocess, "run") as run, patch.object(diag.subprocess, "Popen") as popen:
            self.assertEqual(diag.main([]), 0)
        run.assert_not_called()
        popen.assert_not_called()

    def test_command_allowlist_has_no_mutations(self):
        with tempfile.TemporaryDirectory() as folder:
            session = diag.Session(Path(folder))
            for key in ("installer", "bootout", "pf-enable", "arbitrary"):
                with self.subTest(key=key), patch.object(diag.subprocess, "run") as run:
                    with self.assertRaisesRegex(RuntimeError, "Unknown observation"):
                        session.observe(key)
                    run.assert_not_called()
        pf = [v for v in diag.COMMANDS.values() if v[0] == "/sbin/pfctl"]
        self.assertEqual(pf, [["/sbin/pfctl", "-s", "info"], ["/sbin/pfctl", "-sr"], ["/sbin/pfctl", "-sn"]])

    def test_snapshot_guards(self):
        baseline = valid_snapshot()
        diag.validate_snapshot(baseline)
        cases = {"build": "different", "architecture": "x86_64", "address": "192.168.1.5",
                 "en0": baseline["en0"].replace(diag.ETHER, "00:00:00:00:00:00"),
                 "route": "interface: en1", "interfaces": "inet 192.168.1.240 netmask x",
                 "arp": "? (192.168.1.241) at 00:01:02:03:04:05 permanent published",
                 "pf": "Status: Enabled\n", "processes": "31 309 /Library/SquirrelOps/sensor/python/bin/python3.12 -m squirrelops_home_sensor"}
        for key, value in cases.items():
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                diag.validate_snapshot(dict(baseline, **{key: value}))

    def test_launchd_absence_requires_exact_diagnostic(self):
        diag.require_unloaded(113, '', 'Could not find service "com.squirrelops.sensor" in domain for system', "com.squirrelops.sensor")
        for code, error in ((0, ""), (1, "permission denied"), (113, "could not connect")):
            with self.subTest(code=code, error=error), self.assertRaises(RuntimeError):
                diag.require_unloaded(code, "", error, "com.squirrelops.sensor")

    def test_accounts_must_match_both_uid_and_gid(self):
        diag.validate_accounts([(309, 309), (501, 20)])
        for accounts in ([(309, 20), (501, 20)], [(310, 309), (501, 20)], [(309, 309), (0, 0)]):
            with self.assertRaises(RuntimeError):
                diag.validate_accounts(accounts)

    def test_runtime_file_trust(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "runtime"
            path.write_bytes(b"fixture")
            path.chmod(0o600)
            # Fixtures are not root-owned: an explicit expected owner is test-only.
            diag.trusted(path, owner=os.getuid())
            path.chmod(0o666)
            with self.assertRaises(RuntimeError):
                diag.trusted(path, owner=os.getuid())
            path.chmod(0o600)
            link = Path(folder) / "link"
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                diag.trusted(link, owner=os.getuid())
            with self.assertRaises(RuntimeError):
                diag.trusted(path, owner=os.getuid() + 1)

    def test_runtime_digest_drift_refuses(self):
        with patch.object(diag, "trusted"), patch.object(diag.Path, "read_bytes", return_value=b"changed"):
            with self.assertRaisesRegex(RuntimeError, "Pinned runtime changed"):
                diag.validate_runtime()

    def test_readiness_pins_identity_address_and_ports(self):
        row = dict(event="ready", pid=123, uid=309, gid=309, address=diag.ADDRESS, port=52000)
        diag.validate_ready(row, 123, (309, 309), set())
        for key, value in (("pid", 9), ("uid", 0), ("gid", 0), ("port", 22), ("port", 65536), ("address", "0.0.0.0")):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                diag.validate_ready(dict(row, **{key: value}), 123, (309, 309), set())
        with self.assertRaises(RuntimeError):
            diag.validate_ready(row, 123, (309, 309), {52000})

    def test_spawn_drops_privileges_before_python(self):
        with tempfile.TemporaryDirectory() as folder:
            session = diag.Session(Path(folder))
            with patch.object(diag.subprocess, "Popen") as popen:
                for uid, gid in diag.ACCOUNTS:
                    session.spawn(uid, gid, diag.clock() + 10)
                    args, kwargs = popen.call_args
                    self.assertEqual(args[0][:5], [diag.PYTHON, "-I", "-S", "-B", "-u"])
                    self.assertEqual((kwargs["user"], kwargs["group"], kwargs["extra_groups"]), (uid, gid, []))
                    self.assertTrue(kwargs["start_new_session"])
                    self.assertFalse(kwargs.get("shell", False))
            for handle in session.logs:
                handle.close()

    def test_cleanup_reaps_both_even_when_first_fails(self):
        first, second = Mock(), Mock()
        with patch.object(diag, "stop_child", side_effect=[RuntimeError("first"), None]) as stop:
            errors = diag.stop_all([first, second])
        self.assertEqual(stop.call_count, 2)
        self.assertEqual(len(errors), 1)

    def test_partial_startup_stops_first_child_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)
            public = root / "public"
            public.mkdir()
            session = diag.Session(root)
            before = valid_snapshot()
            before.update(listeners="p1\nu0\nn*:22\nn*:445\nn*:5900\np2\nu501\nn192.168.1.115:11434\n",
                          pf_rules="anchor com.apple", pf_nat="rdr-anchor com.apple")
            stack.enter_context(patch.object(session, "preflight", return_value=before))
            stack.enter_context(patch.object(session, "baseline", return_value=before))
            stack.enter_context(patch.object(diag.tempfile, "mkdtemp", return_value=str(public)))
            stack.enter_context(patch.object(diag.signal, "signal"))
            first = Mock(pid=123, returncode=0)
            def spawn(*args):
                if not session.children:
                    session.children.append(first)
                    return first
                raise RuntimeError("second child failed")
            stack.enter_context(patch.object(session, "spawn", side_effect=spawn))
            stack.enter_context(patch.object(diag, "read_line", return_value=json.dumps(dict(
                event="ready", pid=123, uid=309, gid=309, address=diag.ADDRESS, port=52000))))
            stop = stack.enter_context(patch.object(diag, "stop_child"))
            self.assertEqual(session.run(), 1)
            stop.assert_called_once_with(first)
            status = json.loads((public / "status.json").read_text())
            self.assertEqual(status["phase"], "needs_review")
            self.assertIn("second child failed", status["errors"])
            self.assertTrue(status["baseline_verified"])

    def test_cleanup_escalates_only_for_direct_unreaped_child(self):
        child = Mock()
        child.stdin.closed = False
        child.wait.side_effect = [subprocess.TimeoutExpired("probe", 2), subprocess.TimeoutExpired("probe", 2), 0]
        diag.stop_child(child)
        child.terminate.assert_called_once()
        child.kill.assert_called_once()
        self.assertEqual(child.wait.call_count, 3)

    def test_cleanup_closes_lifeline_and_waits(self):
        child = Mock()
        child.stdin.closed = False
        diag.stop_child(child)
        child.stdin.close.assert_called_once()
        child.wait.assert_called_once_with(timeout=2)
        child.terminate.assert_not_called()

    def test_scoped_socket_rows_do_not_expose_unrelated_rows(self):
        rows = "tcp4 0 0 192.168.1.115.52000 192.168.1.7.43000 ESTABLISHED\ntcp4 0 0 192.168.1.115.22 192.168.1.8.10000 ESTABLISHED\n"
        self.assertEqual(len(diag.scoped_rows(rows, [52000])), 1)
        self.assertEqual(diag.scoped_rows(rows, [52001]), [])


def valid_snapshot():
    return dict(build="26A428", architecture="arm64", address=diag.ADDRESS,
                en0="ether " + diag.ETHER, route="interface: en0", interfaces="inet 192.168.1.115 netmask x",
                arp="", pf="Status: Disabled\n", processes="1 0 /sbin/launchd")


class RealChild(unittest.TestCase):
    def start(self, peer="127.0.0.1", duration=3):
        child_python = os.environ.get("SQUIRRELOPS_DIAGNOSTIC_CHILD_PYTHON", sys.executable)
        process = subprocess.Popen([child_python, "-I", "-S", "-B", "-u", "-c", diag.CHILD,
                                    "127.0.0.1", peer, str(diag.clock() + duration)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.cleanup, process)
        try:
            ready = json.loads(diag.read_line(process, 2))
        except RuntimeError:
            if process.poll() is not None:
                self.fail(process.stderr.read().decode())
            raise
        return process, ready["port"]

    @staticmethod
    def cleanup(process):
        diag.stop_child(process)
        process.stdout.close()
        process.stderr.close()

    def test_fixed_banner_and_no_client_payload_required(self):
        process, port = self.start()
        with socket.create_connection(("127.0.0.1", port), timeout=1) as stream:
            self.assertEqual(stream.recv(100), diag.BANNER)
        row = json.loads(diag.read_line(process, 1))
        self.assertEqual(row["event"], "banner_sent")

    def test_other_peer_is_closed_without_response(self):
        _, port = self.start(peer="127.0.0.2")
        with socket.create_connection(("127.0.0.1", port), timeout=1) as stream:
            self.assertEqual(stream.recv(100), b"")

    def test_deadline_closes_listener(self):
        started = time.monotonic()
        process, port = self.start(duration=0.5)
        process.wait(timeout=2)
        self.assertGreaterEqual(time.monotonic() - started, 0.45)
        self.assertLess(time.monotonic() - started, 1.5)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=0.2)

    def test_lifeline_eof_closes_listener(self):
        process, port = self.start()
        process.stdin.close()
        process.wait(timeout=2)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=0.2)

    def test_readiness_timeout_is_bounded(self):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.cleanup, process)
        with self.assertRaisesRegex(RuntimeError, "readiness timeout"):
            diag.read_line(process, 0.1)


if __name__ == "__main__":
    unittest.main()
