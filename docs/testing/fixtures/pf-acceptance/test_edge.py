"""Offline contracts for the approved bounded TCP-edge fixture."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class ResetGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.guard = module("edge_guard")

    def test_plan_is_exactly_two_drop_rules_with_kernel_expiration(self):
        text = self.guard.rules("a" * 12)
        self.assertEqual(text.count("add rule "), 2)
        self.assertIn("42839 timeout 80s", text)
        self.assertIn("42840 timeout 80s", text)
        for value in ("192.168.1.239 tcp sport 42839 tcp dport 22",
                      "192.168.1.240 tcp sport 42840 tcp dport 445"):
            self.assertIn(value, text)
        self.assertEqual(text.count("tcp flags & rst == rst tcp sport @live_ports counter drop"), 2)
        self.assertNotIn("flush", text)
        self.assertNotIn("192.168.1.241", text)
        for value in ("", "..", "x" * 12, "a" * 12 + ";flush ruleset"):
            with self.assertRaises(ValueError):
                self.guard.rules(value)

    def test_canonical_baseline_ignores_only_runtime_counters_and_handles(self):
        before = {"nftables": [{"metainfo": {"version": "x"}}, {"rule": {
            "family": "ip", "table": "existing", "chain": "out", "handle": 4,
            "expr": [{"counter": {"packets": 1, "bytes": 60}}, {"drop": None}]}}]}
        after = {"nftables": [{"rule": {"family": "ip", "table": "existing", "chain": "out", "handle": 9,
                                      "expr": [{"counter": {"packets": 4, "bytes": 240}}, {"drop": None}]}}]}
        self.assertEqual(self.guard.canonical(before), self.guard.canonical(after))
        after["nftables"][0]["rule"]["expr"][-1] = {"accept": None}
        self.assertNotEqual(self.guard.canonical(before), self.guard.canonical(after))

    def test_lifeline_eof_invokes_cleanup_without_waiting_for_deadline(self):
        reader, writer = os.pipe()
        try:
            os.close(writer)
            cleanup = Mock()
            self.guard.supervise(reader, 100, cleanup, now=lambda: 0)
            cleanup.assert_called_once()
        finally:
            os.close(reader)

    def test_deadline_invokes_cleanup_without_lifeline_eof(self):
        reader, writer = os.pipe()
        try:
            cleanup = Mock()
            self.guard.supervise(reader, 5, cleanup, now=lambda: 6)
            cleanup.assert_called_once()
        finally:
            os.close(reader)
            os.close(writer)

    def test_real_detached_watchdog_cleans_on_pipe_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "cleaned"
            code = ("import importlib.util,time;from pathlib import Path;"
                    "s=importlib.util.spec_from_file_location('guard'," + repr(self.guard.__file__) + ");"
                    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                    "print('ready',flush=True);"
                    "m.supervise(0,time.monotonic()+5,lambda:Path(" + repr(str(marker)) + ").write_text('cleaned'))")
            child = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-u", "-c", code],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, start_new_session=True)
            try:
                self.assertEqual(child.stdout.readline(), b"ready\n")
                child.stdin.close()
                child.wait(timeout=2)
                self.assertEqual(child.returncode, 0)
                self.assertEqual(marker.read_text(), "cleaned")
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=2)
                child.stdout.close()

    def test_cleanup_only_deletes_owned_unchanged_table_once(self):
        with tempfile.TemporaryDirectory() as directory:
            session = self.guard.Guard(Path(directory), "a" * 12)
            session.initial = {"nftables": []}
            session.owned = {"nftables": [{"table": {"family": "ip", "name": session.table, "handle": 42}}]}
            session.add_attempted = True
            session.snapshot = Mock(side_effect=[session.owned, session.initial])
            session.run = Mock()
            session.cleanup()
            self.assertEqual(session.run.call_args.args[0], ["delete", "table", "ip", session.table])
            self.assertTrue(session.cleaned)
            with self.assertRaisesRegex(RuntimeError, "already attempted"):
                session.cleanup()
            session.run.assert_called_once()

    def test_ambiguous_add_is_not_retried_or_deleted_without_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            session = self.guard.Guard(Path(directory), "a" * 12)
            session.initial = {"nftables": []}
            session.add_attempted = True
            session.snapshot = Mock(return_value={"nftables": [{"table": {
                "family": "ip", "name": session.table, "handle": 42}}]})
            session.run = Mock()
            with self.assertRaisesRegex(RuntimeError, "ownership"):
                session.cleanup()
            session.run.assert_not_called()

    def test_changed_owned_rule_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            session = self.guard.Guard(Path(directory), "a" * 12)
            session.initial = {"nftables": []}
            session.owned = {"nftables": [{"table": {"family": "ip", "name": session.table, "handle": 42}}]}
            session.add_attempted = True
            session.snapshot = Mock(return_value={"nftables": [{"table": {
                "family": "ip", "name": session.table, "handle": 43}}]})
            session.run = Mock()
            with self.assertRaisesRegex(RuntimeError, "ownership"):
                session.cleanup()
            session.run.assert_not_called()


class EdgeContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = module("edge_client")
        cls.runner = module("edge_runner")

    def test_raw_syns_use_only_reserved_tuples_and_valid_checksums(self):
        for index, (ip, port, source_port) in enumerate(self.client.TARGETS):
            data = self.client.syn_packet(index)
            self.assertEqual(len(data), 40)
            self.assertEqual(self.client.base.checksum(data[:20]), 0)
            pseudo = data[12:20] + struct.pack("!BBH", 0, 6, 20)
            self.assertEqual(self.client.base.checksum(pseudo + data[20:]), 0)
            self.assertEqual(socket.inet_ntoa(data[12:16]), "192.168.1.7")
            self.assertEqual(socket.inet_ntoa(data[16:20]), ip)
            self.assertEqual(struct.unpack("!HH", data[20:24]), (source_port, port))
            self.assertEqual(data[33], 2)
        with self.assertRaises(ValueError):
            self.client.syn_packet(2)

    def test_response_export_has_no_payload_and_rejects_unrelated_sources(self):
        packet = bytearray(self.client.syn_packet(0))
        packet[12:16], packet[16:20] = packet[16:20], packet[12:16]
        packet[20:22], packet[22:24] = packet[22:24], packet[20:22]
        packet[33] = 18
        result = self.client.response_metadata(bytes(packet) + b"DO NOT EXPORT")
        self.assertEqual(result["ip"], "192.168.1.239")
        self.assertEqual(result["flags"], 18)
        self.assertNotIn("DO NOT", str(result))
        packet[12:16] = socket.inet_aton("192.168.1.241")
        self.assertIsNone(self.client.response_metadata(packet))

    def test_half_open_state_requires_exact_reserved_tuple_and_incomplete_handshake(self):
        row = {"endpoints": [{"ip": "192.168.1.239", "port": 61322},
                             {"ip": "192.168.1.7", "port": 42839}], "state": "SYN_SENT:SYN_RCVD"}
        self.assertTrue(self.runner.half_open([row], 0))
        self.assertFalse(self.runner.half_open([row], 1))
        self.assertFalse(self.runner.half_open([{**row, "state": "ESTABLISHED:ESTABLISHED"}], 0))
        self.assertFalse(self.runner.half_open([{**row, "state": "TIME_WAIT:TIME_WAIT"}], 0))

    def test_ambiguity_inventory_retains_both_processes(self):
        text = "p100\nu309\nn192.168.1.239:61322\np200\nu309\nn*:61322\np1\nu0\nn*:22\n"
        self.assertEqual(self.runner.listener_records(text), [
            {"pid": 100, "uid": 309, "endpoint": "192.168.1.239:61322"},
            {"pid": 200, "uid": 309, "endpoint": "*:61322"}])

    def test_client_and_runner_phases_match(self):
        self.assertEqual(self.client.PHASES, self.runner.PHASES)

    def test_plan_commands_do_not_create_sockets_or_processes(self):
        with patch.object(self.client.socket, "socket") as sockets, \
                patch.object(self.client.subprocess, "Popen") as spawn:
            self.assertEqual(self.client.main([]), 0)
            self.assertEqual(self.runner.main([]), 0)
        sockets.assert_not_called()
        spawn.assert_not_called()

    def test_full_edge_sequence_without_network_mutation(self):
        runner = self.runner
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            session = runner.EdgeSession(root)
            session.public = root
            session.spawn = Mock()
            session.stop_children = Mock()
            session.children = []
            session.bind_observation = Mock(return_value=[{"pid": i} for i in range(4)])
            session.create_child = Mock(side_effect=[(Mock(), {"event": "bind_failed", "errno": 48}),
                (Mock(), {"event": "bind_failed", "errno": 48}),
                *[(Mock(), {"event": "ready"}) for _ in range(4)]])
            session.rpc = Mock(side_effect=lambda op: {"ok": op not in ("listener_check", "fail_load_first_kill"),
                "alias_authorized": [op != "fail_load_first_kill"] * 2})
            def states(phase, *_):
                if phase == "edge_healthy":
                    return [{"endpoints": [{"ip": ip, "port": port}], "state": "ESTABLISHED:ESTABLISHED"}
                            for ip, port in zip(runner.base.IPS, runner.base.PORTS)]
                if phase == "half_open_start":
                    return [{"endpoints": [{"ip": ip, "port": port}, {"ip": runner.base.PEER, "port": source}],
                             "state": "SYN_SENT:SYN_RCVD"}
                            for ip, port, source in zip(runner.base.IPS, runner.base.PORTS, runner.SOURCE_PORTS)]
                return []
            session.wait_probes = Mock(side_effect=states)
            session.exercise()
            self.assertEqual([call.args[0] for call in session.wait_probes.call_args_list], list(runner.PHASES))
            self.assertEqual(json.loads((root / "ambiguity-result.json").read_text()),
                             {"coexistence_observed": True, "guard_rejection_verified": True, "published": False})

    def test_guard_failure_does_not_authorize_more_raw_probes(self):
        with tempfile.TemporaryDirectory() as directory:
            client = self.client.EdgeClient(Path(directory))
            client.guard = Mock()
            client.guard.poll.return_value = 1
            client.send = Mock()
            with self.assertRaisesRegex(RuntimeError, "no longer active"):
                client.raw_probes()
            client.send.sendto.assert_not_called()

    def test_failed_healthy_control_preserves_the_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            client = self.client.EdgeClient(Path(directory))
            result = {"ip": "192.168.1.239", "port": 22, "error": "TimeoutError"}
            with patch.object(self.client.base, "fresh", return_value=(result, None)):
                with self.assertRaisesRegex(RuntimeError, "Healthy control failed"):
                    client.phase("edge_healthy")
            self.assertEqual(client.partial, {"connections": [result]})

    def test_closed_listener_keeps_established_socket_alive(self):
        python = os.environ.get("SQUIRRELOPS_DIAGNOSTIC_CHILD_PYTHON", sys.executable)
        child = subprocess.Popen([python, "-I", "-S", "-B", "-u",
            str(Path(__file__).with_name("edge_child.py")), "127.0.0.1", "0", "127.0.0.1",
            str(time.clock_gettime(time.CLOCK_MONOTONIC) + 20), "0"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        try:
            ready = self.runner.base.read_line(child, 3)
            self.assertEqual(ready["event"], "ready")
            with socket.create_connection(("127.0.0.1", ready["port"]), timeout=2) as stream:
                self.assertEqual(stream.recv(64), ("A5 uid=%s\n" % os.getuid()).encode())
                self.assertEqual(self.runner.base.read_line(child, 3)["event"], "accepted")
                child.stdin.write(b'{"op":"close_listener"}\n')
                self.assertEqual(self.runner.base.read_line(child, 3)["clients"], 1)
                stream.sendall(b"A5-PING\n")
                self.assertEqual(stream.recv(64), ("A5-PONG uid=%s\n" % os.getuid()).encode())
                self.assertEqual(self.runner.base.read_line(child, 3)["event"], "echo")
                stream.shutdown(socket.SHUT_WR)
                self.assertEqual(stream.recv(64), b"")
        finally:
            self.runner.base.stop_child(child)
            self.assertEqual(child.returncode, 0, child.stderr.read())
            child.stdout.close()
            child.stderr.close()


if __name__ == "__main__":
    unittest.main()
