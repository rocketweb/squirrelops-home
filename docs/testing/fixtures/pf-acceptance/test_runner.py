"""Offline safety contract. No PF mutation, remote session or installed job."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("pf_runner", Path(__file__).with_name("runner.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
CLIENT_SPEC = importlib.util.spec_from_file_location("pf_client", Path(__file__).with_name("client.py"))
client = importlib.util.module_from_spec(CLIENT_SPEC)
CLIENT_SPEC.loader.exec_module(client)


class Contracts(unittest.TestCase):
    def test_plan_has_no_side_effect(self):
        with patch.object(runner.subprocess, "run") as run, patch.object(runner.subprocess, "Popen") as spawn:
            self.assertEqual(runner.main([]), 0)
        run.assert_not_called()
        spawn.assert_not_called()

    def test_ack_only_advances_exact_current_phase(self):
        good = {"nonce": "a" * 12, "phase": "healthy", "action": "probes_done"}
        self.assertTrue(runner.valid_ack(good, "a" * 12, "healthy"))
        for altered in ({**good, "phase": "old"}, {**good, "nonce": "b" * 12},
                        {**good, "action": "run_command"}, {**good, "command": "id"}, None, []):
            self.assertFalse(runner.valid_ack(altered, "a" * 12, "healthy"))

    def test_policy_is_strict_but_accepts_observed_apple_hooks(self):
        runner.validate_policy('scrub-anchor "com.apple/*" all fragment reassemble\nanchor "com.apple/*" all', "")
        runner.validate_policy('anchor "200.AirDrop/*" all\nanchor "250.ApplicationFirewall/*" all', "com.apple")
        for policy in ('pass all', 'block all', 'anchor "*" all {', 'pfctl: DIOCGETRULES: Invalid argument',
                       'anchor "not-apple/*" all'):
            with self.subTest(policy=policy), self.assertRaises(RuntimeError):
                runner.validate_policy(policy, "")

    def test_anchor_paths_cannot_escape(self):
        self.assertEqual(runner.anchor_path("200.AirDrop", "com.apple"), "com.apple/200.AirDrop")
        for value in ("../x", "com.apple/../x", "*", "com.apple/x/y", "not-apple"):
            with self.assertRaises(RuntimeError):
                runner.anchor_path(value, "")

    def test_reference_release_requires_exact_token_and_is_never_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = runner.Session(Path(tmp))
            session.token = "123456"
            session.command = Mock(return_value=subprocess.CompletedProcess([], 0, "TOKENS:\n7 pfctl 123456 today\n", ""))
            session.release_reference()
            self.assertEqual(session.command.call_args_list[-1].args[0], ["/sbin/pfctl", "-X", "123456"])
            with self.assertRaisesRegex(RuntimeError, "already attempted"):
                session.release_reference()
        for text in ("No pf starter references held", "TOKENS:\n7 pfctl 91234567 today\n"):
            with tempfile.TemporaryDirectory() as tmp:
                session = runner.Session(Path(tmp))
                session.token = "123456"
                session.command = Mock(return_value=subprocess.CompletedProcess([], 0, text, ""))
                with self.assertRaises(RuntimeError):
                    session.release_reference()
                self.assertEqual(session.command.call_count, 1)

    def test_ambiguous_enable_is_not_retried_or_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = runner.Session(Path(tmp))
            session.command = Mock(side_effect=subprocess.TimeoutExpired("pfctl", 15))
            with self.assertRaises(subprocess.TimeoutExpired):
                session.enable_reference()
            self.assertTrue(session.enable_attempted)
            with self.assertRaises(RuntimeError):
                session.enable_reference()
            session.command.assert_called_once_with(["/sbin/pfctl", "-E"])

    def test_safe_read_refuses_symlinks_and_writable_root_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "file"
            path.write_text("test")
            path.chmod(0o600)
            self.assertEqual(runner.safe_read(path, os.getuid()), b"test")
            link = path.with_name("link")
            link.symlink_to(path)
            with self.assertRaises((RuntimeError, OSError)):
                runner.safe_read(link, os.getuid())
            path.chmod(0o666)
            with self.assertRaises(RuntimeError):
                runner.safe_read(path, os.getuid())

    def test_cleanup_does_not_release_if_alias_removal_uncertain(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = runner.Session(Path(tmp))
            session.enable_attempted = True
            session.token = "123"
            session.aliases = {runner.IPS[0]}
            session.rpc = Mock(return_value={"ok": True})
            session.stop_children = Mock()
            session.remove_aliases = Mock(side_effect=RuntimeError("alias uncertainty"))
            session.release_reference = Mock()
            session.publish = Mock()
            self.assertFalse(session.cleanup())
            session.release_reference.assert_not_called()

    def test_child_stop_failure_does_not_skip_quarantine(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = runner.Session(Path(tmp))
            session.enable_attempted = True
            session.stop_children = Mock(side_effect=RuntimeError("child uncertain"))
            session.rpc = Mock(return_value={"ok": True})
            session.release_reference = Mock()
            session.remove_aliases = Mock()
            session.publish = Mock()
            self.assertFalse(session.cleanup())
            session.rpc.assert_called_once_with("quarantine")
            session.remove_aliases.assert_not_called()
            session.release_reference.assert_not_called()

    def test_failure_injection_is_fixed_scope(self):
        source = Path(__file__).with_name("main.swift").read_text()
        self.assertIn('args[1] = anchor', source)
        self.assertIn('"-k", "0.0.0.0/0", "-k", ips[0]', source)
        self.assertNotIn('"-e"', source)
        self.assertNotIn('"-F"', source)
        self.assertIn('try quarantinePortForwardingAfterListenerRace(', source)
        self.assertIn('try requireUnusedVirtualIPAddress(', source)

    def test_complete_phase_sequence_without_kernel_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            public = root / "public"
            public.mkdir()
            session = runner.Session(root)
            for name in ("preflight", "record", "enable_reference", "add_aliases", "packet_capture",
                         "spawn", "stop_children", "held_services", "no_aliases", "preserve_files"):
                setattr(session, name, Mock())
            session.inventory_policy = Mock(return_value=None)
            session.wait_probes = Mock()
            session.cleanup = Mock(return_value=True)
            def rpc(op):
                bad = op.startswith("fail_") or op == "listener_check"
                return {"ok": not bad, "alias_authorized": [not bad, not bad]}
            session.rpc = Mock(side_effect=rpc)
            with patch.object(runner.tempfile, "mkdtemp", return_value=str(public)), \
                    patch.object(runner.os, "chown"), patch.object(runner.signal, "signal"):
                self.assertEqual(session.run(), 0)
            self.assertEqual([call.args[0] for call in session.wait_probes.call_args_list], list(runner.PHASES))
            session.cleanup.assert_called_once()

    def test_pf_reference_release_timeout_is_durably_marked_before_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = runner.Session(Path(tmp))
            session.token = "123456"
            def command(args):
                if args[-2:] == ["-X", "123456"]:
                    self.assertTrue(json.loads((Path(tmp) / "receipt.json").read_text())["release_attempted"])
                    raise subprocess.TimeoutExpired("pfctl", 20)
                return subprocess.CompletedProcess([], 0, "7 pfctl 123456 timestamp\n", "")
            session.command = Mock(side_effect=command)
            with self.assertRaises(subprocess.TimeoutExpired):
                session.release_reference()
            with self.assertRaisesRegex(RuntimeError, "already attempted"):
                session.release_reference()
            self.assertEqual(session.command.call_count, 2)

    def test_failed_enable_does_not_remove_unowned_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = runner.Session(Path(tmp))
            session.alias_attempts = {runner.IPS[0]}
            session.command = Mock()
            with self.assertRaisesRegex(RuntimeError, "ambiguous"):
                session.remove_aliases()
            session.command.assert_not_called()

    def test_children_are_privilege_dropped_and_fixed_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = runner.Session(Path(tmp))
            child = Mock(pid=123)
            def readiness(*unused):
                index = len(session.children) - 1
                return {"event": "ready", "pid": 123, "uid": 501, "gid": 20,
                        "address": runner.IPS[index], "port": runner.PORTS[index]}
            with patch.object(runner.subprocess, "Popen", return_value=child) as spawn, \
                    patch.object(runner, "read_line", side_effect=readiness):
                session.spawn(501)
            for index, call in enumerate(spawn.call_args_list):
                self.assertEqual(call.kwargs["user"], 501)
                self.assertEqual(call.kwargs["group"], 20)
                self.assertEqual(call.kwargs["extra_groups"], [])
                self.assertEqual(call.args[0][:5], [runner.PYTHON, "-I", "-S", "-B", "-u"])
                self.assertEqual(call.args[0][-4:-1], [runner.IPS[index], str(runner.PORTS[index]), runner.PEER])
            for handle in session.handles:
                handle.close()

    def test_loopback_handoff_configures_both_uids_and_no_pf_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = runner.Session(Path(tmp))
            session.spawn_child = Mock(return_value=42123)
            session.stop_children = Mock()
            session.command = Mock()
            stream = Mock()
            stream.recv.side_effect = [b"A5 uid=309\n", b"", b"A5 uid=501\n", b""]
            stream.__enter__ = Mock(return_value=stream)
            stream.__exit__ = Mock(return_value=False)
            with patch.object(runner.socket, "create_connection", return_value=stream):
                session.loopback_handoff()
            self.assertEqual([call.args for call in session.spawn_child.call_args_list],
                             [(309, "127.0.0.1", 0, "127.0.0.1"), (501, "127.0.0.1", 42123, "127.0.0.1")])
            self.assertEqual(session.stop_children.call_count, 2)
            self.assertEqual(stream.shutdown.call_count, 2)
            session.command.assert_not_called()

    def test_retained_state_gate_refuses_empty_or_other_endpoint_inventory(self):
        self.assertFalse(runner.has_retained_closing_state([]))
        row = {"endpoints": [{"ip": runner.IPS[0], "port": runner.PORTS[0]},
                             {"ip": runner.PEER, "port": 43000}], "state": "TIME_WAIT:TIME_WAIT"}
        self.assertTrue(runner.has_retained_closing_state([row]))
        self.assertFalse(runner.has_retained_closing_state([{**row, "state": "ESTABLISHED:ESTABLISHED"}]))
        self.assertFalse(runner.has_retained_closing_state([{**row, "endpoints": [
            {"ip": runner.IPS[1], "port": runner.PORTS[1]}, {"ip": runner.PEER, "port": 43000}]}]))

    def test_wrong_uid_phase_is_not_ready_without_retained_closing_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = runner.Session(Path(tmp))
            session.held_services = Mock()
            session.pf = Mock(return_value="Status: Enabled")
            session.evidence = Mock(return_value=[])
            session.publish = Mock()
            with self.assertRaisesRegex(RuntimeError, "reuse case not proven"):
                session.wait_probes("wrong_uid_retained_state")
            session.publish.assert_not_called()

    def test_child_factory_rejects_root_and_unapproved_addresses_before_spawn(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = runner.Session(Path(tmp))
            with patch.object(runner.subprocess, "Popen") as spawn:
                for values in ((0, "127.0.0.1", 0, "127.0.0.1"),
                               (501, "192.168.1.241", 61322, runner.PEER),
                               (309, "127.0.0.1", 61322, runner.PEER)):
                    with self.assertRaises(RuntimeError):
                        session.spawn_child(*values)
            spawn.assert_not_called()

    def test_root_writes_are_only_scoped(self):
        source = Path(__file__).with_name("runner.py").read_text()
        for forbidden in ('"-d"', '"-F"', '"bootout"', '"bootstrap"', '"kickstart"', '"installer"'):
            self.assertNotIn(forbidden, source)
        self.assertIn('["/sbin/pfctl", "-a", self.anchor, "-f", "-"]', source)
        self.assertIn('self.rpc("quarantine")', source)

    def test_public_packet_metadata_excludes_payload_and_unrelated_addresses(self):
        lines = [
            "2026-10-02 03:00:00.000001 IP 192.168.1.7.42739 > 192.168.1.239.22: Flags [S], seq 1, length 0",
            "2026-10-02 03:00:00.000002 IP 192.168.1.9.22 > 192.168.1.7.1234: Flags [P.], length 8",
            "payload-secret",
            "2026-10-02 03:00:00.000003 IP 192.168.1.240.61445 > 192.168.1.7.43000: Flags [P.], length 11",
        ]
        rows = runner.packet_metadata("\n".join(lines))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["source_port"], 42739)
        self.assertEqual(rows[0]["flags"], "S")
        self.assertNotIn("secret", json.dumps(rows))
        self.assertNotIn("192.168.1.9", json.dumps(rows))

    def test_public_states_only_include_approved_endpoints(self):
        source = ("all tcp 192.168.1.239:61322 (192.168.1.239:22) <- 192.168.1.7:43000 ESTABLISHED:ESTABLISHED\n"
                  "all tcp 192.168.1.239:61322 <- 192.168.1.9:43000 ESTABLISHED:ESTABLISHED\n"
                  "private arbitrary line\n")
        self.assertEqual(len(runner.scoped_states(source)), 1)

    def test_observed_macos_uppercase_prefix_and_closing_states_are_exported(self):
        # Numeric, synthetic reconstruction of the completed Mini export.
        source = ("ALL tcp 192.168.1.239:61322 <- 192.168.1.7:35301 ESTABLISHED:ESTABLISHED\n"
                  "ALL tcp 192.168.1.240:61445 <- 192.168.1.7:44733 FIN_WAIT_2:FIN_WAIT_2\n"
                  "en0 tcp 192.168.1.239:61322 <- 192.168.1.7:38657 TIME_WAIT:TIME_WAIT\n")
        rows = runner.scoped_states(source)
        self.assertEqual([row["state"] for row in rows],
                         ["ESTABLISHED:ESTABLISHED", "FIN_WAIT_2:FIN_WAIT_2", "TIME_WAIT:TIME_WAIT"])
        self.assertEqual(rows[1]["endpoints"][1], {"ip": runner.PEER, "port": 44733})

    def test_state_export_rejects_invalid_ports_and_unknown_state_names(self):
        for tail in ("192.168.1.7:70000 ESTABLISHED:ESTABLISHED", "192.168.1.7:42 SECRET:TOKEN"):
            with self.subTest(tail=tail):
                self.assertEqual(runner.scoped_states("all tcp 192.168.1.239:61322 <- " + tail), [])


class ChildRuntime(unittest.TestCase):
    def start(self, peer="127.0.0.1", seconds=10):
        python = os.environ.get("SQUIRRELOPS_DIAGNOSTIC_CHILD_PYTHON", sys.executable)
        child = subprocess.Popen([python, "-I", "-S", "-B", "-u", "-c", runner.CHILD,
                                  "127.0.0.1", "0", peer, str(runner.clock() + seconds)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.finish, child)
        return child, runner.read_line(child, 2)["port"]

    @staticmethod
    def finish(child):
        runner.stop_child(child)
        child.stdout.close()
        child.stderr.close()

    def test_actual_banner_and_held_echo(self):
        child, port = self.start()
        with socket.create_connection(("127.0.0.1", port), timeout=2) as stream:
            self.assertEqual(stream.recv(64), ("A5 uid=%d\n" % os.getuid()).encode())
            stream.sendall(b"A5-PING\n")
            self.assertEqual(stream.recv(64), ("A5-PONG uid=%d\n" % os.getuid()).encode())
        runner.stop_child(child)
        self.assertEqual(child.returncode, 0)

    def test_real_client_initiated_close_drains_child_before_listener_stop(self):
        child, port = self.start()
        with socket.create_connection(("127.0.0.1", port), timeout=2) as stream:
            self.assertEqual(stream.recv(64), ("A5 uid=%d\n" % os.getuid()).encode())
            client.close_orderly(stream)
        runner.stop_child(child)
        self.assertEqual(child.returncode, 0)

    def test_wrong_peer_receives_nothing(self):
        _, port = self.start(peer="127.0.0.2")
        with socket.create_connection(("127.0.0.1", port), timeout=2) as stream:
            self.assertEqual(stream.recv(64), b"")

    def test_deadline_and_lifeline_stop_listener(self):
        child, _ = self.start(seconds=0.3)
        child.wait(timeout=2)
        self.assertEqual(child.returncode, 0)
        child, _ = self.start()
        child.stdin.close()
        child.wait(timeout=2)
        self.assertEqual(child.returncode, 0)


class ClientContract(unittest.TestCase):
    def test_handoff_finishes_tcp_before_ack_but_retains_tuple_for_probe(self):
        held = {}
        streams = [Mock(), Mock()]
        for index, stream in enumerate(streams):
            stream.getsockname.return_value = (runner.PEER, 43000 + index)
            stream.recv.return_value = b""
        def fresh(ip, port, source_port=0, keep=False):
            index = client.IPS.index(ip)
            if keep:
                return {"response": "A5 uid=309\n"}, streams[index]
            return {"error": "TimeoutError"}, None
        with patch.object(client, "fresh", side_effect=fresh):
            rows = client.phase("healthy_again", held)
        self.assertEqual(len([row for row in rows if row["kind"] == "client_close" and row["eof"]]), 2)
        for index, stream in enumerate(streams):
            stream.shutdown.assert_called_once_with(socket.SHUT_WR)
            stream.recv.assert_called_once_with(64)
            stream.close.assert_called_once()
            self.assertEqual(held[client.IPS[index]], (None, 43000 + index))
        with patch.object(client, "fresh", return_value=({}, None)) as probe:
            rows = client.phase("wrong_uid_retained_state", held)
        self.assertEqual(len([row for row in rows if row["kind"] == "same_tuple_reconnect"]), 2)
        self.assertFalse(any(row["kind"] == "established" for row in rows))
        self.assertEqual(probe.call_args_list[0].args, (client.IPS[0], 22, 43000))
        self.assertEqual(held, {})

    def test_close_handshake_error_is_not_a_successful_handoff(self):
        stream = Mock()
        stream.recv.side_effect = socket.timeout("no EOF")
        with self.assertRaises(socket.timeout):
            client.close_orderly(stream)
        stream.close.assert_called_once()

    def test_second_ingress_frames_have_fixed_addresses_and_valid_checksums(self):
        frames = client.second_ingress_frames(bytes.fromhex("001122334455"))
        self.assertEqual(len(frames), 2)
        for index, frame in enumerate(frames):
            self.assertEqual(len(frame), 54)
            self.assertEqual(frame[:6], bytes.fromhex("ea0372637e01"))
            header, tcp = frame[14:34], frame[34:]
            self.assertEqual(client.checksum(header), 0)
            self.assertEqual(socket.inet_ntoa(header[12:16]), "192.168.1.7")
            self.assertEqual(socket.inet_ntoa(header[16:20]), client.IPS[index])
            self.assertEqual(struct.unpack("!HH", tcp[:4]), (42739 + index, client.PUBLIC_PORTS[index]))
            self.assertEqual(tcp[13], 2)
            self.assertEqual(client.checksum(header[12:20] + struct.pack("!BBH", 0, 6, len(tcp)) + tcp), 0)

    def test_no_arguments_do_not_open_socket(self):
        with patch.object(client.socket, "socket") as socket_factory:
            self.assertEqual(client.main([]), 0)
        socket_factory.assert_not_called()

    def test_phases_match_and_cannot_be_skipped_or_repeated(self):
        self.assertEqual(client.PHASES, runner.PHASES)
        for line in ('{"phase":"wrong_uid_retained_state"}\n', '{"phase":"healthy","cmd":"id"}\n'):
            import io
            with patch.object(client.sys, "stdin", io.StringIO(line)), patch.object(client, "phase") as probe:
                with self.assertRaises(ValueError):
                    client.main(["--run"])
            probe.assert_not_called()

    def test_fresh_probe_binds_only_approved_source(self):
        stream = Mock()
        stream.getsockname.return_value = ("192.168.1.7", 43000)
        stream.recv.return_value = b"A5 uid=309\n"
        with patch.object(client.socket, "socket", return_value=stream):
            row, held = client.fresh(client.IPS[0], client.PUBLIC_PORTS[0], keep=True)
        stream.bind.assert_called_once_with(("192.168.1.7", 0))
        stream.connect.assert_called_once_with((client.IPS[0], client.PUBLIC_PORTS[0]))
        self.assertTrue(row["connected"])
        self.assertIs(held, stream)
        stream.close.assert_not_called()


if __name__ == "__main__":
    unittest.main()
