"""Synthetic exact-run export checks; no live commands or traffic."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("protocol_export", Path(__file__).with_name("mini_protocol_evidence_export.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ProtocolEvidenceTests(unittest.TestCase):
    def test_pf_translation_and_state_only(self):
        record = dict(command=["/sbin/pfctl", "-s", "states"], exit=0, stdout=(
            "all tcp 192.168.1.240:59738 (192.168.1.240:22) <- 192.168.1.7:40100 ESTABLISHED:ESTABLISHED\n"
            "  age 00:00:02, expires in 00:00:20, secret-token\n"))
        result = m.pf_states(record)
        self.assertEqual(len(result["states"]), 1)
        self.assertEqual(result["states"][0]["vip_ports"], [22, 59738])
        self.assertEqual(result["states"][0]["client_ports"], [40100])
        self.assertEqual(result["states"][0]["state_pair"], "ESTABLISHED:ESTABLISHED")
        self.assertNotIn("secret-token", json.dumps(result))

    def test_pf_nonstate_commands_never_export(self):
        for command in (["/sbin/pfctl", "-E"], ["/sbin/pfctl", "-s", "References"],
                        ["/sbin/pfctl", "-X", "secret-token"]):
            self.assertIsNone(m.pf_states(dict(command=command, exit=0, stdout="secret-token")))

    def test_pf_unknown_other_addresses_and_ports_are_withheld(self):
        for line in (
            "all tcp 192.168.1.240:59738 <- 192.168.1.8:40100 ESTABLISHED:ESTABLISHED",
            "all tcp 192.168.1.240:5900 <- 192.168.1.7:40100 ESTABLISHED:ESTABLISHED",
            "all tcp 192.168.1.240:22 <- 192.168.1.7:70000 ESTABLISHED:ESTABLISHED",
            "all tcp 192.168.1.240:22 <- 192.168.1.7:40100 SECRET:SECRET",
            "all tcp 192.168.1.240:22 (10.0.0.1:22) <- 192.168.1.7:40100 ESTABLISHED:ESTABLISHED",
        ):
            parsed = m.pf_states(dict(command=m.PF_STATES, exit=0, stdout=line))
            self.assertEqual(parsed["states"], [])
            self.assertEqual(parsed["withheld_lines"], 1)

    def test_packets_window_and_private_content(self):
        text = ("2026-10-01 05:29:07.001 IP 192.168.1.7.40100 > 192.168.1.240.445: tcp 238\n"
                "2026-10-01 05:29:08.001 IP 192.168.1.240.445 > 192.168.1.7.40100: tcp 0\n"
                "2026-10-01 05:30:00.001 IP 192.168.1.7.40100 > 192.168.1.240.445: tcp 1\n"
                "secret-token\n")
        result = m.packet_summary(text)
        self.assertEqual(len(result["groups"]), 2)
        self.assertEqual(sum(r["tcp_payload_bytes_with_retransmits"] for r in result["groups"]), 238)
        self.assertEqual(result["withheld_outside_window_lines"], 1)
        self.assertEqual(result["unparsed_or_out_of_scope_lines"], 1)
        self.assertNotIn("secret-token", json.dumps(result))

    def test_backup_resolution_is_exact_and_receipt_bound(self):
        backup = m.BASE / "mini-protocol-20261001.ExactRun"
        receipt = b"pinned fixture"
        def read(path, **kwargs):
            if path == m.CLAIM:
                return json.dumps(dict(backup=str(backup), package_sha256=m.PACKAGE_SHA)).encode()
            if path in (m.RECEIPT, backup / "cleanup.json"):
                return receipt
            raise AssertionError(path)
        with patch.object(m.common, "read_safe", side_effect=read), patch.object(m, "RECEIPT_SHA", m.hashlib.sha256(receipt).hexdigest()):
            self.assertEqual(m.resolve_backup(), backup)
        for value in ("/private/tmp/elsewhere", str(m.BASE / "mini-protocol-20261001.a/../other")):
            with patch.object(m.common, "read_safe", return_value=json.dumps(dict(backup=value, package_sha256=m.PACKAGE_SHA)).encode()):
                with self.assertRaises(RuntimeError):
                    m.resolve_backup()

    def test_receipt_drift_stops_resolution(self):
        with patch.object(m.common, "read_safe", return_value=b"drift"):
            with self.assertRaises(RuntimeError):
                m.resolve_backup()

    def test_no_live_command_outside_allowlist(self):
        for args in (["/sbin/pfctl", "-E"], ["/sbin/pfctl", "-s", "states"],
                     ["/bin/launchctl", "bootstrap", "system", "x"], ["/usr/sbin/installer"]):
            with patch.object(m.subprocess, "run") as run:
                with self.assertRaises(RuntimeError):
                    m.command(args)
                run.assert_not_called()

    def test_mock_collect_reads_only_retained_files(self):
        backup = m.BASE / "mini-protocol-20261001.ExactRun"
        def read(path, **kwargs):
            if path.name.startswith("packet-"):
                return b"2026-10-01 05:29:07.001 IP 192.168.1.7.40100 > 192.168.1.240.22: tcp 0\n"
            return json.dumps(dict(command=["/sbin/pfctl", "-E"], exit=0, stdout="Token : secret-token")).encode()
        with patch.object(m.common, "read_safe", side_effect=read), patch.object(Path, "glob", return_value=[backup / "command-001.json"]), patch.object(m, "command") as run:
            report = m.collect(backup)
            run.assert_not_called()
            self.assertEqual(report["state_snapshot_count"], 0)
            self.assertNotIn("secret-token", json.dumps(report))

    def test_actual_cleanup_receipt_pin(self):
        evidence = Path(__file__).parents[1] / "evidence/2026-10-01-mini-installed-protocol/cleanup-status.json"
        if not evidence.is_file():
            self.skipTest("Requires retained private Mini cleanup evidence")
        self.assertEqual(m.hashlib.sha256(evidence.read_bytes()).hexdigest(), m.RECEIPT_SHA)

    def test_wrapper_pins_both_inputs(self):
        wrapper = Path(__file__).with_name("export-mini-protocol-evidence.sh").read_text()
        for name in ("mini_protocol_evidence_export.py", "mini_readonly_diagnostic_export.py"):
            self.assertIn(m.hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest(), wrapper)
        self.assertIn('"$runtime" -I -B', wrapper)
        self.assertNotRegex(wrapper, r"(?m)^\s*(?:/usr/bin/)?sudo\s")

    def test_main_only_reads_live_boot_and_job_status(self):
        calls = []
        def run(args):
            calls.append(args)
            if args[0] == "/usr/sbin/sysctl":
                return SimpleNamespace(returncode=0, stdout="{ sec = 1790777754, usec = 0 }", stderr="")
            return SimpleNamespace(returncode=113, stdout="", stderr='Could not find service "' + args[2][7:] + '"')
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(m.os, "geteuid", return_value=0), patch.object(m.os, "umask"), patch.object(m, "resolve_backup", return_value=m.BASE / "mini-protocol-20261001.ExactRun"), patch.object(m, "command", side_effect=run), patch.object(m, "collect", return_value={"safe": True}), patch.object(m.tempfile, "mkdtemp", return_value=directory), patch.object(m.os, "chown"), patch("builtins.print"):
                m.main()
            self.assertEqual(json.loads((Path(directory) / "diagnostic.json").read_text()), {"safe": True})
            self.assertEqual(len(calls), 3)
            self.assertTrue(all(c[0] in ("/usr/sbin/sysctl", "/bin/launchctl") for c in calls))


if __name__ == "__main__":
    unittest.main()
