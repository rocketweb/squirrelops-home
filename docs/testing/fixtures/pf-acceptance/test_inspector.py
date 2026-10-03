import importlib.util
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("inspect_completed", Path(__file__).with_name("inspect_completed.py"))
inspector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inspector)


class Inspector(unittest.TestCase):
    def test_successful_collection_is_pinned_and_contains_all_phase_pairs(self):
        root = Path("/private-evidence")
        children = [root / ("child-%d-events.jsonl" % n) for n in range(8)]
        snapshot = json.dumps({"time_utc": "2026-10-02T06:32:46Z", "states": "", "counters": ""})
        def retained(path):
            return '{"event":"stopped"}\n' if path.suffix == ".jsonl" else snapshot
        with patch.object(inspector, "verified_root", return_value=root) as verify, \
                patch.object(inspector, "read_safe", side_effect=retained) as read, \
                patch.object(Path, "glob", side_effect=[children, []]):
            result = inspector.collect_successful()
        verify.assert_called_once_with(inspector.SUCCESSFUL_RUN)
        self.assertEqual(len(result["snapshots"]), 16)
        self.assertEqual([row["phase"] for row in result["phase_deltas"]], list(inspector.PHASES))
        self.assertEqual(len(result["children"]), 8)
        self.assertFalse(result["system_mutations"])
        self.assertTrue(all(call.args[0].parent == root for call in read.call_args_list))

    def test_successful_collection_rejects_incomplete_child_evidence(self):
        snapshot = json.dumps({"time_utc": "2026-10-02T06:32:46Z", "states": "", "counters": ""})
        with patch.object(inspector, "verified_root", return_value=Path("/private-evidence")), \
                patch.object(inspector, "read_safe", return_value=snapshot), \
                patch.object(Path, "glob", return_value=[]):
            with self.assertRaisesRegex(RuntimeError, "eight retained"):
                inspector.collect_successful()

    def test_pinned_receipt_requires_cleaned_state_and_matching_nonce(self):
        clean = {"nonce": inspector.SUCCESSFUL_RUN[1], "phase": "cleaned", "cleanup_complete": True}
        receipt = {"nonce": inspector.SUCCESSFUL_RUN[1], "release_attempted": True,
                   "aliases": [], "alias_attempts": []}
        info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        for changed in ({**clean, "nonce": "wrong"}, {**clean, "cleanup_complete": False},
                        {**clean, "phase": "healthy"}):
            with patch.object(Path, "lstat", return_value=info), \
                    patch.object(inspector, "read_safe", side_effect=map(json.dumps, (changed, receipt))):
                with self.assertRaisesRegex(RuntimeError, "identity or cleanup"):
                    inspector.verified_root(inspector.SUCCESSFUL_RUN)

    def test_successful_plan_reads_no_evidence(self):
        with patch.object(inspector, "collect_successful") as collect:
            self.assertEqual(inspector.main(["--successful-run"]), 0)
        collect.assert_not_called()

    def test_counter_export_identifies_rules_without_copying_raw_text(self):
        source = (
            "@0 pass in quick on en0 inet proto tcp from any to 192.168.1.239 port = 61322 "
            "user = _squirrelops flags any tagged squirrelops_192_168_1_239_22_61322 keep state\n"
            "  [ Evaluations: 12 Packets: 8 Bytes: 440 States: 1 ]\n"
            "  [ Inserted: uid 0 pid 987 ]\n"
            "@1 block drop in quick inet from any to 192.168.1.239\n"
            "  [ Evaluations: 8 Packets: 4 Bytes: 240 States: 0 ]\n"
            "SECRET-DO-NOT-EXPORT\n"
        )
        result = inspector.counter_summary(source)
        self.assertEqual(result["rules"][0]["kind"], "uid_tag_pass")
        self.assertEqual(result["rules"][1]["kind"], "vip_block")
        self.assertEqual(result["rules"][1]["counters"]["packets"], 4)
        self.assertEqual(result["withheld_lines"], 1)
        self.assertNotIn("SECRET", str(result))

    def test_counter_deltas_require_same_rules_and_monotonic_counters(self):
        source = "@0 block drop in quick inet from any to 192.168.1.239\n[ Evaluations: 8 Packets: 4 Bytes: 240 States: 0 ]\n"
        before = inspector.counter_summary(source)
        after = inspector.counter_summary(source.replace("Packets: 4", "Packets: 7").replace("Bytes: 240", "Bytes: 420"))
        result = inspector.counter_delta(before, after)
        self.assertTrue(result["comparable"])
        self.assertEqual(result["rules"][0]["packets_delta"], 3)
        self.assertFalse(inspector.counter_delta(after, before)["comparable"])
        changed = inspector.counter_summary(source.replace("239", "240"))
        self.assertFalse(inspector.counter_delta(before, changed)["comparable"])

    def test_unknown_or_incomplete_counters_cannot_be_counted_as_proof(self):
        for source in (
            "@0 pass from any to 192.168.1.9\n[ Evaluations: 1 Packets: 1 Bytes: 1 States: 0 ]\n",
            "@0 block drop in quick inet from any to 192.168.1.239\n",
            "@0 block drop in quick inet from any to 192.168.1.239\n[ Evaluations: 1 Packets: 1 Packets: 2 Bytes: 1 States: 0 ]\n",
        ):
            result = inspector.counter_summary(source)
            self.assertFalse(inspector.counter_delta(result, result)["comparable"])

    def test_child_events_distinguish_loopback_from_lan_and_withhold_unknowns(self):
        events = [
            {"event": "accepted", "source": "127.0.0.1", "source_port": 40500, "uid": 501},
            {"event": "accepted", "source": "192.168.1.7", "source_port": 40501, "uid": 309},
            {"event": "echo", "uid": 309},
            {"event": "accepted", "source": "192.168.1.9", "source_port": 40502, "uid": 309},
            {"event": "SECRET"},
            {"event": "stopped"},
        ]
        result = inspector.child_summary("\n".join(json.dumps(row) for row in events))
        self.assertEqual(result["lan_accepts"], {"309": 1, "501": 0})
        self.assertEqual(result["loopback_accepts"], {"309": 0, "501": 1})
        self.assertEqual(result["withheld_lines"], 2)
        self.assertTrue(result["stopped"])
        self.assertNotIn("SECRET", str(result))

    def test_incomplete_or_malformed_child_events_do_not_claim_clean_stop(self):
        result = inspector.child_summary('{"event":"stopped"}\nnot json\n')
        self.assertFalse(result["stopped"])
        self.assertEqual(result["withheld_lines"], 1)

    def test_plan_reads_no_private_evidence(self):
        with patch.object(inspector, "collect") as collect:
            self.assertEqual(inspector.main([]), 0)
        collect.assert_not_called()

    def test_only_selected_error_facts_leave_private_evidence(self):
        result = inspector.error_summary("secret\nOSError: [Errno 48] Address already in use\n")
        self.assertEqual(result["errno"], [48])
        self.assertTrue(result["address_in_use"])
        self.assertNotIn("secret", str(result))

    def test_known_state_pair_parses_without_prefix_assumption(self):
        for prefix in ("all", "ALL", "en0"):
            source = prefix + " tcp 192.168.1.239:61322 (192.168.1.239:22) <- 192.168.1.7:35301 ESTABLISHED:ESTABLISHED\n"
            result = inspector.state_summary(source)
            self.assertEqual(len(result["selected"]), 1)
            self.assertEqual(result["selected"][0]["state_pair"], "ESTABLISHED:ESTABLISHED")

    def test_other_addresses_and_unrecognized_states_are_withheld(self):
        for source in ("all tcp 192.168.1.7:43111 <- 192.168.1.9:22 ESTABLISHED:ESTABLISHED",
                       "all tcp 192.168.1.7:43111 <- 192.168.1.240:61445 SECRET:SECRET",
                       "all tcp 192.168.1.7:43111 <- 192.168.1.240:70000 ESTABLISHED:ESTABLISHED"):
            result = inspector.state_summary(source)
            self.assertEqual(result["selected"], [])
            self.assertEqual(result["withheld_lines"], 1)

    def test_exporter_has_no_subprocess_or_mutating_network_operations(self):
        text = Path(inspector.__file__).read_text()
        for forbidden in ("import subprocess", "pfctl", "launchctl", "socket.socket", "installer", "os.chown"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
