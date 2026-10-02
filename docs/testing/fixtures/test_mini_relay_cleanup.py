"""Exact-session cleanup guards; host operations are mocked, files disposable."""
import importlib.util
import json
from pathlib import Path
import copy
import hashlib
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("relay_cleanup", Path(__file__).with_name("mini_relay_cleanup.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RelayCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.session = module.Cleanup(self.root)
        self.session.backup = self.root / "private"
        self.session.backup.mkdir()
        self.session.public = self.root / "public"
        self.session.public.mkdir()
        self.session.attempt = self.root / "attempt.json"
        self.session.private_reference = "123456789012345"

    @staticmethod
    def records():
        def row(command, stdout="", stderr="", code=0):
            return dict(command=command, stdout=stdout, stderr=stderr, exit=code)
        rows = [row(module.upgrade.LISTENERS, "u0\nn*:22\nn*:445\nn*:5900\nu501\nn192.168.1.115:11434\n")]
        rows.append(row(["/sbin/pfctl", "-s", "info"], "Status: Disabled\ncurrent entries 0\n"))
        for flags in (["-s", "Anchors"], ["-sr"], ["-sn"]):
            rows.append(row(["/sbin/pfctl", *flags]))
        rows.extend([
            row(["/sbin/pfctl", "-E"], "Token : 123456789012345\n"),
            row(["/usr/sbin/installer", "-pkg", str(module.STAGE / "candidate.pkg"), "-target", "/"]),
            row(["/bin/launchctl", "print-disabled", "system"],
                '\n'.join('"' + job + '" => disabled' for job in module.upgrade.JOBS)),
        ])
        return rows

    def test_all_seven_recorded_rows_preserve_original_intent(self):
        evidence = Path(__file__).parent.parent / "evidence/2026-09-30-mini-relay-idle"
        if not all((evidence / name).is_file() for name in ("before.json", "after.json")):
            self.skipTest("Requires retained private Mini before/after evidence")
        fields = ("id", "decoy_type", "bind_address", "port", "status")
        before = [[row[k] for k in fields] for row in json.loads((evidence / "before.json").read_text())["decoys"]]
        after = [[row[k] for k in fields] for row in json.loads((evidence / "after.json").read_text())["decoys"]]
        self.assertEqual(before, after)
        module.validate_cleanup_intent(after)

    def test_no_blanket_acceptance_of_new_changed_missing_or_reordered_rows(self):
        variants = [module.EXPECTED[:-1], [*module.EXPECTED, [8, "home_assistant", "192.168.1.115", 50000, "active"]],
                    list(reversed(module.EXPECTED))]
        for index in range(7):
            for field in range(5):
                rows = copy.deepcopy(module.EXPECTED)
                rows[index][field] = "changed"
                variants.append(rows)
        for rows in variants:
            with self.subTest(rows=rows), self.assertRaises(RuntimeError):
                module.validate_cleanup_intent(rows)

    def test_plan_only_never_opens_live_host(self):
        r = subprocess.run([sys.executable, "-I", "-B", module.__file__],capture_output=True,text=True,timeout=5)
        self.assertEqual(r.returncode, 0, r.stderr)
        plan = json.loads(r.stdout)
        self.assertEqual(plan["mode"], "plan_only")
        self.assertEqual(plan["reviewed_decoy_count"], 7)
        self.assertFalse(plan["install"] or plan["restart"] or plan["database_edits"])

    def test_original_attempt_claim_cannot_redirect_to_arbitrary_path(self):
        good = {"package_sha256": module.PACKAGE_SHA,
                "backup": str(module.CONTAINER / "mini-relay-20260930.m06dh5r3")}
        self.assertEqual(module.baseline_path(good), Path(good["backup"]))
        for claim in ({**good, "backup": "/tmp/mini-relay-20260930.m06dh5r3"},
                      {**good, "backup": str(module.CONTAINER / "other-session")},
                      {**good, "package_sha256": "wrong"}, {**good, "extra": True}):
            with self.subTest(claim=claim), self.assertRaises(RuntimeError):
                module.baseline_path(claim)

    def test_provenance_replays_only_recorded_reads(self):
        with patch.object(module.subprocess, "run") as run:
            endpoints, policy = module.recover_baseline(self.records(), self.session.private_reference)
        run.assert_not_called()
        self.assertEqual(len(endpoints), 4)
        self.assertEqual(policy, {"": {"children": [], "-sr": "", "-sn": ""}})

    def test_reference_mismatch_repeat_acquisition_and_prior_release_stop(self):
        for token in ("different", "999", "", "1" * 21):
            with self.subTest(token=token), self.assertRaises(RuntimeError):
                module.recover_baseline(self.records(), token)
        for command in (["/sbin/pfctl", "-E"], ["/sbin/pfctl", "-X", self.session.private_reference]):
            rows = [*self.records(), dict(command=command, exit=0, stdout="", stderr="")]
            with self.subTest(command=command), self.assertRaises(RuntimeError):
                module.recover_baseline(rows, self.session.private_reference)

    def test_failed_or_wrong_install_and_hold_rejected(self):
        for index, field, value in ((6, "exit", 1), (6, "command", ["/usr/sbin/installer", "wrong"]),
                                    (7, "stdout", '"com.squirrelops.sensor" => enabled'), (7, "exit", 1)):
            rows = self.records()
            rows[index][field] = value
            with self.subTest(index=index, field=field), self.assertRaises(RuntimeError):
                module.recover_baseline(rows, self.session.private_reference)

    def test_missing_changed_or_error_pf_baseline_rejected(self):
        variants = []
        rows = self.records()
        rows.pop(3)
        variants.append(rows)
        for index, field, value in ((3, "stderr", "pfctl: DIOCGETRULES: Invalid argument"),
                                    (3, "stdout", "block all"),
                                    (1, "stdout", "Status: Enabled\ncurrent entries 0\n")):
            rows = self.records()
            rows[index][field] = value
            variants.append(rows)
        for rows in variants:
            with self.subTest(rows=rows), self.assertRaises(RuntimeError):
                module.recover_baseline(rows, self.session.private_reference)

    def test_command_allowlist_blocks_every_other_mutation(self):
        forbidden = [["/sbin/pfctl", "-E"], ["/sbin/pfctl", "-d"], ["/sbin/pfctl", "-F", "all"],
                     ["/sbin/pfctl", "-f", "/tmp/rules"], ["/sbin/ifconfig", "en0", "-alias", "192.168.1.240"],
                     ["/bin/launchctl", "disable", "system/com.squirrelops.sensor"],
                     ["/bin/launchctl", "bootout", "system/com.squirrelops.sensor"],
                     ["/usr/sbin/installer", "-pkg", "candidate.pkg", "-target", "/"],
                     ["/bin/kill", "123"], ["/bin/sh", "-c", "echo test"]]
        with patch.object(module.base.Session, "command") as dispatch:
            for args in forbidden:
                with self.subTest(args=args), self.assertRaises(RuntimeError):
                    self.session.command(args)
        dispatch.assert_not_called()

    def test_readonly_inventory_commands_are_allowed(self):
        for args in (module.upgrade.LISTENERS, ["/bin/launchctl", "print-disabled", "system"],
                     ["/sbin/pfctl", "-a", "com.apple/250.ApplicationFirewall", "-sr"],
                     ["/sbin/pfctl", "-s", "References"], ["/bin/ls", "-lde", str(module.post.DATABASE)]):
            self.assertTrue(module.read_command_allowed(args), args)
        self.assertFalse(module.read_command_allowed(["/sbin/pfctl", "-a", "*", "-sr"]))

    def test_unarmed_wrong_and_repeated_release_never_dispatch(self):
        with patch.object(module.base.Session, "command") as dispatch:
            with self.assertRaises(RuntimeError):
                self.session.command(["/sbin/pfctl", "-X", self.session.private_reference])
            self.session.release_armed = True
            with self.assertRaises(RuntimeError):
                self.session.command(["/sbin/pfctl", "-X", "999"])
            self.session.command(["/sbin/pfctl", "-X", self.session.private_reference])
            with self.assertRaises(RuntimeError):
                self.session.command(["/sbin/pfctl", "-X", self.session.private_reference])
        dispatch.assert_called_once()

    def release_commands(self, fail=False):
        events = []
        def dispatch(args, **_kwargs):
            events.append(args)
            if args[:2] == ["/sbin/pfctl", "-X"]:
                self.assertTrue(self.session.attempt.exists())
                self.assertIsNone(self.session.token)
                if fail:
                    raise subprocess.TimeoutExpired(args, 30)
            refs = self.session.private_reference if len(events) == 1 else "999"
            output = "Status: Enabled\n" if args[-1] == "info" else refs
            return subprocess.CompletedProcess(args, 0, output, "")
        return events, dispatch

    def test_release_requires_backup_and_consent(self):
        for approved, backed in ((False, True), (True, False)):
            self.session.approved, self.session.backup_verified = approved, backed
            with patch.object(self.session, "verify_stopped") as checks, self.assertRaises(RuntimeError):
                self.session.release_once()
            checks.assert_not_called()

    def test_recheck_failure_prevents_attempt_record_and_release(self):
        self.session.approved = self.session.backup_verified = True
        for method in ("verify_stopped", "verify_reference"):
            with patch.object(self.session, "verify_stopped"), patch.object(self.session, "verify_reference"), \
                    patch.object(self.session, method, side_effect=RuntimeError("drift")), \
                    patch.object(module.base.Session, "command") as dispatch, self.assertRaises(RuntimeError):
                self.session.release_once()
            dispatch.assert_not_called()
            self.assertFalse(self.session.attempt.exists())

    def test_exact_release_records_first_and_keeps_other_reference(self):
        self.session.approved = self.session.backup_verified = True
        events, dispatch = self.release_commands()
        with patch.object(self.session, "verify_stopped") as checks, patch.object(self.session, "verify_reference"), \
                patch.object(module.base.Session, "command", side_effect=dispatch), patch.object(self.session, "publish") as publish:
            self.session.release_once()
        self.assertEqual(events, [["/sbin/pfctl", "-s", "References"],
                                 ["/sbin/pfctl", "-X", self.session.private_reference],
                                 ["/sbin/pfctl", "-s", "References"], ["/sbin/pfctl", "-s", "info"]])
        self.assertEqual(checks.call_count, 2)
        self.assertTrue(publish.call_args.kwargs["pf_enabled"])
        self.assertFalse(self.session.release_armed)

    def test_uncertain_release_is_not_retried(self):
        self.session.approved = self.session.backup_verified = True
        events, dispatch = self.release_commands(fail=True)
        with patch.object(self.session, "verify_stopped"), patch.object(self.session, "verify_reference"), \
                patch.object(module.base.Session, "command", side_effect=dispatch):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.session.release_once()
            with self.assertRaises(FileExistsError):
                self.session.release_once()
        self.assertEqual(sum(args[:2] == ["/sbin/pfctl", "-X"] for args in events), 1)
        self.assertIsNone(self.session.token)
        self.assertFalse(self.session.release_armed)

    def test_failure_redacts_token_and_never_runs_inherited_teardown(self):
        error = subprocess.TimeoutExpired(["/sbin/pfctl", "-X", self.session.private_reference], 30)
        with patch.object(self.session, "preflight_cleanup", side_effect=error), patch.object(self.session, "stop") as stop, \
                patch.object(self.session, "publish") as publish, patch("builtins.print") as output, \
                patch.object(module.os, "umask"), self.assertRaises(SystemExit):
            self.session.run_cleanup()
        stop.assert_not_called()
        self.assertNotIn(self.session.private_reference, str(output.call_args_list) + str(publish.call_args_list))

    def test_readonly_database_and_backup_use_original_uid_dropping_worker(self):
        self.assertIs(module.Cleanup.database, module.post.PostRebootUpgrade.database)
        self.assertIs(module.Cleanup.read_intent, module.post.PostRebootUpgrade.read_intent)

    def test_bootstrap_pins_all_inputs(self):
        script = Path(module.__file__).with_name("finish-mini-relay-cleanup.sh").read_text()
        copies = re.search(r"for name in (.+); do",script).group(1).split()
        pins = dict(re.findall(r"^verify_digest (\S+) ([a-f0-9]{64})$",script,re.M))
        self.assertEqual(set(copies),set(pins))
        self.assertEqual(pins.pop("candidate.pkg"),module.PACKAGE_SHA)
        for name, digest in pins.items():
            path = Path(module.__file__).with_name(name)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),digest,name)


if __name__ == "__main__":
    unittest.main()
