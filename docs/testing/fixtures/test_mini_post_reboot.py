"""Post-reboot acceptance guards. Disposable files and mocked host operations only."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "post_reboot", Path(__file__).with_name("mini_post_reboot_acceptance.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PostRebootTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.session = module.PostRebootUpgrade(self.root)
        self.session.backup = self.root / "private"
        self.session.backup.mkdir()
        self.session.public = self.root / "public"
        self.session.public.mkdir()

    def test_plan_does_not_contact_or_mutate_host(self):
        result = subprocess.run([sys.executable, module.__file__], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["mode"], "plan_only")
        self.assertEqual(plan["boot_seconds"], 1790777754)
        self.assertEqual(plan["test_vips"], ["192.168.1.240"])
        self.assertFalse(plan["database_recovery"])
        self.assertTrue(plan["restore_disabled_jobs"])

    def test_expected_intent_includes_classic_host_listener(self):
        module.validate_intent(module.EXPECTED_INTENT)
        for rows in (module.EXPECTED_INTENT[:-1], [],
                     [*module.EXPECTED_INTENT[:-1], [6, "dev_server", "192.168.1.115", 60556, "stopped"]]):
            with self.subTest(rows=rows), self.assertRaises(RuntimeError):
                module.validate_intent(rows)

    def test_hold_requires_both_explicit_disabled_records(self):
        good = '\n'.join(f'"{job}" => disabled' for job in module.upgrade.JOBS)
        self.assertEqual(module.hold_state(good), dict.fromkeys(module.upgrade.JOBS, True))
        for text in ("", good.replace("disabled", "enabled", 1), good + '\n"com.squirrelops.sensor" => disabled'):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                module.require_hold(text)

    def test_database_reader_drops_root_and_supplementary_groups(self):
        result = subprocess.CompletedProcess([], 0, b'[]', b'')
        with patch.object(self.session, "check_database_paths"), patch.object(module.subprocess, "run", return_value=result) as run:
            self.assertEqual(self.session.database("intent"), [])
        self.assertEqual(run.call_args.kwargs["user"], 309)
        self.assertEqual(run.call_args.kwargs["group"], 309)
        self.assertEqual(run.call_args.kwargs["extra_groups"], [])
        self.assertIn("mode=ro", run.call_args.args[0][4])

    def test_database_failure_does_not_expose_private_output(self):
        result = subprocess.CompletedProcess([], 1, b'private-data', b'private-data')
        with patch.object(self.session, "check_database_paths"), patch.object(module.subprocess, "run", return_value=result):
            with self.assertRaises(RuntimeError) as error:
                self.session.database("intent")
        self.assertNotIn("private-data", str(error.exception))

    def test_database_operation_is_allowlisted(self):
        with patch.object(module.subprocess, "run") as run, self.assertRaises(RuntimeError):
            self.session.database("UPDATE decoys")
        run.assert_not_called()

    def test_enable_requires_backup_consent_and_own_protection(self):
        for approved, backed_up, token in ((False, True, "123"), (True, False, "123"), (True, True, None)):
            self.session.upgrade_approved, self.session.backup_verified, self.session.token = approved, backed_up, token
            with self.subTest(approved=approved, backup=backed_up, token=token), \
                    patch.object(self.session, "command") as command, self.assertRaises(RuntimeError):
                self.session.enable_for_install()
            command.assert_not_called()

    def test_enable_targets_exact_jobs_without_bootstrapping_old_payload(self):
        self.session.upgrade_approved = self.session.backup_verified = True
        self.session.token = "123"
        text = '\n'.join(f'"{job}" => enabled' for job in module.upgrade.JOBS)
        with patch.object(self.session, "assert_boot"), patch.object(self.session, "assert_held_stopped"), \
                patch.object(self.session, "command", return_value=subprocess.CompletedProcess([], 0, text, "")) as command:
            self.session.enable_for_install()
        self.assertEqual([call.args[0] for call in command.call_args_list], [
            *[["/bin/launchctl", "enable", "system/" + job] for job in module.upgrade.JOBS],
            ["/bin/launchctl", "print-disabled", "system"],
        ])

    def test_release_reference_restores_hold_first(self):
        order = []
        with patch.object(self.session, "restore_hold", side_effect=lambda: order.append("hold")), \
                patch.object(module.launchd.LaunchdUpgrade, "release_reference", side_effect=lambda _: order.append("release")):
            self.session.release_reference()
        self.assertEqual(order, ["hold", "release"])

    def test_failed_hold_restore_retains_reference(self):
        with patch.object(self.session, "restore_hold", side_effect=RuntimeError("not stopped")), \
                patch.object(module.launchd.LaunchdUpgrade, "release_reference") as release, self.assertRaises(RuntimeError):
            self.session.release_reference()
        release.assert_not_called()

    def test_restore_does_not_disable_around_surviving_guest(self):
        with patch.object(self.session, "processes", return_value=[123]), patch.object(self.session, "command") as command, \
                self.assertRaises(RuntimeError):
            self.session.restore_hold()
        command.assert_not_called()

    def test_stale_ledger_must_be_exact_and_absent_after_install(self):
        with patch.object(self.session, "owned", return_value=[module.single.VIP]):
            self.session.check_stale_ledger()
        for owned in ([], ["192.168.1.241"], [module.single.VIP, "192.168.1.241"]):
            with patch.object(self.session, "owned", return_value=owned), self.assertRaises(RuntimeError):
                self.session.check_stale_ledger()

    def test_installer_failure_does_not_start_restart_test(self):
        with patch.object(self.session, "install_package", side_effect=RuntimeError("installer failed")), \
                patch.object(self.session, "restart_check") as restart, self.assertRaises(RuntimeError):
            self.session.install()
        restart.assert_not_called()

    def test_surviving_runtime_blocks_restart(self):
        with patch.object(self.session, "snapshot"), patch.object(self.session, "read_intent", return_value=module.EXPECTED_INTENT), \
                patch.object(self.session, "stop_job"), patch.object(self.session, "processes", return_value=[123]), \
                patch.object(module.time, "monotonic", side_effect=[0, 61]), \
                patch.object(self.session, "command") as command, self.assertRaisesRegex(RuntimeError, "survived"):
            self.session.restart_check()
        command.assert_not_called()

    def test_status_is_mirrored_to_durable_private_evidence(self):
        self.session.publish("preflight")
        self.assertEqual((self.session.public / "status.json").read_bytes(),
                         (self.session.backup / "status.json").read_bytes())
        report = json.loads((self.session.public / "status.json").read_text())
        self.assertEqual(report["test_scope"], "mini-post-reboot-240")

    def test_no_legacy_receipt_or_recovery_preflight_is_inherited(self):
        self.assertIs(module.PostRebootUpgrade.__bases__[0], module.upgrade.Upgrade)
        self.assertNotEqual(self.session.preflight.__func__, module.upgrade.Upgrade.preflight)
        source = Path(module.__file__).read_text()
        self.assertNotIn("CLEANUP_SHA", source)
        self.assertNotIn("restore_five(", source)
        self.assertNotIn("sqlite3.connect(", source.split('WORKER = r"""')[0])

    def test_real_worker_reads_and_backs_up_disposable_wal_database(self):
        source = self.root / "source.sqlite"
        destination = self.root / "snapshot.sqlite"
        with sqlite3.connect(source) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE decoys (id,decoy_type,bind_address,port,status)")
            db.executemany("INSERT INTO decoys VALUES (?,?,?,?,?)", module.EXPECTED_INTENT)
            db.commit()
            for operation, extras in (("intent", []), ("backup", [str(destination)])):
                result = subprocess.run([sys.executable, "-I", "-B", "-c", module.WORKER,
                                         operation, str(source), *extras], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), module.EXPECTED_INTENT if operation == "intent" else {"ok": True})
            self.assertEqual([list(row) for row in db.execute("SELECT * FROM decoys")], module.EXPECTED_INTENT)
        with sqlite3.connect(destination) as backup:
            self.assertEqual(backup.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual([list(row) for row in backup.execute("SELECT * FROM decoys")], module.EXPECTED_INTENT)

    def test_install_failure_order_preserves_evidence_and_never_restarts(self):
        session = self.session
        session.upgrade_approved = session.backup_verified = True
        session.pf_baseline = {}
        order = []

        def command(args, **_kwargs):
            if args[:2] == ["/sbin/pfctl", "-E"]:
                order.append("pf_enable")
                return subprocess.CompletedProcess(args, 0, "Token : 123\n", "")
            if args[0] == "/usr/bin/install":
                order.append("local_test_marker")
                return subprocess.CompletedProcess(args, 0, "", "")
            if args[0] == "/usr/sbin/installer":
                order.append("installer")
                return subprocess.CompletedProcess(args, 1, "private failure", "")
            self.fail("Unexpected command: " + str(args))

        with patch.object(session, "validate_existing"), patch.object(session, "verify_intent"), \
                patch.object(session, "inspect_empty_pf", return_value={}), patch.object(session, "check_conflicts"), \
                patch.object(module.single, "replace_config", side_effect=lambda *_: order.append("config")), \
                patch.object(session, "check_effective_pool"), patch.object(session, "pf", return_value="Status: Enabled\n"), \
                patch.object(session, "enable_for_install", side_effect=lambda: order.append("enable_jobs")), \
                patch.object(session, "command", side_effect=command), patch.object(session, "restart_check") as restart:
            with self.assertRaisesRegex(RuntimeError, "Installer failed"):
                session.install()
        self.assertEqual(order, ["config", "pf_enable", "enable_jobs", "local_test_marker", "installer"])
        self.assertTrue(session.install_started)
        self.assertFalse(session.install_in_progress)
        self.assertEqual(session.token, "123")
        self.assertTrue(session.claim.is_file())
        restart.assert_not_called()

    def test_wrong_boot_stops_before_hold_or_mutation(self):
        with patch.object(self.session, "command", return_value=subprocess.CompletedProcess([], 0, "{ sec = 1, usec = 0 }", "")) as command:
            with self.assertRaisesRegex(RuntimeError, "rebooted"):
                self.session.assert_held_stopped()
        command.assert_called_once_with(["/usr/sbin/sysctl", "kern.boottime"])

    def test_existing_attempt_claim_blocks_config_and_pf_mutation(self):
        session = self.session
        session.upgrade_approved = session.backup_verified = True
        session.pf_baseline = {}
        (session.backup.parent / f"post-reboot-{module.BOOT}-{session.package_sha[:12]}-attempt.json").touch()
        with patch.object(session, "validate_existing"), patch.object(session, "verify_intent"), \
                patch.object(session, "inspect_empty_pf", return_value={}), patch.object(session, "check_conflicts"), \
                patch.object(module.single, "replace_config") as edit, patch.object(session, "command") as command:
            with self.assertRaises(FileExistsError):
                session.install_package()
        edit.assert_not_called()
        command.assert_not_called()

    def test_preinstall_missing_product_anchor_is_not_queried_as_an_error(self):
        report = {"virtual_ips": [{"ip_address": module.single.VIP}]}
        with patch.object(self.session, "database", return_value=report), \
                patch.object(self.session, "owned", return_value=[module.single.VIP]), \
                patch.object(self.session, "pf", return_value="com.apple/200.AirDrop\ncom.apple/250.ApplicationFirewall\n") as pf:
            self.session.snapshot("pre-upgrade")
        pf.assert_called_once_with(["-a", "com.apple", "-s", "Anchors"])
        saved = json.loads((self.session.backup / "pre-upgrade.json").read_text())
        self.assertEqual(saved["pf_rules"], "")
        self.assertEqual(saved["pf_nat"], "")

    def test_persisted_active_rows_do_not_count_as_live_guest_readiness(self):
        report = {"owned_aliases": [], "pf_rules": "", "pf_nat": "", "decoys": [
            dict(zip(("id", "decoy_type", "bind_address", "port", "status"), row, strict=True))
            for row in module.EXPECTED_INTENT
        ]}
        self.assertFalse(module.publication_ready(report))
        report["owned_aliases"] = [module.single.VIP]
        self.assertFalse(module.publication_ready(report))

    def test_readiness_requires_exact_five_guarded_ports(self):
        mappings = [{"ip": module.single.VIP, "port": port, "backend": 50000 + i}
                    for i, port in enumerate((22, 445, 11434, 1234, 8765))]
        report = {"owned_aliases": [module.single.VIP], "pf_rules": "rules", "pf_nat": "nat", "decoys": [
            dict(zip(("id", "decoy_type", "bind_address", "port", "status"), row, strict=True))
            for row in module.EXPECTED_INTENT
        ]}
        with patch.object(module.upgrade, "verify_guarded_snapshot", return_value=mappings):
            self.assertTrue(module.publication_ready(report))
        for incomplete in (mappings[:-1], [*mappings, {"ip": "192.168.1.241", "port": 22, "backend": 50200}]):
            with patch.object(module.upgrade, "verify_guarded_snapshot", return_value=incomplete):
                self.assertFalse(module.publication_ready(report))

    def test_client_rejects_old_runner_status_and_wrong_boot(self):
        client_spec = importlib.util.spec_from_file_location("post_client", Path(module.__file__).with_name("mini_post_reboot_client.py"))
        client = importlib.util.module_from_spec(client_spec)
        client_spec.loader.exec_module(client)
        good = {"test_scope": module.SCOPE, "test_vips": [module.single.VIP],
                "boot_seconds": module.BOOT, "config_change_verified": True}
        for field, value in (("test_scope", "mini-single-ip-240"), ("boot_seconds", 1),
                             ("test_vips", ["192.168.1.241"]), ("config_change_verified", False)):
            with patch.object(client, "validate_original") as original, self.assertRaises(RuntimeError):
                client.validate_inputs({}, {}, {**good, field: value}, None)
            original.assert_not_called()
        with patch.object(client, "validate_original", return_value=True) as original:
            self.assertTrue(client.validate_inputs({}, {}, good, None))
        original.assert_called_once_with({}, {}, good, None)

    def test_bootstrap_pins_every_copied_input(self):
        fixtures = Path(module.__file__).parent
        script = (fixtures / "start-mini-post-reboot-acceptance.sh").read_text()
        copies = re.search(r"for name in (.+); do", script).group(1).split()
        pins = dict(re.findall(r"^verify_digest (\S+) ([a-f0-9]{64})$", script, re.M))
        self.assertEqual(set(copies), set(pins))
        self.assertEqual(pins["candidate.pkg"], module.launchd.PACKAGE_SHA)
        for name, expected in pins.items():
            if name == "candidate.pkg":
                continue
            source = fixtures / name
            if name == "single-ip-config.yaml":
                source = fixtures / "mini-single-ip-config.yaml"
            elif name == "approved-scope.md":
                source = fixtures.parent / "2026-09-30-mini-post-reboot-upgrade-scope.md"
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), expected, name)

    def test_preflight_accepts_pinned_app_larger_than_evidence_limit(self):
        # Exercise the actual preflight call site, not a mocked payload guard.
        # Ownership is simulated; bytes and the >1 MiB file are real/disposable.
        payload = self.root / "SquirrelOpsHome"
        payload.write_bytes(b"x" * 7791648)
        payload.chmod(0o755)
        expected = hashlib.sha256(payload.read_bytes()).hexdigest()
        actual = payload.lstat()
        root_info = os.stat_result((*actual[:4], 0, 0, *actual[6:]))
        self.session.old_executables = {payload: expected}
        class PayloadChecksCompleted(Exception):
            pass
        with patch.object(self.session, "assert_held_stopped"), \
                patch.object(module.base, "safe_directory"), \
                patch.object(module.base.pwd, "getpwnam", side_effect=lambda name: SimpleNamespace(
                    pw_uid=309 if name == "_squirrelops" else 501, pw_gid=309, pw_dir="/var/empty", pw_shell="/usr/bin/false")), \
                patch.object(module.base.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=309, gr_mem=[])), \
                patch.object(module.Path, "lstat", return_value=root_info), \
                patch.object(module.os, "fstat", return_value=root_info), \
                patch.object(module.upgrade, "RUNTIME", payload), patch.object(module.upgrade, "PYTHON_SHA", expected), \
                patch.object(module.single, "checked_config", side_effect=PayloadChecksCompleted):
            with self.assertRaises(PayloadChecksCompleted):
                self.session.validate_existing()

    def test_payload_metadata_rejects_unsafe_files_without_changing_evidence_guard(self):
        good = dict(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_gid=0, st_nlink=1, st_size=7791648)
        module.validate_payload_metadata(SimpleNamespace(**good), Path("test-app"))
        for key, value in (("st_uid", 501), ("st_gid", 20), ("st_nlink", 2),
                           ("st_mode", stat.S_IFLNK | 0o755), ("st_mode", stat.S_IFREG | 0o775),
                           ("st_mode", stat.S_IFREG | 0o757), ("st_size", 0), ("st_size", 64 * 1024**2 + 1)):
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                module.validate_payload_metadata(SimpleNamespace(**{**good, key: value}), Path("test-app"))
        with patch.object(module.Path, "lstat", return_value=SimpleNamespace(**good)):
            with self.assertRaisesRegex(RuntimeError, "Unsafe preflight evidence"):
                module.base.safe_file(Path("evidence"))

    def test_payload_guard_hashes_real_large_bytes_and_rejects_mismatch(self):
        payload = self.root / "app"
        payload.write_bytes(b"large-payload\n" * 100000)
        payload.chmod(0o755)
        actual = payload.lstat()
        root_info = os.stat_result((*actual[:4], 0, 0, *actual[6:]))
        expected = hashlib.sha256(payload.read_bytes()).hexdigest()
        with patch.object(module.Path, "lstat", return_value=root_info), patch.object(module.os, "fstat", return_value=root_info):
            module.check_payload(payload, expected)
            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                module.check_payload(payload, "0" * 64)

    def test_payload_guard_rejects_replacement_during_open_and_hash(self):
        payload = self.root / "app"
        payload.write_bytes(b"payload")
        actual = payload.lstat()
        root_info = os.stat_result((*actual[:4], 0, 0, *actual[6:]))
        swapped = os.stat_result((root_info.st_mode, root_info.st_ino + 1, *root_info[2:]))
        expected = hashlib.sha256(payload.read_bytes()).hexdigest()
        for observations in ((swapped,), (root_info, swapped)):
            with patch.object(module.Path, "lstat", return_value=root_info), \
                    patch.object(module.os, "fstat", side_effect=observations), \
                    self.assertRaisesRegex(RuntimeError, "Payload changed"):
                module.check_payload(payload, expected)

    def test_installer_verification_uses_the_same_payload_guard(self):
        import inspect
        self.assertIn("check_payload(path, expected)", inspect.getsource(self.session.install_package))
        self.assertIn("check_payload(path, expected)", inspect.getsource(self.session.validate_existing))

    @unittest.skipUnless(os.environ.get("SQUIRRELOPS_TEST_PACKAGE_EXPANDED"), "Requires the extracted pinned candidate")
    def test_real_candidate_payload_bytes_with_simulated_install_ownership(self):
        expanded = Path(os.environ["SQUIRRELOPS_TEST_PACKAGE_EXPANDED"])
        self.assertTrue(expanded.is_absolute())
        for installed, expected in {**self.session.new_executables, module.upgrade.RUNTIME: module.upgrade.PYTHON_SHA}.items():
            package = "sensor.pkg" if installed.is_relative_to(module.base.SENSOR) else "app.pkg"
            payload = expanded / package / "Payload" / installed.relative_to("/")
            if installed == module.base.HELPER:
                # App postinstall copies the bundled helper into the privileged
                # helper directory; that destination is not a package member.
                payload = expanded / "app.pkg/Payload/Applications/SquirrelOps Home.app/Contents/Library/LaunchServices/com.squirrelops.helper"
            actual = payload.lstat()
            # pkgutil extraction belongs to the developer. Simulate only the
            # installed owner; retain actual size/mode/link/identity and bytes.
            root_info = os.stat_result((*actual[:4], 0, 0, *actual[6:]))
            with self.subTest(path=str(installed)), patch.object(module.Path, "lstat", return_value=root_info), \
                    patch.object(module.os, "fstat", return_value=root_info):
                module.check_payload(payload, expected)


if __name__ == "__main__":
    unittest.main()
