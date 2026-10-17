"""Reboot recovery guards, plus opt-in root/system-domain launchd proof."""
import importlib.util
import json
import os
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

SOURCE = Path(__file__).with_name("mini_reboot_recovery.py")
spec = importlib.util.spec_from_file_location("recovery", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RecoveryGuards(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.session = m.Recovery(self.root)

    def test_receipt_is_durable_and_boot_bound(self):
        self.assertEqual(m.ROOT, Path("/Library/SquirrelOps/acceptance-backups"))
        receipt = {"schema": 1, "phase": "held_stopped", "boot_seconds": m.BOOT,
                   "disabled_jobs": list(m.upgrade.JOBS), "runtime_absent": True, "aliases_absent": True,
                   "product_rules_empty": True, "unrelated_policy_unchanged": True,
                   "pf_enablement_unchanged": True, "pf_references_unchanged": True, "intent_preserved": True}
        m.durable_receipt(receipt, m.BOOT)
        for key, value in (("boot_seconds", 1), ("phase", "stopped"), ("disabled_jobs", []), ("schema", 2)):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                m.durable_receipt({**receipt, key: value}, m.BOOT)
        for key in ("runtime_absent", "aliases_absent", "product_rules_empty", "unrelated_policy_unchanged",
                    "pf_enablement_unchanged", "pf_references_unchanged", "intent_preserved"):
            for value in (False, None, 1):
                with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                    m.durable_receipt({**receipt, key: value}, m.BOOT)

    def test_boot_and_disabled_state_parsing(self):
        self.assertEqual(m.boot_seconds("kern.boottime: { sec = 123, usec = 987 }"), 123)
        with self.assertRaises(RuntimeError):
            m.boot_seconds("unknown")
        name = m.SENSOR_JOB
        for value in ("disabled", "true"):
            self.assertTrue(m.disabled(f'"{name}" => {value}', name))
        for value in ("enabled", "false"):
            self.assertFalse(m.disabled(f'"{name}" => {value}', name))
        self.assertFalse(m.disabled("disabled services = { }", name))
        for text in (f'"{name}" => maybe', f'"{name}" => enabled\n"{name}" => disabled'):
            with self.assertRaises(RuntimeError):
                m.disabled(text, name)
        with self.assertRaises(RuntimeError):
            m.disabled('"com.apple.foo" => disabled', "com.apple.foo")

    def test_runtime_identity_is_bounded(self):
        rows = m.process_rows(f"309 887 1 {m.RUNTIME.with_name('python3')}\n"
                              f"309 1870 887 {m.upgrade.GUEST}\n309 1871 1 {m.upgrade.VM}\n"
                              "309 2000 1 /usr/sbin/distnoted\n0 888 1 /unrelated/daemon")
        self.assertEqual(set(m.runtime_rows(rows)), {887, 1870, 1871})
        for text in ("309 2 1 /bin/sh", f"0 2 1 {m.RUNTIME}", "309 2 1 /bin/sleep"):
            with self.assertRaises(RuntimeError):
                m.runtime_rows(m.process_rows(text))
        self.assertEqual(set(m.runtime_rows(m.process_rows("309 2 1 /bin/sleep"), True)), {2})
        for text in ("malformed", "309 2 1 /a\n309 2 1 /b"):
            with self.assertRaises(RuntimeError):
                m.process_rows(text)

    def test_macos_signed_nobody_uid_does_not_hide_or_block_sensor(self):
        # Exact unrelated row observed on the mini, alongside its known sensor.
        rows = m.process_rows("   -2   900     1 /usr/sbin/distnoted\n"
                              f"  309   887     1 {m.RUNTIME.with_name('python3')}\n")
        self.assertEqual(rows[900]["uid"], -2)
        self.assertEqual(set(m.runtime_rows(rows)), {887})
        with self.assertRaisesRegex(RuntimeError, "unexpected product identity"):
            m.runtime_rows(m.process_rows(f"-2 900 1 {m.RUNTIME}"))
        for row in ("--2 900 1 /a", "+2 900 1 /a", "-2 -900 1 /a", "-2 900 -1 /a",
                    "nobody 900 1 /a", "-2 900 1", "-2147483649 900 1 /a", "4294967296 900 1 /a"):
            with self.subTest(row=row), self.assertRaises(RuntimeError):
                m.process_rows(row)

    def test_live_inventory_excludes_only_verified_current_observer(self):
        sensor = f"309 887 1 {m.RUNTIME.with_name('python3')}\n"
        observer = f"0 910 911 {m.RUNTIME}\n"
        self.session.command = Mock(return_value=subprocess.CompletedProcess([], 0, sensor + observer, ""))
        with patch.object(m.os, "getpid", return_value=910), patch.object(m.os, "geteuid", return_value=0):
            rows = self.session.rows()
        self.assertEqual(set(rows), {887})
        self.assertEqual(set(m.runtime_rows(rows)), {887})
        # A second root Python is not the observer and must remain a blocker.
        self.session.command.return_value.stdout = sensor + observer + f"0 912 1 {m.RUNTIME}\n"
        with patch.object(m.os, "getpid", return_value=910), patch.object(m.os, "geteuid", return_value=0), \
                self.assertRaisesRegex(RuntimeError, "unexpected product identity"):
            m.runtime_rows(self.session.rows())
        for bad in ("0 910 1 /bin/sh\n", f"309 910 1 {m.RUNTIME}\n", ""):
            self.session.command.return_value.stdout = sensor + bad
            with self.subTest(row=bad), patch.object(m.os, "getpid", return_value=910), \
                    patch.object(m.os, "geteuid", return_value=0), self.assertRaises(RuntimeError):
                self.session.rows()

    def test_job_selection_and_inert_arm(self):
        text = f"system/{m.SENSOR_JOB} = {{\n\tpid = 887\n}}"
        self.assertEqual(m.job_pid(text, m.SENSOR_JOB), 887)
        with self.assertRaises(RuntimeError):
            m.job_pid(text, m.HELPER_JOB)
        with self.assertRaises(RuntimeError):
            m.job_pid(text.replace("\tpid = 887", "\tpid = 887\n\tpid = 888"), m.SENSOR_JOB)
        command = Mock()
        m.arm_next_launch(command, "system/" + m.SENSOR_JOB)
        command.assert_called_once_with(["/bin/launchctl", "debug", "system/" + m.SENSOR_JOB,
                                         "--program", "/bin/sleep", "--", "/bin/sleep", "2147483647"])

    def test_evidence_is_exclusive_private_and_not_linked(self):
        target = self.root / "receipt.json"
        m.private_write(target, b"proof")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            m.private_write(target, b"overwrite")
        link = self.root / "link"
        link.symlink_to(target)
        with self.assertRaises(FileExistsError):
            m.private_write(link, b"overwrite")
        self.assertEqual(m.checked_bytes(target, os.getuid(), {0o600}), b"proof")
        with self.assertRaises(RuntimeError):
            m.checked_bytes(link, os.getuid(), {0o600})
        os.link(target, self.root / "hardlink")
        with self.assertRaises(RuntimeError):
            m.checked_bytes(target, os.getuid(), {0o600})

    def test_unrelated_pf_comparison(self):
        before = {"": {"children": ["com.apple"], "-sr": "root", "-sn": "nat"},
                  "com.apple": {"children": [m.upgrade.PRODUCT_ANCHOR], "-sr": "", "-sn": ""},
                  m.upgrade.PRODUCT_ANCHOR: {"children": [], "-sr": "block", "-sn": "rdr"}}
        after = {key: value for key, value in before.items() if key != m.upgrade.PRODUCT_ANCHOR}
        after["com.apple"] = {"children": [], "-sr": "", "-sn": ""}
        self.assertEqual(m.Recovery.unrelated(before), m.Recovery.unrelated(after))
        after[""] = {**after[""], "-sr": "different"}
        self.assertNotEqual(m.Recovery.unrelated(before), m.Recovery.unrelated(after))

    def test_plan_only_is_nonmutating(self):
        result = subprocess.run([sys.executable, "-I", "-B", str(SOURCE)], capture_output=True, text=True, check=True)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["mode"], "plan_only")
        for key in ("install", "pf_enable_disable_or_reference_changes", "studio_changes", "little_snitch_changes"):
            self.assertFalse(plan[key])

    def prepared(self):
        s = self.session
        s.sensor_pid, s.helper_pid, s.started = 887, 888, "known start"
        s.original_rows = {887: {"uid": 309, "parent": 1, "executable": str(m.RUNTIME)}}
        s.original_rows[888] = {"uid": 0, "parent": 1, "executable": str(m.base.HELPER)}
        s.original_intent = [(1, "deep", "192.168.1.240", 445, "active")]
        s.policy = {m.upgrade.PRODUCT_ANCHOR: {"children": [], "-sr": "rules", "-sn": "nat"}}
        s.references, s.listeners = "private refs", {("0", "*:22")}
        s.assert_boot = Mock()
        s.hold_state = Mock(side_effect=[dict.fromkeys(m.upgrade.JOBS, False)] + [dict.fromkeys(m.upgrade.JOBS, True)] * 2)
        s.rows = Mock(side_effect=[s.original_rows, s.original_rows, {}, {}, {888: s.original_rows[888]}, {}])
        s.owned = Mock(return_value=["192.168.1.240"])
        s.inventory_policy = Mock(side_effect=[s.policy, {}, {}])
        s.pf_enabled = Mock(return_value=True)
        s.pf = Mock(return_value=s.references)
        s.no_aliases = Mock()
        s.native_listeners = Mock(return_value=s.listeners)
        s.database_backup = Mock(return_value=s.original_intent)
        sensor = f"system/{m.SENSOR_JOB} = {{\n\tpid = 887\n}}"
        helper = f"system/{m.HELPER_JOB} = {{\n\tpid = 888\n}}"
        s.job = Mock(side_effect=[sensor, helper, sensor, f"system/{m.SENSOR_JOB} = {{\n}}", None, helper, None])
        s.command = Mock(return_value=subprocess.CompletedProcess([], 0, s.started, ""))
        return s

    def test_stop_order_and_durable_success_receipt(self):
        s, events = self.prepared(), []
        s.command.side_effect = lambda args, **kw: (events.append(args) or subprocess.CompletedProcess(args, 0, s.started, ""))
        with patch.object(m.os, "kill", side_effect=lambda pid, sig: events.append(["signal", pid, sig])):
            s.stop_and_hold()
        signal_index = events.index(["signal", 887, signal.SIGTERM])
        debug_index = next(i for i, row in enumerate(events) if row[:2] == ["/bin/launchctl", "debug"])
        bootouts = [i for i, row in enumerate(events) if row[:2] == ["/bin/launchctl", "bootout"]]
        self.assertLess(debug_index, signal_index)
        self.assertTrue(all(i > signal_index for i in bootouts))
        self.assertEqual(len(bootouts), 2)
        m.durable_receipt(json.loads((self.root / "held-stopped.json").read_text()), m.BOOT)
        self.assertFalse(any(row[:1] == ["/sbin/pfctl"] for row in events))

    def test_failed_inert_arm_never_signals_or_boots_out(self):
        s = self.prepared()
        def command(args, **kw):
            if args[1] == "debug":
                raise RuntimeError("debug unavailable")
            return subprocess.CompletedProcess(args, 0, s.started, "")
        s.command.side_effect = command
        with patch.object(m.os, "kill") as kill, self.assertRaisesRegex(RuntimeError, "debug unavailable"):
            s.stop_and_hold()
        kill.assert_not_called()
        self.assertFalse(any(call.args[0][1] == "bootout" for call in s.command.call_args_list))

    def test_failed_hold_never_arms_or_signals(self):
        s = self.prepared()
        s.hold_state.side_effect = [dict.fromkeys(m.upgrade.JOBS, False)] * 2
        with patch.object(m.os, "kill") as kill, self.assertRaisesRegex(RuntimeError, "Persistent hold failed"):
            s.stop_and_hold()
        kill.assert_not_called()
        self.assertFalse(any(call.args[0][1] in ("debug", "bootout") for call in s.command.call_args_list))

    def test_surviving_guest_never_boots_out_or_removes_protection(self):
        s = self.prepared()
        s.rows.side_effect = None
        s.rows.return_value = s.original_rows
        with patch.object(m.os, "kill"), patch.object(m.time, "monotonic", side_effect=[0, 91]), \
                self.assertRaisesRegex(RuntimeError, "graceful budget"):
            s.stop_and_hold()
        s.no_aliases.assert_not_called()
        self.assertFalse(any(call.args[0][1] == "bootout" for call in s.command.call_args_list))
        self.assertFalse((self.root / "held-stopped.json").exists())

    def test_changed_pid_after_arm_is_not_signaled(self):
        s = self.prepared()
        s.rows.side_effect = [s.original_rows, {}]
        with patch.object(m.os, "kill") as kill, self.assertRaisesRegex(RuntimeError, "Sensor changed before signal"):
            s.stop_and_hold()
        kill.assert_not_called()

    def test_intent_drift_prevents_success_receipt(self):
        s = self.prepared()
        s.database_backup.return_value = [(1, "deep", "192.168.1.240", 445, "stopped")]
        with patch.object(m.os, "kill"), self.assertRaisesRegex(RuntimeError, "intent changed"):
            s.stop_and_hold()
        self.assertFalse((self.root / "held-stopped.json").exists())

    def test_returned_runtime_blocks_bootout(self):
        s = self.prepared()
        s.rows.side_effect = [s.original_rows, s.original_rows, {}, s.original_rows]
        with patch.object(m.os, "kill"), self.assertRaisesRegex(RuntimeError, "returned before bootout"):
            s.stop_and_hold()
        self.assertFalse(any(call.args[0][1] == "bootout" for call in s.command.call_args_list))

    def test_real_sqlite_backup_worker_uses_service_identity_and_preserves_source(self):
        parent = self.root / "live"
        parent.mkdir()
        source = parent / "squirrelops.db"
        with sqlite3.connect(source) as db:
            db.executescript("CREATE TABLE decoys(id,decoy_type,bind_address,port,status);"
                             "INSERT INTO decoys VALUES(1,'deep','192.168.1.240',445,'active');"
                             "CREATE TABLE virtual_ips(ip_address);"
                             "INSERT INTO virtual_ips VALUES('192.168.1.240');")
        before = source.read_bytes()
        run, metadata, checked, temporary = subprocess.run, Path.lstat, m.checked_bytes, tempfile.mkdtemp
        def launch(args, **kw):
            self.assertEqual((kw.pop("user"), kw.pop("group"), kw.pop("extra_groups")), (309, 309, []))
            self.assertEqual(args[1:4], ["-I", "-B", "-c"])
            # Execute the fixed worker against disposable test-owned SQLite.
            return run(args, **kw)
        def source_metadata(path):
            if path == parent:
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=309, st_gid=309)
            return metadata(path)
        self.session.command = Mock(return_value=subprocess.CompletedProcess([], 0, "one ACL-free metadata line", ""))
        with patch.object(m, "DB", source), patch.object(m, "RUNTIME", Path(sys.executable)), \
                patch.object(m.base, "safe_directory"), patch.object(m.os, "chown"), \
                patch.object(m.subprocess, "run", side_effect=launch), \
                patch.object(Path, "lstat", source_metadata), \
                patch.object(m, "checked_bytes", side_effect=lambda path, uid, modes, limit: checked(path, os.getuid(), modes, limit)), \
                patch.object(m.tempfile, "mkdtemp", side_effect=lambda **kw: temporary(prefix=kw["prefix"], dir=self.root)):
            self.assertEqual(self.session.database_backup("test"), [(1, "deep", "192.168.1.240", 445, "active")])
        self.assertEqual(source.read_bytes(), before)
        self.assertEqual(stat.S_IMODE((self.root / "test.sqlite").stat().st_mode), 0o600)


@unittest.skipUnless(sys.platform == "darwin" and os.geteuid() == 0 and os.environ.get("SQUIRRELOPS_TEST_LAUNCHD") == "1",
                     "Explicit root/system-domain opt-in; also tested by attended mini runner")
class NativeRecoveryTest(unittest.TestCase):
    def test_slow_cleanup_and_inert_replacement(self):
        with tempfile.TemporaryDirectory(prefix="squirrelops-recovery-probe-") as directory:
            def command(args, **kw):
                return subprocess.run(args, capture_output=True, text=True, timeout=kw.get("timeout", 30), check=kw.get("check", True))
            with patch.object(m, "RUNTIME", Path(sys.executable)):
                m.native_probe(command, Path(directory))


if __name__ == "__main__":
    unittest.main()
