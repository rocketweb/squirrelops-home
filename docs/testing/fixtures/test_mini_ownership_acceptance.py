"""Disposable SQLite recovery tests; never touch installed data or networking."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("ownership", Path(__file__).with_name("mini_ownership_acceptance.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OwnershipGuards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE decoys (id INTEGER PRIMARY KEY, port INTEGER, decoy_type TEXT,
                status TEXT, bind_address TEXT, retired_at TEXT, host_id INTEGER,
                is_primary INTEGER, config TEXT, connection_count INTEGER, updated_at TEXT);
            CREATE TABLE credentials (id INTEGER PRIMARY KEY, content TEXT);
            CREATE TABLE history (id INTEGER PRIMARY KEY, content TEXT);
            INSERT INTO credentials VALUES (1, 'synthetic private bait');
            INSERT INTO history VALUES (1, 'preserve existing alert');
        """)
        for ident, port in module.EXPECTED.items():
            self.db.execute("INSERT INTO decoys VALUES (?,?,'deep','active','192.168.1.240',NULL,7,?, ?,0,'old')",
                            (ident, port, int(ident == 1), '{"synthetic":true}'))
        self.original = module.decoy_rows(self.db)
        self.db.execute("UPDATE decoys SET status='stopped', updated_at='failure'")
        self.db.execute("INSERT INTO decoys VALUES (6,60556,'dev_server','active','192.168.1.115',NULL,NULL,0,'{}',9,'old')")
        self.db.execute("INSERT INTO decoys VALUES (7,8080,'mimic','stopped','192.168.1.241',NULL,NULL,0,'{}',2,'old')")
        self.db.commit()
        self.journal = self.root / "recovery.json"

    def test_status_only_recovery_preserves_every_other_field_and_table(self):
        before = module.preserved_digest(self.db)
        preview = module.restore_five(self.db, self.original, self.journal)
        self.assertEqual([row['id'] for row in preview], [1, 2, 3, 4, 5])
        self.assertEqual(module.preserved_digest(self.db), before)
        self.assertTrue(all(row['status'] == 'active' for row in module.decoy_rows(self.db)))
        self.assertEqual([tuple(row) for row in self.db.execute("SELECT id,status FROM decoys WHERE id>5")],
                         [(6, 'active'), (7, 'stopped')])
        evidence = json.loads(self.journal.read_text())
        self.assertTrue(all(row['status'] == 'stopped' for row in evidence['before']))

    def test_private_journal_does_not_depend_on_callers_umask(self):
        previous = os.umask(0o022)
        try:
            module.restore_five(self.db, self.original, self.journal)
        finally:
            os.umask(previous)
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)

    def test_recovery_rejects_all_unexpected_row_drift_without_writing(self):
        for field, value in [('port', 23), ('id', 8), ('decoy_type', 'mimic'), ('status', 'active'),
                             ('bind_address', '192.168.1.115'), ('retired_at', 'today'),
                             ('host_id', 99), ('is_primary', 0), ('config', '{}'), ('connection_count', 1)]:
            current = module.decoy_rows(self.db)
            current[0][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                module.validate_recovery(current, self.original)
        self.assertTrue(all(row['status'] == 'stopped' for row in module.decoy_rows(self.db)))
        self.assertFalse(self.journal.exists())

    def test_missing_extra_and_reordered_rows_rejected(self):
        rows = module.decoy_rows(self.db)
        for current in (rows[:-1], rows + [rows[0]], list(reversed(rows))):
            with self.subTest(count=len(current)), self.assertRaises(RuntimeError):
                module.validate_recovery(current, self.original)

    def test_historical_operator_stop_is_never_reactivated(self):
        original = copy.deepcopy(self.original)
        original[0]['status'] = 'stopped'
        with self.assertRaisesRegex(RuntimeError, 'Historical host'):
            module.restore_five(self.db, original, self.journal)
        self.assertFalse(self.journal.exists())

    def test_recovery_is_one_shot_and_does_not_overwrite_journal(self):
        self.journal.write_text('existing private evidence')
        with self.assertRaises(FileExistsError):
            module.restore_five(self.db, self.original, self.journal)
        self.assertEqual(self.journal.read_text(), 'existing private evidence')
        self.assertTrue(all(row['status'] == 'stopped' for row in module.decoy_rows(self.db)))

    def test_trigger_side_effect_rolls_back_entire_transaction(self):
        self.db.executescript("""
            CREATE TRIGGER unwanted AFTER UPDATE ON decoys
            BEGIN UPDATE history SET content='changed'; END;
        """)
        before = module.preserved_digest(self.db)
        with self.assertRaisesRegex(RuntimeError, 'outside the five'):
            module.restore_five(self.db, self.original, self.journal)
        self.assertEqual(module.preserved_digest(self.db), before)
        self.assertTrue(all(row['status'] == 'stopped' for row in module.decoy_rows(self.db)))

    def test_prepare_requires_both_attended_approval_and_backup(self):
        for approved, backup in ((False, True), (True, False)):
            session = module.OwnershipUpgrade(self.root)
            session.recovery_approved, session.backup_verified = approved, backup
            session.backup = self.root
            with patch.object(module.sqlite3, 'connect') as connect, self.assertRaises(RuntimeError):
                session.prepare_upgrade()
            connect.assert_not_called()

    def test_preflight_decline_does_not_recover_or_install(self):
        session = module.OwnershipUpgrade(self.root)
        with patch.object(module.upgrade.Upgrade, 'preflight'), \
                patch.object(session, 'historical_rows', return_value=self.original), \
                patch.object(session, 'checked_rows', return_value=module.decoy_rows(self.db)), \
                patch('builtins.input', return_value=''), patch('builtins.print'), \
                patch.object(module, 'restore_five') as restore, self.assertRaisesRegex(RuntimeError, 'did not approve'):
            session.preflight()
        restore.assert_not_called()
        self.assertFalse(getattr(session, 'recovery_approved', False))

    def test_cleanup_receipt_survives_later_error_status(self):
        session = module.OwnershipUpgrade(self.root)
        session.public = self.root
        session.publish('stopped', own_pf_reference_released=True, aliases_absent=True)
        session.publish('needs_review', reason='protocol readiness failed')
        receipt = json.loads((self.root / 'cleanup.json').read_text())
        self.assertEqual(receipt['phase'], 'stopped')
        self.assertTrue(receipt['own_pf_reference_released'])
        self.assertEqual(json.loads((self.root / 'status.json').read_text())['phase'], 'needs_review')

    def test_new_artifact_and_existing_receipt_are_explicit(self):
        session = module.OwnershipUpgrade(self.root)
        self.assertNotEqual(session.package_sha, module.upgrade.PACKAGE_SHA)
        self.assertEqual(session.receipt_time, 1790711659)
        self.assertIn(module.ORCHESTRATOR, session.new_executables)

    def test_restart_rejects_persisted_intent_damage_before_bootstrap(self):
        self.db.execute("UPDATE decoys SET status='active' WHERE decoy_type='deep'")
        self.db.commit()
        path = self.root / 'restart.sqlite'
        with sqlite3.connect(path) as target:
            self.db.backup(target)
        session = module.OwnershipUpgrade(self.root)
        def damaged_stop(_label):
            with sqlite3.connect(path) as target:
                target.execute("UPDATE decoys SET status='stopped' WHERE id=1")
        with patch.object(module, 'DATABASE', path), patch.object(module.upgrade.Upgrade, 'install'), \
                patch.object(session, 'snapshot'), patch.object(session, 'stop_job', side_effect=damaged_stop), \
                patch.object(session, 'processes', return_value=[]), patch.object(session, 'assert_no_test_network'), \
                patch.object(session, 'owned', return_value=[]), patch.object(session, 'command') as command, \
                patch('builtins.print'), self.assertRaisesRegex(RuntimeError, 'persisted Studio intent'):
            session.install()
        command.assert_not_called()

    def test_restart_waits_for_guest_exit_and_alias_withdrawal(self):
        self.db.execute("UPDATE decoys SET status='active' WHERE decoy_type='deep'")
        self.db.commit()
        path = self.root / 'restart.sqlite'
        with sqlite3.connect(path) as target:
            self.db.backup(target)
        for processes, aliases, reason in (([123], [], 'survived restart'), ([], ['192.168.1.240'], 'Aliases survived')):
            session = module.OwnershipUpgrade(self.root)
            with patch.object(module, 'DATABASE', path), patch.object(module.upgrade.Upgrade, 'install'), \
                    patch.object(session, 'snapshot'), patch.object(session, 'stop_job'), \
                    patch.object(session, 'processes', return_value=processes), patch.object(session, 'assert_no_test_network'), \
                    patch.object(session, 'owned', return_value=aliases), patch.object(session, 'command') as command, \
                    patch.object(module.time, 'monotonic', side_effect=[0, 70]), patch('builtins.print'), \
                    self.assertRaisesRegex(RuntimeError, reason):
                session.install()
            command.assert_not_called()

    def test_default_is_readonly_plan(self):
        result = subprocess.run([sys.executable, module.__file__], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['mode'], 'plan_only')
        self.assertFalse(data['third_party_filter_rule_changes'])
        self.assertEqual(data['restore_status_ids'], [1, 2, 3, 4, 5])

    def read_checked_fixture(self, *, file_changes=None, parent_changes=None, acl_path=None, acl_output=None):
        path = self.root / 'guard.sqlite'
        with sqlite3.connect(path) as target:
            self.db.backup(target)
        parent = dict(st_mode=stat.S_IFDIR | 0o700, st_uid=309, st_gid=309)
        file = dict(st_mode=stat.S_IFREG | 0o644, st_uid=309, st_gid=309, st_nlink=1, st_size=512000)
        parent.update(parent_changes or {})
        file.update(file_changes or {})
        session = module.OwnershipUpgrade(self.root)
        def metadata(candidate):
            self.assertIn(candidate, (path, path.parent))
            return SimpleNamespace(**(file if candidate == path else parent))
        def listing(args):
            self.assertEqual(args[:2], ['/bin/ls', '-lde'])
            self.assertIn(args[2], (str(path), str(path.parent)))
            output = '-rw-r--r-- 1 _squirrelops _squirrelops 512000 Sep 29 20:00 ' + args[2] + '\n'
            if (acl_path == 'file' and args[2] == str(path)) or (acl_path == 'parent' and args[2] == str(path.parent)):
                output = acl_output if acl_output is not None else output + ' 0: group:everyone allow read,search\n'
            return SimpleNamespace(stdout=output)
        with patch.object(module, 'DATABASE', path), patch.object(session, 'validate_existing'), \
                patch.object(Path, 'lstat', autospec=True, side_effect=metadata), \
                patch.object(session, 'command', side_effect=listing), \
                patch.object(module.sqlite3, 'connect', wraps=sqlite3.connect) as connect:
            try:
                return session.checked_rows()
            except RuntimeError:
                connect.assert_not_called()
                raise

    def test_installed_644_database_inside_private_directory_is_accepted(self):
        self.assertEqual(self.read_checked_fixture(), module.decoy_rows(self.db))

    def test_private_600_database_remains_accepted(self):
        self.assertEqual(self.read_checked_fixture(file_changes={'st_mode': stat.S_IFREG | 0o600}),
                         module.decoy_rows(self.db))

    def test_database_rejects_unsafe_metadata_before_sqlite_open(self):
        for changes in ({'st_mode': stat.S_IFREG | 0o664}, {'st_mode': stat.S_IFREG | 0o666},
                        {'st_mode': stat.S_IFREG | 0o755}, {'st_mode': stat.S_IFREG | 0o4644},
                        {'st_mode': stat.S_IFLNK | 0o644}, {'st_mode': stat.S_IFDIR | 0o644},
                        {'st_uid': 0}, {'st_gid': 20}, {'st_nlink': 2}, {'st_size': 64 * 1024**2 + 1}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                self.read_checked_fixture(file_changes=changes)

    def test_database_rejects_accessible_or_wrongly_owned_parent(self):
        for changes in ({'st_mode': stat.S_IFDIR | 0o755}, {'st_mode': stat.S_IFDIR | 0o750},
                        {'st_mode': stat.S_IFDIR | 0o770}, {'st_mode': stat.S_IFLNK | 0o700},
                        {'st_mode': stat.S_IFREG | 0o700}, {'st_uid': 501}, {'st_gid': 20}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                self.read_checked_fixture(file_changes={'st_mode': stat.S_IFREG | 0o600}, parent_changes=changes)

    def test_database_rejects_extended_acls_on_file_or_parent(self):
        for target in ('file', 'parent'):
            with self.subTest(target=target), self.assertRaises(RuntimeError):
                self.read_checked_fixture(file_changes={'st_mode': stat.S_IFREG | 0o600}, acl_path=target)

    def test_database_rejects_missing_acl_inventory(self):
        with self.assertRaises(RuntimeError):
            self.read_checked_fixture(file_changes={'st_mode': stat.S_IFREG | 0o600}, acl_path='parent', acl_output='')

    def test_wrong_metadata_reports_safe_numeric_details(self):
        with self.assertRaisesRegex(RuntimeError, r'uid=0.*gid=309.*mode=0644.*links=1.*bytes=512000'):
            self.read_checked_fixture(file_changes={'st_uid': 0})

    def test_bootstrap_pins_match_current_runner_and_scope(self):
        fixture = Path(__file__).parent
        bootstrap = (fixture / 'start-mini-ownership-acceptance.sh').read_text()
        pins = dict(line.split()[1:] for line in bootstrap.splitlines() if line.startswith('verify_digest '))
        self.assertEqual(set(pins), {'candidate.pkg', 'mini_acceptance.py', 'mini_upgrade_acceptance.py',
                                    'mini_ownership_acceptance.py', 'approved-scope.md'})
        self.assertEqual(pins.pop('candidate.pkg'), module.PACKAGE_SHA)
        for name, digest in pins.items():
            path = (fixture.parent / '2026-09-29-mini-ownership-upgrade-scope.md'
                    if name == 'approved-scope.md' else fixture / name)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest, name)


if __name__ == '__main__':
    unittest.main()
