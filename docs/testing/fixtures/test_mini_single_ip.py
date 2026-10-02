"""Disposable config files and mocked networking only; never installed paths."""
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


module = load("mini_single_ip_acceptance")
client = load("mini_single_ip_client")


class SingleIPTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "config.yaml"
        self.backup = self.root / "backup"
        self.backup.mkdir(mode=0o700)
        self.original = Path(__file__).with_name("mini-a5-config.yaml").read_bytes()
        self.revised = Path(__file__).with_name("mini-single-ip-config.yaml").read_bytes()
        module.private_write(self.config, self.original)
        # Actual local filesystem operations, but with the fixture's UID/GID.
        self.enterContext(patch.object(module, "CONFIG_OWNER", (os.getuid(), os.getgid())))
        self.enterContext(patch.object(module.base, "safe_directory"))
        self.enterContext(patch.object(module.base, "CONFIG_SHA", module.OLD_CONFIG_SHA))
        self.session = module.SingleIPUpgrade(self.root)
        self.session.backup = self.backup
        self.session.public = self.root

    def test_exactly_two_configuration_fields_change(self):
        import yaml
        self.assertEqual(module.narrow_config(self.original), self.revised)
        old, new = yaml.safe_load(self.original), yaml.safe_load(self.revised)
        expected = copy.deepcopy(old)
        expected["scouts"].update(virtual_ip_range_end=240, max_virtual_ips=1)
        self.assertEqual(new, expected)
        self.assertEqual(hashlib.sha256(self.revised).hexdigest(), module.NEW_CONFIG_SHA)

    def test_schema_and_profile_preserve_single_address_allocator(self):
        import yaml
        from squirrelops_home_sensor.config import Settings
        from squirrelops_home_sensor.__main__ import _canonicalize_profile_runtime
        from squirrelops_home_sensor.network.virtual_ip import IPAllocator
        config = Settings.model_validate(yaml.safe_load(self.revised)).model_dump()
        _canonicalize_profile_runtime(config)
        # Profile selection can override capacity, but never the range bounds.
        scouts = config["scouts"]
        allocator = IPAllocator("192.168.1.0/24", "192.168.1.1", "192.168.1.115",
                                scouts["virtual_ip_range_start"], scouts["virtual_ip_range_end"])
        self.assertEqual(allocator.allocate(50), [module.VIP])
        self.assertEqual(allocator.allocate(1), [])

    def test_revised_or_changed_source_is_never_rewritten(self):
        for source in (self.revised, self.original + b"\n# operator edit\n", self.original.replace(b"241", b"242")):
            with self.subTest(source_hash=hashlib.sha256(source).hexdigest()), self.assertRaises(RuntimeError):
                module.narrow_config(source)

    def test_atomic_edit_preserves_owner_mode_and_private_inverse(self):
        old_inode = self.config.stat().st_ino
        recheck = MagicMock()
        module.replace_config(self.config, self.backup, recheck)
        self.assertEqual(self.config.read_bytes(), self.revised)
        self.assertNotEqual(self.config.stat().st_ino, old_inode)
        self.assertEqual((self.config.stat().st_uid, self.config.stat().st_gid), module.CONFIG_OWNER)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.backup / "config-before.yaml").read_bytes(), self.original)
        journal = json.loads((self.backup / "config-change.json").read_text())
        self.assertEqual(journal["before_sha256"], module.OLD_CONFIG_SHA)
        self.assertEqual(journal["after_sha256"], module.NEW_CONFIG_SHA)
        self.assertEqual(len(journal["changes"]), 2)
        for path in self.backup.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        recheck.assert_called_once_with()

    def test_concurrent_edit_is_preserved(self):
        changed = self.original + b"# concurrent operator edit\n"
        with self.assertRaisesRegex(RuntimeError, "nothing overwritten"):
            module.replace_config(self.config, self.backup, lambda: self.config.write_bytes(changed))
        self.assertEqual(self.config.read_bytes(), changed)
        self.assertEqual((self.backup / "config-before.yaml").read_bytes(), self.original)

    def test_replaced_inode_even_with_equal_bytes_is_rejected(self):
        def replace():
            other = self.root / "operator.yaml"
            module.private_write(other, self.original)
            other.replace(self.config)
        with self.assertRaisesRegex(RuntimeError, "nothing overwritten"):
            module.replace_config(self.config, self.backup, replace)
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_guard_failure_keeps_original_and_backup(self):
        def fail():
            raise RuntimeError("runtime restarted")
        with self.assertRaisesRegex(RuntimeError, "runtime restarted"):
            module.replace_config(self.config, self.backup, fail)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual((self.backup / "config-before.yaml").read_bytes(), self.original)

    def test_existing_backup_is_never_overwritten(self):
        module.private_write(self.backup / "config-before.yaml", b"older inverse")
        with self.assertRaises(FileExistsError):
            module.replace_config(self.config, self.backup, lambda: None)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual((self.backup / "config-before.yaml").read_bytes(), b"older inverse")

    def test_symlink_hardlink_and_insecure_mode_are_rejected(self):
        linked = self.root / "linked.yaml"
        linked.symlink_to(self.config)
        with self.assertRaisesRegex(RuntimeError, "metadata"):
            module.checked_config(linked)
        os.link(self.config, self.root / "hardlink.yaml")
        with self.assertRaisesRegex(RuntimeError, "metadata"):
            module.checked_config(self.config)
        self.config.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "metadata"):
            module.checked_config(self.config)

    def test_prepare_requires_parent_approval_and_backup_guard(self):
        with patch.object(module.launchd.LaunchdUpgrade, "prepare_upgrade", side_effect=RuntimeError("not approved")), \
                patch.object(module, "replace_config") as change, self.assertRaisesRegex(RuntimeError, "not approved"):
            self.session.prepare_upgrade()
        change.assert_not_called()
        self.assertFalse(self.session.config_change_started)

    def test_config_invariant_changes_only_after_verified_edit(self):
        events = []
        def replace(_path, _backup, recheck):
            events.append(("replace", module.base.CONFIG_SHA))
            recheck()
        with patch.object(module.launchd.LaunchdUpgrade, "prepare_upgrade"), \
                patch.object(self.session, "check_config_acl"), patch.object(self.session, "check_effective_pool"), \
                patch.object(module, "replace_config", side_effect=replace), \
                patch.object(self.session, "validate_existing", side_effect=lambda: events.append(("validate", module.base.CONFIG_SHA))), \
                patch.object(self.session, "publish"), patch("builtins.print"):
            self.session.prepare_upgrade()
        self.assertEqual(events, [("replace", module.OLD_CONFIG_SHA), ("validate", module.OLD_CONFIG_SHA),
                                  ("validate", module.NEW_CONFIG_SHA)])
        self.assertTrue(self.session.config_change_verified)

    def test_effective_pool_rejects_persisted_override(self):
        for start, end, maximum in ((240, 241, 1), (239, 240, 1), (240, 240, 2)):
            settings = SimpleNamespace(scouts=SimpleNamespace(virtual_ip_range_start=start,
                                       virtual_ip_range_end=end, max_virtual_ips=maximum))
            with self.subTest(end=end, maximum=maximum), self.assertRaisesRegex(RuntimeError, "override"):
                module.validate_effective_pool(settings)
        module.validate_effective_pool(SimpleNamespace(scouts=SimpleNamespace(
            virtual_ip_range_start=240, virtual_ip_range_end=240, max_virtual_ips=1)))

    def test_persisted_override_stops_before_backup_or_edit(self):
        with patch.object(self.session, "check_effective_pool", side_effect=RuntimeError("override")), \
                patch.object(module.upgrade.Upgrade, "backup_existing") as backup, self.assertRaisesRegex(RuntimeError, "override"):
            self.session.backup_existing()
        backup.assert_not_called()

    def test_layered_config_errors_do_not_expose_values(self):
        with patch.object(module.base, "SENSOR", self.root / "absent-sensor"), \
                patch("squirrelops_home_sensor.config.load_settings", side_effect=ValueError("private-synthetic-value")):
            with self.assertRaises(RuntimeError) as raised:
                self.session.check_effective_pool(self.config)
        self.assertNotIn("private-synthetic-value", str(raised.exception))

    def test_config_acl_stops_edit(self):
        with patch.object(module.launchd.LaunchdUpgrade, "prepare_upgrade"), \
                patch.object(self.session, "command", return_value=MagicMock(stdout="file\n 0: extra ACL\n")), \
                patch.object(module, "replace_config") as change, self.assertRaisesRegex(RuntimeError, "ACL drift"):
            self.session.prepare_upgrade()
        change.assert_not_called()

    def test_ledger_rejects_studio_address(self):
        self.assertEqual(module.base.parse_ledger("192.168.1.240|en0\n"), [module.VIP])
        with self.assertRaisesRegex(RuntimeError, "approved scope"):
            module.base.parse_ledger("192.168.1.241|en0\n")

    def test_probe_is_bounded_to_240_and_retains_reply_evidence(self):
        from scapy.all import ARP, Ether
        response = Ether() / ARP(op=2, psrc=module.VIP, hwsrc="02:00:00:00:00:01")
        for answered in ([], [(None, response)]):
            with patch("scapy.all.srp", return_value=(answered, [])) as probe:
                if answered:
                    with self.assertRaisesRegex(RuntimeError, "240 answered ARP"):
                        self.session.check_conflicts()
                else:
                    self.session.check_conflicts()
            request = probe.call_args.args[0]
            self.assertEqual(request[ARP].pdst, module.VIP)
            self.assertEqual(probe.call_args.kwargs, {"iface": "en0", "timeout": 2, "retry": 2, "verbose": False})
            evidence = json.loads((self.root / f"arp-check-{self.session.arp_checks}.json").read_text())
            self.assertEqual(evidence["reply_count"], len(answered))
            self.assertEqual(evidence["target"], module.VIP)

    def test_packet_capture_excludes_studio_and_uses_no_active_probes(self):
        self.session.config_change_verified = True
        process = MagicMock()
        process.poll.return_value = None
        with patch.object(module.subprocess, "Popen", return_value=process) as popen, \
                patch.object(module.time, "sleep"), patch.object(module.select, "select", return_value=([0], [], [])), \
                patch.object(module.os, "read", return_value=b"\n"), patch.object(self.session, "snapshot"), patch("builtins.print"):
            self.session.observe()
        self.assertEqual(popen.call_count, 2)
        for call in popen.call_args_list:
            self.assertEqual(call.args[0][-1], "host 192.168.1.7 and host 192.168.1.240")
            self.assertNotIn("192.168.1.241", " ".join(call.args[0]))
        for _, output, _ in self.session.captures:
            output.close()

    def test_scope_and_config_verification_are_in_readiness(self):
        self.session.publish("ready_for_tests", package_sha256=self.session.package_sha)
        data = json.loads((self.root / "status.json").read_text())
        self.assertEqual(data["test_scope"], module.SCOPE)
        self.assertEqual(data["test_vips"], [module.VIP])
        self.assertFalse(data["config_change_verified"])

    def test_plan_modes_do_not_touch_host(self):
        for script in (module.__file__, client.__file__):
            result = subprocess.run([sys.executable, "-I", "-B", script], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("plan", result.stdout.lower())

    def client_inputs(self):
        now = 1790709500
        endpoints = {"guest_ip": module.VIP, "mappings": [
            {"ip": module.VIP, "port": port, "backend": 50000 + i} for i, port in enumerate((22, 445, 1234, 11434, 8765))]}
        login = {"ip": module.VIP, "username": "buildbot", "password": "Juniper!123456"}
        status = {"phase": "ready_for_tests", "sensor_uid": 309, "package_sha256": module.launchd.PACKAGE_SHA,
                  "time": datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "remaining_seconds": 1100,
                  "test_scope": module.SCOPE, "test_vips": [module.VIP], "config_change_verified": True}
        return endpoints, login, status, now

    def test_client_requires_verified_single_ip_scope(self):
        self.assertEqual(client.validate_inputs(*self.client_inputs()), module.VIP)
        for field, value in (("test_scope", "old"), ("test_vips", ["192.168.1.241"]), ("config_change_verified", False)):
            endpoints, login, status, now = self.client_inputs()
            status[field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                client.validate_inputs(endpoints, login, status, now)

    def test_client_cannot_target_studio_even_with_candidate_and_scope(self):
        endpoints, login, status, now = self.client_inputs()
        endpoints["mappings"].append({"ip": "192.168.1.241", "port": 22, "backend": 51000})
        with self.assertRaises(RuntimeError):
            client.validate_inputs(endpoints, login, status, now)
        endpoints["guest_ip"] = login["ip"] = "192.168.1.241"
        with self.assertRaises(RuntimeError):
            client.validate_inputs(endpoints, login, status, now)


if __name__ == "__main__":
    unittest.main()
