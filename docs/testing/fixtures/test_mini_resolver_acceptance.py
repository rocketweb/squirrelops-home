"""Resolver candidate checks using disposable files and mock host operations only."""
from datetime import datetime, timezone
from contextlib import ExitStack, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server = load("mini_resolver_acceptance")
client = load("mini_resolver_client")


class ResolverAcceptance(unittest.TestCase):
    def test_previous_cleanup_is_exact_and_complete(self):
        path = ROOT.parent / "evidence/2026-10-01-mini-smb-diagnostic/cleanup-status.json"
        if not path.is_file():
            self.skipTest("Requires retained private Mini cleanup evidence")
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), server.CLEANUP_SHA)
        receipt = json.loads(path.read_text())
        server.validate_cleanup(receipt)
        for key in receipt:
            changed = {**receipt, key: None}
            if key != "time":
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    server.validate_cleanup(changed)

    def test_claim_cannot_select_another_backup_or_candidate(self):
        claim = {"package_sha256": server.PREVIOUS_PACKAGE_SHA,
                 "backup": str(server.BASE / "mini-smb-20261001.abc_123")}
        self.assertEqual(server.backup_from_claim(claim), Path(claim["backup"]))
        for changed in ({**claim, "package_sha256": server.PACKAGE_SHA},
                        {**claim, "backup": "/tmp/mini-smb-20261001.abc"},
                        {**claim, "backup": str(server.BASE / "mini-relay-20261001.abc")},
                        {**claim, "backup": str(server.BASE / "../mini-smb-20261001.abc")},
                        {"backup": None}):
            with self.subTest(claim=changed), self.assertRaises(RuntimeError):
                server.backup_from_claim(changed)

    def test_plan_only_modes(self):
        for module in (server, client):
            result = subprocess.run([sys.executable, "-B", module.__file__], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("plan", result.stdout.lower())
        plan = json.loads(subprocess.check_output([sys.executable, "-B", server.__file__], text=True))
        self.assertEqual(plan["package_sha256"], server.PACKAGE_SHA)
        self.assertEqual(plan["test_vips"], ["192.168.1.240"])
        self.assertFalse(plan["third_party_filter_rule_changes"])

    def test_approval_still_required_and_methods_are_inherited(self):
        session = server.ResolverUpgrade(Path("/tmp/not-a-run"))
        with patch.object(session, "command") as command:
            with self.assertRaisesRegex(RuntimeError, "Approval"):
                session.install_package()
            command.assert_not_called()
        for method in ("install_package", "restart_check", "stop", "release_reference", "observe"):
            self.assertIs(getattr(server.ResolverUpgrade, method), getattr(server.relay.RelayDiagnosticUpgrade, method))
        self.assertEqual(session.receipt_time, 1790818368)
        self.assertEqual(server.relay.PACKAGE_SHA, server.PACKAGE_SHA)
        self.assertEqual(server.relay.SCOPE, server.SCOPE)

    def test_old_guest_is_checked_before_mutations_and_new_guest_before_readiness(self):
        session = server.ResolverUpgrade(Path("/tmp/not-a-run"))
        with patch.object(server.post.PostRebootUpgrade, "validate_existing") as baseline, \
                patch.object(server, "verify_bundle") as verify:
            session.validate_existing()
            baseline.assert_called_once()
            verify.assert_called_once_with(server.OLD_MANIFEST_SHA)
        with patch.object(server.relay.RelayDiagnosticUpgrade, "wait_until_ready") as ready, \
                patch.object(server, "verify_bundle", side_effect=RuntimeError("digest changed")):
            with self.assertRaisesRegex(RuntimeError, "digest changed"):
                session.wait_until_ready()
            ready.assert_not_called()

    def test_bootstrap_pins_every_input(self):
        text = (ROOT / "start-mini-resolver-acceptance.sh").read_text()
        pins = dict(re.findall(r"^verify_digest (\S+) ([a-f0-9]{64})$", text, re.M))
        self.assertEqual(set(pins), {*server.ResolverUpgrade.input_names, "candidate.pkg"})
        self.assertEqual(pins.pop("candidate.pkg"), server.PACKAGE_SHA)
        for name, expected in pins.items():
            path = ROOT / name
            if name == "approved-scope.md":
                path = ROOT.parent / "2026-10-01-mini-resolver-scope.md"
            elif name == "single-ip-config.yaml":
                path = ROOT / "mini-single-ip-config.yaml"
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected, name)
        self.assertLess(text.index("verify_digest approved-scope.md"), text.index("/usr/sbin/pkgutil --expand-full"))
        self.assertIn('"$runtime" -I -B "$task_dir/mini_resolver_acceptance.py"', text)

    @unittest.skipUnless(os.environ.get("SQUIRRELOPS_TEST_RESOLVER_PACKAGE_EXPANDED"), "Requires resolver payload")
    def test_exact_payload_pins(self):
        expanded = Path(os.environ["SQUIRRELOPS_TEST_RESOLVER_PACKAGE_EXPANDED"])
        pins = {**server.ResolverUpgrade.new_executables, server.upgrade.RUNTIME: server.upgrade.PYTHON_SHA}
        for installed, expected in pins.items():
            component = "sensor.pkg" if installed.is_relative_to(server.base.SENSOR) else "app.pkg"
            payload = expanded / component / "Payload" / installed.relative_to("/")
            if installed == server.base.HELPER:
                payload = expanded / "app.pkg/Payload/Applications/SquirrelOps Home.app/Contents/Library/LaunchServices/com.squirrelops.helper"
            with self.subTest(path=str(installed)):
                self.assertEqual(hashlib.sha256(payload.read_bytes()).hexdigest(), expected)


class ResolverClient(unittest.TestCase):
    def inputs(self):
        now = 1790888400
        endpoints = {"guest_ip": "192.168.1.240", "mappings": [
            {"ip": "192.168.1.240", "port": port, "backend": 50000 + i}
            for i, port in enumerate((22, 445, 1234, 11434, 8765))]}
        login = {"ip": "192.168.1.240", "username": "buildbot", "password": "Juniper!123456"}
        status = {"phase": "ready_for_tests", "sensor_uid": 309, "remaining_seconds": 1100,
                  "package_sha256": server.PACKAGE_SHA, "test_scope": server.SCOPE,
                  "test_vips": ["192.168.1.240"], "boot_seconds": server.post.BOOT,
                  "configuration_unchanged": True, "config_change_verified": True,
                  "time": datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        return endpoints, login, status, now

    def test_readiness_scope_pin_and_freshness(self):
        self.assertEqual(client.validate_inputs(*self.inputs()), "192.168.1.240")
        for key, value in (("package_sha256", server.PREVIOUS_PACKAGE_SHA), ("test_scope", "old"),
                           ("test_vips", ["192.168.1.241"]), ("boot_seconds", 1),
                           ("configuration_unchanged", False), ("config_change_verified", False),
                           ("remaining_seconds", 599), ("phase", "stopped")):
            endpoints, login, status, now = self.inputs()
            status[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                client.validate_inputs(endpoints, login, status, now)
        endpoints, login, status, now = self.inputs()
        with self.assertRaisesRegex(RuntimeError, "Stale"):
            client.validate_inputs(endpoints, login, status, now + 31)

    def test_exact_five_private_mappings_only(self):
        endpoints, login, status, now = self.inputs()
        endpoints["mappings"].append({"ip": "192.168.1.240", "port": 8080, "backend": 51000})
        with self.assertRaises(RuntimeError):
            client.validate_inputs(endpoints, login, status, now)
        endpoints["mappings"].pop()
        endpoints["mappings"][1]["backend"] = endpoints["mappings"][0]["backend"]
        with self.assertRaises(RuntimeError):
            client.validate_inputs(endpoints, login, status, now)

    def test_smb_uses_empty_config_no_kerberos_and_direct_445(self):
        arguments = client.smb_arguments("192.168.1.240")
        for value in ("/dev/null", "--use-kerberos=off", "192.168.1.240", "445"):
            self.assertIn(value, arguments)
        self.assertNotIn("-N", arguments)  # Authenticated calls must still prompt once.
        self.assertEqual(client.anonymous_arguments("192.168.1.240")[-5:],
                         ["-L", "//192.168.1.240", "-N", "-U", "%"])

    def test_slow_success_cannot_pass_resolver_gate(self):
        self.assertTrue(client.timing_ok("smb_share_discovery", 0.8))
        self.assertTrue(client.timing_ok("smb_share_discovery", 5.0))
        self.assertFalse(client.timing_ok("smb_share_discovery", 5.001))
        self.assertFalse(client.timing_ok("smb_share_discovery", 20.841))
        self.assertTrue(client.timing_ok("sftp_read_write_delete", 8.0))

    def test_slow_share_list_stops_before_authentication_and_cannot_retry(self):
        endpoints, login, status, now = self.inputs()
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            directory = MagicMock()
            directory.parent = Path("/root")
            directory.name = "squirrelops-mini-resolver-client.synthetic"
            directory.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
            directory.__truediv__.side_effect = lambda name: Path(tmp) / name
            child = MagicMock()
            child.expect.return_value = 1  # EOF, without a password prompt.
            child.before = "Engineering Builds Time Machine Backups IPC$"
            child.exitstatus = 0
            fake_pexpect = SimpleNamespace(spawn=MagicMock(return_value=child), EOF="EOF", TIMEOUT="TIMEOUT")
            stack.enter_context(patch.dict(sys.modules, {"pexpect": fake_pexpect}))
            stack.enter_context(patch.object(client.os, "umask"))
            stack.enter_context(patch.object(client, "safe_input", side_effect=lambda _, name: {
                "endpoints.json": endpoints, "login.json": login, "status.json": status}[name]))
            stack.enter_context(patch.object(client.time, "time", return_value=now))
            stack.enter_context(patch.object(client.time, "monotonic", side_effect=[100, 120.841]))
            stack.enter_context(patch.object(client.subprocess, "run", return_value=SimpleNamespace(
                stdout='[{"dev":"wlp0s20f3","prefsrc":"192.168.1.7"}]')))
            banner = stack.enter_context(patch.object(client, "banner_probe", return_value={"passed": True}))
            network = stack.enter_context(patch.object(client.socket, "create_connection",
                                                       side_effect=AssertionError("Unapproved later probe")))
            response = MagicMock(status=200)
            response.read.return_value = b"{}"
            connection = MagicMock()
            connection.getresponse.return_value = response
            stack.enter_context(patch.object(client.http.client, "HTTPConnection", return_value=connection))
            stack.enter_context(patch.object(client, "http_payload_ok", return_value=True))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(client.run(directory), 1)
            rows = [json.loads(line) for line in (Path(tmp) / "results.jsonl").read_text().splitlines()]
            discovery = next(row for row in rows if row["name"] == "smb_share_discovery")
            self.assertFalse(discovery["passed"])
            self.assertEqual(discovery["elapsed_seconds"], 20.841)
            self.assertEqual(rows[-1]["name"], "protocol_gate")
            self.assertFalse(rows[-1]["passed"])
            fake_pexpect.spawn.assert_called_once()
            self.assertEqual(fake_pexpect.spawn.call_args.args,
                             ("/usr/bin/smbclient", client.anonymous_arguments("192.168.1.240")[1:]))
            child.sendline.assert_not_called()
            network.assert_not_called()
            banner.reset_mock()
            with self.assertRaises(FileExistsError):
                client.run(directory)
            banner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
