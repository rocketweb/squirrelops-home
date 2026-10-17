"""Second bounded A5 experiment. Reuses the original preservation/cleanup engine."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile


def sibling(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


base = sibling("runner")
inspector = sibling("inspect_completed")
PHASES = ("edge_healthy", "established_replacement", "half_open_start",
          "half_open_wrong_uid", "half_open_quarantine")
SOURCE_PORTS = (42839, 42840)


def half_open(rows, index):
    return any({"ip": base.IPS[index], "port": base.PORTS[index]} in row["endpoints"]
               and {"ip": base.PEER, "port": SOURCE_PORTS[index]} in row["endpoints"]
               and set(row["state"].split(":")) <= {"SYN_SENT", "SYN_RCVD", "ESTABLISHED"}
               and bool(set(row["state"].split(":")) & {"SYN_SENT", "SYN_RCVD"}) for row in rows)


def listener_records(text):
    pid = uid = None
    result = []
    for line in text.splitlines():
        if line.startswith("p"):
            pid, uid = int(line[1:]), None
        elif line.startswith("u"):
            uid = int(line[1:])
        elif line.startswith("n") and line[1:] in {
                *(ip + ":" + str(port) for ip, port in zip(base.IPS, base.PORTS)),
                *("*:" + str(port) for port in base.PORTS)}:
            base.require(pid is not None and uid in (309, 501), "Unexpected disposable listener owner")
            result.append({"pid": pid, "uid": uid, "endpoint": line[1:]})
    return result


class EdgeSession(base.Session):
    def child_event(self, child, expected, timeout=8):
        until = base.clock() + timeout
        while base.clock() < until:
            row = base.read_line(child, max(0.01, until - base.clock()))
            with (self.root / ("edge-child-%s.jsonl" % child.pid)).open("a") as stream:
                stream.write(json.dumps(row) + "\n")
            if row.get("event") in expected:
                return row
        raise RuntimeError("Child event deadline")

    def create_child(self, uid, address, port, peer=base.PEER, reuse=False):
        base.require(uid in (309, 501), "Invalid disposable UID")
        base.require((address == peer == "127.0.0.1" and 0 <= port <= 65535)
                     or (peer == base.PEER and ((address, port) in zip(base.IPS, base.PORTS)
                                              or (address == "0.0.0.0" and port in base.PORTS))),
                     "Out-of-scope child target")
        source = base.safe_read(self.root / "edge_child.py").decode()
        child = subprocess.Popen([base.PYTHON, "-I", "-S", "-B", "-u", "-c", source,
            address, str(port), peer, str(self.deadline), "1" if reuse else "0"],
            user=uid, group=309 if uid == 309 else 20, extra_groups=[], start_new_session=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0,
            stderr=self.log("edge-child-%s.stderr" % len(self.handles)), env=base.ENV)
        self.children.append(child)
        row = self.child_event(child, {"ready", "bind_failed"})
        base.require(row.get("uid") == uid and row.get("pid") == child.pid, "Child identity mismatch")
        if row["event"] == "ready":
            base.require(row == {"event": "ready", "pid": child.pid, "uid": uid,
                                 "gid": 309 if uid == 309 else 20, "address": address, "port": row["port"]}
                         and type(row["port"]) is int and 1 <= row["port"] <= 65535
                         and (port == 0 or port == row["port"]), "Child endpoint mismatch")
        else:
            base.require(type(row.get("errno")) is int, "Malformed bind result")
        return child, row

    def spawn_child(self, uid, address, port, peer):
        _, row = self.create_child(uid, address, port, peer)
        base.require(row["event"] == "ready", "Required child bind failed")
        return row["port"]

    def stop_children(self):
        errors = []
        for child in self.children:
            try:
                base.stop_child(child)
                with (self.root / ("edge-child-%s.jsonl" % child.pid)).open("ab") as stream:
                    stream.write(child.stdout.read(128 * 1024))
            except Exception as error:
                errors.append(type(error).__name__)
        base.require(not errors, "Disposable edge children did not all stop")
        self.children = []

    def evidence(self, phase):
        rows = super().evidence(phase)
        value = json.loads(base.safe_read(self.root / (phase + "-pf.json")))
        base.write_json(self.public / (phase + "-counters.json"), {
            "time_utc": value["time_utc"], "counters": inspector.counter_summary(value["counters"]),
            "listeners": listener_records(value["listeners"])}, public=True)
        return rows

    def wait_probes(self, phase, helper_result=None):
        base.require(phase in PHASES, "Unexpected edge phase")
        self.held_services()
        base.require(self.pf(["-s", "info"]).startswith("Status: Enabled"), "PF disappeared")
        rows = self.evidence(phase + "-before")
        self.publish(phase, ready=True, experiment="tcp_edges", phases=PHASES,
                     helper_ok=helper_result.get("ok") if helper_result else None,
                     retained_half_open=[half_open(rows, index) for index in range(2)])
        print("READY: " + phase + ". Waiting for one bounded laptop phase.", flush=True)
        until = min(base.clock() + (480 if phase == PHASES[0] else 90), self.deadline)
        while not self.stop and base.clock() < until:
            if select.select([0], [], [], 0.2)[0]:
                self.stop = True
                break
            path = self.inbox / (phase + ".json")
            if path.exists():
                value = json.loads(base.safe_read(path, 501, 1024))
                if value == {"nonce": self.nonce, "phase": phase, "action": "stop"}:
                    raise RuntimeError("Coordinator requested scoped stop after a failed control")
                base.require(base.valid_ack(value, self.nonce, phase), "Invalid edge acknowledgement")
                return self.evidence(phase + "-after")
        raise RuntimeError("Attended stop or edge phase deadline")

    def bind_observation(self, kind, results):
        records = listener_records(self.command(["/usr/sbin/lsof", "-nP", "-l", "-iTCP", "-sTCP:LISTEN", "-Fpun"]).stdout)
        base.write_json(self.public / (kind + "-binding.json"), {"results": results, "listeners": records}, public=True)
        return records

    def exercise(self):
        self.spawn(309)
        base.require(self.rpc("publish")["ok"], "Initial publication failed")
        rows = self.wait_probes("edge_healthy")
        base.require(all(any({"ip": ip, "port": port} in row["endpoints"]
                             and row["state"] == "ESTABLISHED:ESTABLISHED" for row in rows)
                         for ip, port in zip(base.IPS, base.PORTS)), "Established control state missing")
        for child in self.children[:]:
            child.stdin.write(b'{"op":"close_listener"}\n')
            child.stdin.flush()
            row = self.child_event(child, {"listener_closed"})
            base.require(row["clients"] == 1, "Established socket not retained")
        results = []
        for ip, port in zip(base.IPS, base.PORTS):
            _, row = self.create_child(501, ip, port)
            base.require(row["event"] == "ready" or row.get("errno") == 48, "Unexpected cross-UID bind error")
            results.append({"ip": ip, "port": port, **row})
        self.bind_observation("established", results)
        base.require(not self.rpc("listener_check")["ok"], "Missing/wrong UID listener accepted")
        failed = self.rpc("fail_load_first_kill")
        base.require(not failed["ok"] and failed["alias_authorized"] == [False, False], "Failure lost cleanup debt")
        self.wait_probes("established_replacement", failed)
        self.stop_children()
        base.require(self.rpc("quarantine")["ok"], "Recovery failed before ambiguity test")
        results = []
        for ip, port in zip(base.IPS, base.PORTS):
            _, exact = self.create_child(309, ip, port, reuse=True)
            base.require(exact["event"] == "ready", "Ambiguity exact listener failed")
            _, wildcard = self.create_child(309, "0.0.0.0", port, reuse=True)
            base.require(wildcard["event"] == "ready" or wildcard.get("errno") == 48,
                         "Unexpected wildcard bind error")
            results.append({"ip": ip, "port": port, "exact": exact, "wildcard": wildcard})
        records = self.bind_observation("ambiguity", results)
        coexist = all(row["wildcard"]["event"] == "ready" for row in results)
        if coexist:
            base.require(len(records) == 4 and len({row["pid"] for row in records}) == 4,
                         "Expected simultaneous exact and wildcard listeners")
            base.require(not self.rpc("listener_check")["ok"], "Ambiguous listener accepted by guard")
        base.write_json(self.public / "ambiguity-result.json", {"coexistence_observed": coexist,
                        "guard_rejection_verified": coexist, "published": False}, public=True)
        self.stop_children()
        self.spawn(309)
        base.require(self.rpc("publish")["ok"], "Half-open control publication failed")
        rows = self.wait_probes("half_open_start")
        base.require(all(half_open(rows, index) for index in range(2)), "Required half-open states not observed")
        self.stop_children()
        self.spawn(501)
        base.require(not self.rpc("listener_check")["ok"], "Wrong UID listener accepted")
        failed = self.rpc("fail_load_first_kill")
        base.require(not failed["ok"] and failed["alias_authorized"] == [False, False], "Failure lost cleanup debt")
        self.wait_probes("half_open_wrong_uid", failed)
        recovered = self.rpc("quarantine")
        base.require(recovered["ok"] and recovered["alias_authorized"] == [True, True], "Final recovery failed")
        rows = self.wait_probes("half_open_quarantine", recovered)
        base.require(not rows, "Scoped PF states survived final quarantine")

    def run(self):
        def interrupted(*unused):
            self.stop = True
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, interrupted)
        completed = False
        try:
            self.preflight()
            self.public = Path(tempfile.mkdtemp(prefix="squirrelops-mini-a5-edges.", dir="/private/var/tmp"))
            self.public.chmod(0o755)
            self.inbox = self.public / "acknowledgements"
            self.inbox.mkdir(mode=0o700)
            os.chown(self.inbox, 501, 20)
            self.record()
            print("Private evidence: " + str(self.root), flush=True)
            print("Sanitized progress: " + str(self.public / "status.json"), flush=True)
            print("Installed services/data unchanged. Return stops; deadline 20 minutes.", flush=True)
            self.held_services()
            self.no_aliases()
            self.preserve_files(verify=True)
            base.require(self.inventory_policy() == self.policy, "PF drift before activation")
            self.enable_reference()
            base.require(self.rpc("quarantine")["ok"], "Initial quarantine failed")
            self.add_aliases()
            self.packet_capture()
            self.exercise()
            completed = True
        except Exception as error:
            base.write_json(self.root / "failure.json", {"error": str(error), "type": type(error).__name__})
            print("STOPPED: " + str(error) + ". Private evidence: " + str(self.root), flush=True)
        cleaned = self.cleanup()
        if self.public is not None:
            summaries = [{"file": p.name, **inspector.child_summary(base.safe_read(p).decode())}
                         for p in sorted(self.root.glob("edge-child-*.jsonl"))]
            base.write_json(self.public / "edge-child-summary.json", {"children": summaries}, public=True)
        return 0 if completed and cleaned else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args(argv)
    if args.run is None:
        print(json.dumps({"mode": "plan_only", "phases": PHASES, "vips": base.IPS, "installed_changes": False}))
        return 0
    return EdgeSession(args.run).run()


if __name__ == "__main__":
    raise SystemExit(main())
