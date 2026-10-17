"""Studio coordinator for one ready, approved Mini run. Default: no action."""
import argparse
import json
from pathlib import Path
import re
import select
import shlex
import subprocess
import time

PHASES = ("edge_healthy", "established_replacement", "half_open_start",
          "half_open_wrong_uid", "half_open_quarantine")
CONTROL = "/private/tmp/squirrelops-post-reboot-staging.QwxlZTAG/"
LAPTOP = "/root/squirrelops-a5-edges.uN2BSX5p/run-laptop-a5-edges.sh"


def ssh(host):
    return ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8",
            "-o", "ControlMaster=auto", "-o", "ControlPersist=600", "-o",
            "ControlPath=" + CONTROL + ("mini.sock" if host == "mini" else "laptop.sock"),
            "matt@100.108.203.27" if host == "mini" else "root@192.168.1.7"]


class Coordinator:
    def __init__(self, status, output):
        if not re.fullmatch(r"/private/var/tmp/squirrelops-mini-a5-edges[.][A-Za-z0-9_]+/status[.]json", status):
            raise ValueError("Out-of-scope status path")
        self.status_path, self.output, self.nonce = status, output, None

    def remote(self, command):
        result = subprocess.run([*ssh("mini"), command], capture_output=True, text=True, timeout=12)
        if result.returncode:
            raise RuntimeError("Mini coordination command failed")
        return result.stdout

    def status(self):
        value = json.loads(self.remote("/bin/cat " + shlex.quote(self.status_path)))
        if (value.get("scope") != "mini-a5-disposable" or value.get("vips") != ["192.168.1.239", "192.168.1.240"]
                or value.get("peer") != "192.168.1.7" or value.get("public_ports") != [22, 445]
                or value.get("backend_ports") != [61322, 61445]
                or not re.fullmatch(r"[a-f0-9]{12}", value.get("nonce", ""))
                or value.get("inbox") != str(Path(self.status_path).parent / "acknowledgements")
                or not re.fullmatch(r"/Library/SquirrelOps/acceptance-backups/mini-a5-edges-20261002[.][A-Za-z0-9_]+",
                                    value.get("private_evidence", ""))):
            raise RuntimeError("Unexpected Mini run identity")
        if self.nonce is None:
            self.nonce = value["nonce"]
        if self.nonce != value["nonce"]:
            raise RuntimeError("Run nonce changed")
        return value

    def save(self, name, value):
        with (self.output / name).open("x") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)

    def await_phase(self, expected, seconds=45):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            value = self.status()
            if value["phase"] == expected and value.get("ready") is True:
                return value
            if value["phase"] in ("cleaned", "needs_review"):
                self.save("early-final-status.json", value)
                raise RuntimeError("Mini ended before " + expected)
            time.sleep(0.3)
        raise RuntimeError("Mini phase deadline")

    def acknowledge(self, phase, action="probes_done"):
        if phase not in PHASES or action not in ("probes_done", "stop"):
            raise ValueError("Invalid acknowledgement")
        code = '''import json,os,sys
from pathlib import Path
p=Path(sys.argv[1]); nonce,phase,action=sys.argv[2:]
s=json.loads(p.read_text())
if s["nonce"]!=nonce or s["phase"]!=phase or s.get("ready") is not True or s["inbox"]!=str(p.parent/"acknowledgements"):
 raise RuntimeError("Ack identity changed")
fd=os.open(str(p.parent/"acknowledgements"/(phase+".json")),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
os.write(fd,json.dumps({"nonce":nonce,"phase":phase,"action":action}).encode());os.fsync(fd);os.close(fd)
print("ack")
'''
        command = shlex.join(["/usr/bin/python3", "-I", "-S", "-B", "-c", code,
                              self.status_path, self.nonce, phase, action])
        if self.remote(command).strip() != "ack":
            raise RuntimeError("Unexpected acknowledgement receipt")

    def run(self):
        self.output.mkdir(parents=False, exist_ok=False)
        first = self.await_phase(PHASES[0])
        if first.get("phases") != list(PHASES) or first.get("experiment") != "tcp_edges":
            raise RuntimeError("Wrong test experiment")
        self.save("run-started.json", first)
        client = None
        try:
            with (self.output / "client-stderr.log").open("x") as stderr:
                client = subprocess.Popen([*ssh("laptop"), "/bin/bash " + LAPTOP + " --run"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, text=True, bufsize=1)
                for phase in PHASES:
                    state = self.await_phase(phase)
                    self.save(phase + "-status.json", state)
                    print("PROBING " + phase, flush=True)
                    client.stdin.write(json.dumps({"phase": phase}) + "\n")
                    client.stdin.flush()
                    if not select.select([client.stdout], [], [], 35)[0]:
                        raise RuntimeError("Client response deadline")
                    value = json.loads(client.stdout.readline(131072))
                    self.save(phase + "-client.json", value)
                    print(json.dumps(value), flush=True)
                    if (value.get("phase") != phase or "error_type" in value
                            or value.get("observations", {}).get("unexpected_synack") is True):
                        raise RuntimeError("Client failed control or unexpected SYN-ACK; no repeat")
                    self.acknowledge(phase)
                client.stdin.close()
                client.wait(timeout=15)
                if client.returncode:
                    raise RuntimeError("Client did not finish successfully")
        except Exception as error:
            self.save("coordinator-failure.json", {"error": str(error)})
            value = self.status()
            if value.get("ready") is True and value.get("phase") in PHASES:
                self.acknowledge(value["phase"], "stop")
            raise
        finally:
            if client is not None:
                if not client.stdin.closed:
                    client.stdin.close()
                # The independent watchdog remains responsible for its own
                # rules if the SSH client is lost. Never kill that watchdog.
                try:
                    client.wait(timeout=18)
                except subprocess.TimeoutExpired:
                    client.terminate()
                    client.wait(timeout=5)
                client.stdout.close()
        until = time.monotonic() + 45
        while time.monotonic() < until:
            value = self.status()
            if value["phase"] in ("cleaned", "needs_review"):
                self.save("final-status.json", value)
                print(json.dumps(value), flush=True)
                if value.get("cleanup_complete") is not True:
                    raise RuntimeError("Mini cleanup requires review")
                return
            time.sleep(0.3)
        raise RuntimeError("Final cleanup deadline; inspect without retry")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--status")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"mode": "plan_only", "phases": PHASES, "laptop_wrapper": LAPTOP}))
        return
    if not args.status or not args.output:
        parser.error("--run requires exact --status and a fresh --output directory")
    Coordinator(args.status, args.output).run()


if __name__ == "__main__":
    main()
