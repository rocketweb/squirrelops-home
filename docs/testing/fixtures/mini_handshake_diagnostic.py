"""Read-only wire diagnostics for the approved VIP, with no authentication."""
import json
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

directory = Path(sys.argv[1])
ip = "192.168.1.240"
capture = subprocess.Popen([
    "/usr/bin/tcpdump", "-i", "wlp0s20f3", "-n", "-U", "-s", "96", "-w", str(directory / "handshake.pcap"),
    "host 192.168.1.240 and (tcp port 22 or tcp port 445)",
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
results = []
try:
    time.sleep(0.3)
    if capture.poll() is not None:
        raise RuntimeError("Capture did not start")
    for port in (22, 445):
        item = {"port": port, "connected": False}
        try:
            with socket.create_connection((ip, port), timeout=4) as stream:
                item.update(connected=True, source=stream.getsockname())
                stream.settimeout(5)
                if port == 22:
                    stream.sendall(b"SSH-2.0-SquirrelOps_Acceptance\r\n")
                else:
                    header = bytes.fromhex(
                        "fe534d4240000000000000000000010000000000000000000000000000000000"
                        "0000000000000000000000000000000000000000000000000000000000000000")
                    request = bytes.fromhex("24000100010000000000000000112233445566778899aabbccddeeff00000000000000000202")
                    packet = header + request
                    stream.sendall(len(packet).to_bytes(4, "big") + packet)
                data = stream.recv(512)
                item["response_bytes"] = len(data)
                item["response_prefix"] = data[:64].hex()
        except OSError as exc:
            item["error"] = type(exc).__name__
        results.append(item)
        print(json.dumps(item), flush=True)
finally:
    capture.send_signal(signal.SIGINT)
    capture.wait(timeout=5)
    (directory / "handshake-results.json").write_text(json.dumps(results, indent=2) + "\n")
    summary = subprocess.run(["/usr/bin/tcpdump", "-n", "-e", "-tttt", "-r", str(directory / "handshake.pcap")],
                             capture_output=True, text=True, timeout=10)
    (directory / "handshake-headers.txt").write_text(summary.stdout)
    print(summary.stdout, end="")
