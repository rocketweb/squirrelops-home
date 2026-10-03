"""Disposable fixed-token listener; only used by the pinned Mini test runner."""
import json
import os
import select
import signal
import socket
import sys
import time


def emit(**values):
    print(json.dumps(values), flush=True)


def main():
    address, raw_port, peer, raw_deadline, raw_reuse = sys.argv[1:]
    deadline = float(raw_deadline)
    def clock():
        return time.clock_gettime(time.CLOCK_MONOTONIC)
    if not 0 < deadline - clock() <= 1200 or raw_reuse not in ("0", "1"):
        raise ValueError("Invalid child boundary")
    stopping = False
    def interrupted(*unused):
        nonlocal stopping
        stopping = True
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    listener, clients = socket.socket(), []
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if raw_reuse == "1":
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            listener.bind((address, int(raw_port)))
            listener.listen(8)
        except OSError as error:
            emit(event="bind_failed", uid=os.getuid(), pid=os.getpid(), errno=error.errno)
            return 0
        listener.setblocking(False)
        emit(event="ready", pid=os.getpid(), uid=os.getuid(), gid=os.getgid(),
             address=address, port=listener.getsockname()[1])
        count = 0
        while not stopping and clock() < deadline and count < 256:
            ready, _, _ = select.select([0, *([listener] if listener else []), *clients], [], [], 0.2)
            if 0 in ready:
                line = sys.stdin.readline(256)
                if not line:
                    break
                if json.loads(line) != {"op": "close_listener"} or listener is None:
                    raise RuntimeError("Invalid child control")
                listener.close()
                listener = None
                emit(event="listener_closed", uid=os.getuid(), clients=len(clients))
            if listener is not None and listener in ready:
                stream, remote = listener.accept()
                stream.settimeout(0.2)
                if remote[0] != peer or len(clients) >= 16:
                    stream.close()
                else:
                    stream.sendall(("A5 uid=%d\n" % os.getuid()).encode())
                    clients.append(stream)
                    emit(event="accepted", uid=os.getuid(), source=remote[0], source_port=remote[1])
                    count += 1
            for stream in clients[:]:
                if stream not in ready:
                    continue
                try:
                    if stream.recv(64) != b"A5-PING\n":
                        raise OSError("End of synthetic exchange")
                    stream.sendall(("A5-PONG uid=%d\n" % os.getuid()).encode())
                    emit(event="echo", uid=os.getuid())
                except OSError:
                    stream.close()
                    clients.remove(stream)
        return 0
    finally:
        if listener is not None:
            listener.close()
        for stream in clients:
            stream.close()
        emit(event="stopped")


if __name__ == "__main__":
    raise SystemExit(main())
