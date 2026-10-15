#!/usr/bin/env python3
"""Unscored real Unix listener, including a same-descriptor fork/listen handoff."""

import errno
import json
import os
from pathlib import Path
import select
import signal
import socket
import sys


root = Path(sys.argv[1])
mode, config_sha, layer_sha = sys.argv[2:5]
events = root / "events.jsonl"
stop = root / "stop"
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
child_pid = None
filler_clients = []


def event(kind, **fields):
    encoded = (json.dumps({"kind": kind, "pid": os.getpid(), **fields},
                          separators=(",", ":")) + "\n").encode()
    descriptor = os.open(events, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        assert os.write(descriptor, encoded) == len(encoded)
    finally:
        os.close(descriptor)


def stopped():
    return stop.exists()


def wait_for_stop():
    while not stopped():
        select.select([], [], [], 0.02)


def interrupted(_signal, _frame):
    raise SystemExit(0)


def read_request(connection, number):
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        part = connection.recv(1024)
        if not part:
            event("eof-before-request", number=number, bytes=len(data))
            return None
        data.extend(part)
        assert len(data) <= 8192
    request = bytes(data).split(b"\r\n", 1)[0].decode("ascii")
    event("request", number=number, request=request.split(" HTTP/1.1", 1)[0], bytes=len(data))
    return request


def json_response(value):
    body = json.dumps(value, separators=(",", ":")).encode()
    duplicate = f"content-length: {len(body)}\r\n".encode() if mode == "duplicate-header" else b""
    trailing = b"extra" if mode == "trailing-body" else b""
    return (b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode() + duplicate + b"\r\n" + body + trailing)


head = (
    b"HTTP/1.1 200 OK\r\nApi-Version: 1.55\r\nBuilder-Version: 2\r\n"
    b"Cache-Control: no-cache, no-store, must-revalidate\r\nConnection: close\r\n"
    b"Content-Length: 0\r\nContent-Type: text/plain; charset=utf-8\r\n"
    b"Date: Tue, 13 Oct 2026 00:00:00 GMT\r\nDocker-Experimental: false\r\n"
    b"Ostype: linux\r\nPragma: no-cache\r\nServer: Docker/29.7.2 (linux)\r\n"
    b"Swarm: inactive\r\n\r\n"
)


def response(number):
    if number == 0:
        return head
    if number == 1:
        return json_response({"Version": "29.7.2", "ApiVersion": "1.55", "Os": "linux",
                              "Arch": "amd64", "GitCommit": "6a43e3d"})
    if number == 2:
        return json_response({"ServerVersion": "29.7.2", "OSType": "linux", "Driver": "overlay2",
                              "CgroupVersion": "2", "SecurityOptions": ["name=rootless"]})
    if number == 3:
        return json_response({"Id": f"sha256:{config_sha}", "Os": "linux", "Architecture": "amd64",
                              "RootFS": {"Type": "layers", "Layers": [f"sha256:{layer_sha}"]}})
    body = (root / "export.tar").read_bytes()
    encoded = bytearray(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/x-tar\r\n"
                        b"Transfer-Encoding: chunked\r\n\r\n")
    for offset in range(0, len(body), 733):
        chunk = body[offset:offset + 733]
        encoded.extend(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
    encoded.extend(b"0\r\n\r\n")
    return bytes(encoded)


def serve(first_number):
    global child_pid
    for number in range(first_number, 5):
        while not stopped():
            if select.select([listener], [], [], 0.02)[0]:
                break
        if stopped():
            return
        connection, _address = listener.accept()
        with connection:
            event("accepted", number=number)
            request = read_request(connection, number)
            if request is None:
                wait_for_stop()
                return
            if mode == "stall-head" and number == 0:
                while not stopped() and connection.recv(1):
                    pass
                event("stalled-client-closed", number=number)
                wait_for_stop()
                return
            if mode == "handoff" and number == 0:
                ready_read, ready_write = os.pipe()
                child_pid = os.fork()
                if child_pid == 0:
                    child_pid = None
                    os.close(ready_read)
                    connection.close()
                    # This is the same open listener inherited from A, with no pathname change.
                    listener.listen(8)
                    identity = (root / "r" / "s").stat()
                    event("handoff", parent=os.getppid(), dev=identity.st_dev, ino=identity.st_ino)
                    os.write(ready_write, b"R")
                    os.close(ready_write)
                    serve(1)
                    return
                os.close(ready_write)
                assert os.read(ready_read, 1) == b"R"
                os.close(ready_read)
                connection.sendall(response(number))
                event("head-sent-after-handoff", child=child_pid)
                connection.close()
                wait_for_stop()
                return
            connection.sendall(response(number))
    event("five-completed")
    wait_for_stop()


signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
try:
    listener.bind(str(root / "r" / "s"))
    listener.listen(1 if mode == "backlog-stall" else 8)
    if mode == "backlog-stall":
        # Linux AF_UNIX allows backlog+1 pending connections. Keep both open without accepting.
        for _number in range(2):
            filler = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            filler_clients.append(filler)
            filler.settimeout(1)
            filler.connect(str(root / "r" / "s"))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.setblocking(False)
            try:
                probe.connect(str(root / "r" / "s"))
            except BlockingIOError as failure:
                assert failure.errno == errno.EAGAIN
                event("backlog-filled", queued=len(filler_clients), connectErrno=failure.errno)
            else:
                raise AssertionError("actual Unix backlog was not full")
    identity = (root / "r" / "s").stat()
    event("ready", dev=identity.st_dev, ino=identity.st_ino)
    if mode == "backlog-stall":
        wait_for_stop()
    else:
        serve(0)
finally:
    for filler in filler_clients:
        filler.close()
    listener.close()
    if child_pid is not None:
        try:
            os.kill(child_pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        os.waitpid(child_pid, 0)
    event("exit")
