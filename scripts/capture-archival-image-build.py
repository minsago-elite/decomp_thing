#!/usr/bin/env python3
"""Bounded archival image build capture and silent control receipt parser."""
import codecs
import errno
import fcntl
import json
import os
import re
import resource
import selectors
import signal
import stat
import sys
import time
from collections import deque
from pathlib import Path

BUILD = Path(__file__).resolve().parent.parent / "build"
ROOT_RE = re.compile(r"decomp-archival-ci\.[A-Za-z0-9_-]{6,32}\Z")
RAW_LIMIT = 33554432
NORM_LIMIT = 134217728
KEYS = ("schema role cleanupAuthority deadlineSeconds processState exitOrigin rawReturnCode signalsSent terminationReason pipeEOF captureState excerptPolicy logCommitted rawBytes normalizedBytes payloadBytes droppedNormalizedBytes inputLines droppedLines truncatedLines excerptBytes shellExit").split()
LOG_KEYS = tuple(k for k in KEYS if k not in ("logCommitted", "shellExit"))
ENUMS = {
 "processState": {"not-started", "reaped", "unjoined"},
 "exitOrigin": {"none", "pre-signal", "post-term", "post-kill"},
 "signalsSent": {"none", "term", "term-kill"},
 "terminationReason": {"none", "deadline", "capacity", "capture-error", "spawn-error"},
 "captureState": {"complete", "truncated", "incomplete", "error"},
 "excerptPolicy": {"none", "failure-full", "success-receipt-only"},
}
LIMITS = {"deadlineSeconds":2700,"rawBytes":33554433,"normalizedBytes":NORM_LIMIT,"payloadBytes":57344,"droppedNormalizedBytes":NORM_LIMIT,"inputLines":NORM_LIMIT,"droppedLines":NORM_LIMIT,"truncatedLines":NORM_LIMIT,"excerptBytes":59000,"shellExit":255}
COUNTERS = "rawBytes normalizedBytes payloadBytes droppedNormalizedBytes inputLines droppedLines truncatedLines excerptBytes".split()
TERM_GRACE, KILL_GRACE, COMMIT_SECONDS = 10.0, 5.0, 5.0

class Refused(Exception): pass
class CaptureFault(Exception):
    def __init__(self, reason): self.reason = reason

def version(st):
    return tuple(getattr(st, n) for n in ("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns"))

def canonical(obj):
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")

def _pairs(items):
    out = {}
    for k,v in items:
        if k in out: raise ValueError("duplicate key")
        out[k] = v
    return out

def _constant(_): raise ValueError("non-finite number")

def primary(r):
    if r["processState"] == "reaped" and r["exitOrigin"] == "pre-signal" and r["rawReturnCode"] not in (None,0):
        n=r["rawReturnCode"]; return n if n > 0 else 128-n
    if r["terminationReason"] == "spawn-error": return 126
    if r["processState"] == "unjoined": return 125
    if r["terminationReason"] == "deadline": return 124
    if r["terminationReason"] in ("capacity","capture-error"): return 126
    return 0 if (r["processState"] == "reaped" and r["exitOrigin"] == "pre-signal" and r["rawReturnCode"] == 0 and r["pipeEOF"] and r["signalsSent"] == "none" and r["captureState"] in ("complete","truncated") and r["logCommitted"]) else 126

def validate_receipt(r, deadline):
    if type(r) is not dict or set(r) != set(KEYS): return False
    if type(r["schema"]) is not int or r["schema"] != 1 or r["role"] != "control" or r["cleanupAuthority"] != "none": return False
    for k, choices in ENUMS.items():
        if type(r[k]) is not str or r[k] not in choices: return False
    for k in ("pipeEOF","logCommitted"):
        if type(r[k]) is not bool: return False
    for k, hi in LIMITS.items():
        if type(r[k]) is not int or not 0 <= r[k] <= hi: return False
    if r["deadlineSeconds"] != deadline or (r["rawReturnCode"] is not None and (type(r["rawReturnCode"]) is not int or not -64 <= r["rawReturnCode"] <= 255)): return False
    if r["processState"] == "not-started":
        if not (r["rawReturnCode"] is None and r["exitOrigin"] == "none" and r["signalsSent"] == "none" and not r["pipeEOF"] and all(r[k] == 0 for k in COUNTERS) and r["terminationReason"] in ("spawn-error","capture-error")): return False
    elif r["processState"] == "reaped":
        if r["rawReturnCode"] is None or r["exitOrigin"] == "none": return False
        if r["exitOrigin"] == "post-term" and r["signalsSent"] not in ("term","term-kill"): return False
        if r["exitOrigin"] == "post-kill" and r["signalsSent"] != "term-kill": return False
    elif not (r["rawReturnCode"] is None and r["exitOrigin"] == "none" and r["signalsSent"] == "term-kill" and r["terminationReason"] not in ("none","spawn-error")): return False
    if r["terminationReason"] == "none" and not (r["processState"] == "reaped" and r["exitOrigin"] == "pre-signal" and r["signalsSent"] == "none" and r["pipeEOF"]): return False
    if (r["terminationReason"] == "capacity") != (r["rawBytes"] == RAW_LIMIT+1): return False
    if r["captureState"] == "complete" and not (r["pipeEOF"] and r["droppedNormalizedBytes"] == 0 and r["truncatedLines"] == 0): return False
    if r["captureState"] == "truncated" and not (r["pipeEOF"] and (r["droppedNormalizedBytes"] > 0 or r["truncatedLines"] > 0)): return False
    if r["captureState"] == "incomplete" and r["pipeEOF"]: return False
    if r["droppedNormalizedBytes"] != r["normalizedBytes"]-r["payloadBytes"] or r["normalizedBytes"] > 4*min(r["rawBytes"],RAW_LIMIT): return False
    if r["rawBytes"] == 0 and (r["normalizedBytes"] or r["inputLines"]): return False
    if r["droppedLines"] > r["inputLines"] or r["truncatedLines"] > r["inputLines"] or r["inputLines"] > r["normalizedBytes"]: return False
    none_policy = r["excerptPolicy"] == "none"
    if none_policy and not (r["processState"] == "not-started" and r["terminationReason"] == "capture-error" and not r["logCommitted"]): return False
    if r["excerptPolicy"] == "success-receipt-only" and not (r["exitOrigin"] == "pre-signal" and r["rawReturnCode"] == 0 and r["payloadBytes"] == 0 and r["excerptBytes"] == 0): return False
    if r["excerptPolicy"] == "success-receipt-only" and (r["droppedLines"] != r["inputLines"] or r["truncatedLines"] != 0): return False
    if r["terminationReason"] == "spawn-error" and r["processState"] != "not-started": return False
    if r["deadlineSeconds"] < 1: return False
    if r["droppedLines"] + r["truncatedLines"] > r["inputLines"]: return False
    if r["payloadBytes"] > r["excerptBytes"] or (not r["logCommitted"] and r["captureState"] != "error" and not none_policy): return False
    return type(r["shellExit"]) is int and r["shellExit"] == primary(r)

def parse_receipt(stream_fd=0, deadline_seconds=2700, *, api=None):
    read=(api or os).read; data=bytearray()
    try:
        while len(data) <= 2048:
            block=read(stream_fd,2049-len(data))
            if not block: break
            data.extend(block)
        if len(data)>2048 or not data.endswith(b"\n") or data.count(b"\n") != 1 or b"\r" in data or b"\0" in data: return 11
        raw=bytes(data); obj=json.loads(raw.decode("ascii"), object_pairs_hook=_pairs, parse_constant=_constant)
        if canonical(obj)!=raw or not validate_receipt(obj,deadline_seconds): return 11
        return 0 if obj["shellExit"] == 0 else 10
    except Exception: return 11


class Excerpt:
    """Bounded retained records; counters cover decoded observed prefix only."""
    PREFIX = 960  # reserves LF and nine-digit normalized-length suffix

    def __init__(self):
        self.decoder = codecs.getincrementaldecoder("utf-8")("backslashreplace")
        self.raw = self.normalized = self.input = self.length = 0
        self.pending = bytearray()
        self.head, self.tail = [], deque()
        self.headclosed = self.finished = False

    @staticmethod
    def cost(line):
        return len(json.dumps(line.decode("utf-8"), ensure_ascii=True)) + 1

    def _line(self, newline):
        self.input += 1
        original = bytes(self.pending).decode("utf-8", "ignore").encode("utf-8")
        cut = self.length > len(original)
        suffix = (f" [line-truncated {self.length} bytes]".encode() if cut else b"")
        rendered = original + suffix + b"\n"
        payload = len(original) + (1 if newline else 0)
        record = (rendered, payload, cut, self.cost(rendered))
        def fits(rows, extra, caps):
            return (len(rows) < caps[0] and sum(len(x[0]) for x in rows) + len(extra[0]) <= caps[1]
                    and sum(x[3] for x in rows) + extra[3] <= caps[2])
        if not self.headclosed and fits(self.head, record, (40, 8192, 26624)):
            self.head.append(record)
        else:
            self.headclosed = True
            while self.tail and not fits(self.tail, record, (180, 49152, 163840)):
                self.tail.popleft()
            self.tail.append(record)
        self.pending.clear()
        self.length = 0

    def feed(self, raw, eof=False):
        if self.finished:
            raise Refused("excerpt-already-final")
        allowed = max(0, RAW_LIMIT - self.raw)
        if len(raw) > min(65536, allowed if allowed else 1):
            raise Refused("read-bound")
        self.raw += len(raw)
        encoded = self.decoder.decode(raw[:allowed], final=eof).encode("utf-8")
        self.normalized += len(encoded)
        cursor = 0
        while cursor < len(encoded):
            end = encoded.find(b"\n", cursor)
            stop = len(encoded) if end < 0 else end
            take = min(self.PREFIX - len(self.pending), stop - cursor)
            self.pending.extend(encoded[cursor:cursor + take])
            self.length += stop - cursor
            if end < 0:
                break
            self._line(True)
            cursor = end + 1
        if eof:
            self.finish()
        return self.raw > RAW_LIMIT

    def finish(self):
        # Fault finalization counts the observed prefix but never flushes carry.
        if not self.finished:
            if self.length:
                self._line(False)
            self.finished = True

    def render(self, success=False):
        self.finish()
        rows = self.head + list(self.tail)
        payload = 0 if success else sum(x[1] for x in rows)
        dropped = self.normalized - payload
        lines = self.input if success else self.input - len(rows)
        truncated = 0 if success else sum(x[2] for x in rows)
        marker = (f"[archival-capture: dropped {dropped} normalized bytes / {lines} lines between head and tail]\n".encode()
                  if dropped and not success else b"")
        body = b"" if success else b"".join(x[0] for x in self.head) + marker + b"".join(x[0] for x in self.tail)
        return body, dict(rawBytes=self.raw, normalizedBytes=self.normalized, payloadBytes=payload,
                          droppedNormalizedBytes=dropped, inputLines=self.input, droppedLines=lines,
                          truncatedLines=truncated, excerptBytes=len(body))


def _receipt_base(deadline):
    r = dict(schema=1, role="control", cleanupAuthority="none", deadlineSeconds=deadline,
             processState="not-started", exitOrigin="none", rawReturnCode=None, signalsSent="none",
             terminationReason="capture-error", pipeEOF=False, captureState="error",
             excerptPolicy="none", logCommitted=False, shellExit=126)
    r.update({k: 0 for k in COUNTERS})
    return r


class System:
    """All external boundaries. Tests pass a complete replacement, never a fallback dict."""
    def __init__(self):
        self.os, self.resource, self.signal, self.fcntl = os, resource, signal, fcntl
        self.clock = time.monotonic
        self.selector = selectors.DefaultSelector
        self.pause = time.sleep
        self.environ = os.environ
        self.build = BUILD

    def admit(self):
        for name in ("pipe2", "posix_spawnp", "pidfd_open", "waitid", "waitpid", "waitstatus_to_exitcode",
                     "open", "stat", "fstat", "scandir", "close", "read", "write", "set_blocking",
                     "set_inheritable", "killpg", "geteuid", "umask"):
            if not callable(getattr(self.os, name, None)):
                raise Refused("missing-api")
        for name in ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT", "CLD_EXITED", "CLD_KILLED", "CLD_DUMPED",
                     "O_RDONLY", "O_WRONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_CREAT", "O_EXCL",
                     "O_NONBLOCK", "O_ACCMODE", "O_RDWR", "POSIX_SPAWN_OPEN", "POSIX_SPAWN_DUP2", "POSIX_SPAWN_CLOSE"):
            if not hasattr(self.os, name):
                raise Refused("missing-flag")
        if not callable(self.fcntl.fcntl) or not hasattr(self.fcntl, "F_DUPFD_CLOEXEC"):
            raise Refused("missing-fd-normalization")
        for name in ("getrlimit", "setrlimit"):
            if not callable(getattr(self.resource, name, None)):
                raise Refused("missing-resource")
        for name in ("RLIMIT_FSIZE", "RLIMIT_CORE", "RLIM_INFINITY"):
            if not hasattr(self.resource, name):
                raise Refused("missing-resource-flag")
        for name in ("SIGCHLD", "SIG_DFL", "SIGPIPE", "SIGXFSZ", "SIGTERM", "SIGKILL"):
            if not hasattr(self.signal, name):
                raise Refused("missing-signal")
        if not callable(self.selector) or not callable(self.clock) or not callable(self.pause):
            raise Refused("missing-event-api")
        if self.signal.getsignal(self.signal.SIGCHLD) != self.signal.SIG_DFL:
            raise Refused("sigchld-disposition")
        self.os.fstat(1)
        if not hasattr(self.fcntl, "F_GETFL"):
            raise Refused("missing-control-flags")
        flags = self.fcntl.fcntl(1, self.fcntl.F_GETFL)
        if flags & self.os.O_ACCMODE not in (self.os.O_WRONLY, self.os.O_RDWR):
            raise Refused("control-not-writable")


class Descriptors:
    def __init__(self, system):
        self.s, self.owned = system, set()

    def add(self, fd):
        self.owned.add(fd)
        if fd <= 2:
            new = self.s.fcntl.fcntl(fd, self.s.fcntl.F_DUPFD_CLOEXEC, 3)
            self.owned.add(new)
            if new <= 2 or new == fd:
                raise Refused("fd-alias")
            self.close(fd)
            fd = new
        self.s.os.set_inheritable(fd, False)
        return fd

    def close(self, fd):
        # A close error never authorizes retrying a possibly reused descriptor.
        self.owned.remove(fd)
        self.s.os.close(fd)

    def finish(self):
        failed = False
        for fd in tuple(self.owned):
            try:
                self.close(fd)
            except Exception:
                failed = True
        return failed


class Directories:
    def __init__(self, s, owned, root, device, inode):
        self.s, self.owned, self.fds, self.snaps = s, owned, [], []
        self.paths = [s.build, Path(root).name, "output", "archival-image", "reports"]
        path = Path(root)
        if (path.parent != s.build or not ROOT_RE.fullmatch(path.name)
                or any(type(n) is not int or not 0 <= n < 1 << 64 for n in (device, inode))):
            raise Refused("root-selection")
        flags = s.os.O_RDONLY | s.os.O_DIRECTORY | s.os.O_NOFOLLOW | s.os.O_CLOEXEC
        for i, name in enumerate(self.paths):
            kw = {} if i == 0 else {"dir_fd": self.fds[-1]}
            selected = s.os.stat(name, follow_symlinks=False, **kw)
            fd = owned.add(s.os.open(name, flags, **kw))
            held = s.os.fstat(fd)
            if not stat.S_ISDIR(held.st_mode) or version(held) != version(selected):
                raise Refused("directory-admission")
            if i == 1 and (held.st_dev, held.st_ino) != (device, inode):
                raise Refused("root-identity")
            if i and held.st_dev != device:
                raise Refused("foreign-device")
            self.fds.append(fd)
            self.snaps.append(version(held))
        self.device = device
        self.check(False)

    def check(self, post):
        for i, (fd, name, snap) in enumerate(zip(self.fds, self.paths, self.snaps)):
            kw = {} if i == 0 else {"dir_fd": self.fds[i - 1]}
            values = (version(self.s.os.fstat(fd)), version(self.s.os.stat(name, follow_symlinks=False, **kw)))
            for value in values:
                # Reports insertion may change only size, mtime and ctime.
                if (value[:6] != snap[:6] if post and i == 4 else value != snap):
                    raise Refused("directory-changed")
        with self.s.os.scandir(self.fds[-1]) as scan:
            first = next(scan, None)
            if post:
                if first is None or first.name != "build.log" or next(scan, None) is not None:
                    raise Refused("report-set")
            elif first is not None:
                raise Refused("reports-not-empty")

    def commit(self, data, mask, deadline):
        s = self.s
        def timely():
            if s.clock() >= deadline:
                raise Refused("commit-deadline")
        timely()
        self.check(False)
        timely()
        flags = s.os.O_WRONLY | s.os.O_CREAT | s.os.O_EXCL | s.os.O_NOFOLLOW | s.os.O_NONBLOCK | s.os.O_CLOEXEC
        fd = self.owned.add(s.os.open("build.log", flags, 0o644, dir_fd=self.fds[-1]))
        timely()
        initial = s.os.fstat(fd)
        identity = version(initial)[:6]
        if (not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1 or initial.st_size != 0
                or initial.st_dev != self.device or initial.st_uid != s.os.geteuid()
                or stat.S_IMODE(initial.st_mode) != (0o644 & ~mask)):
            raise Refused("leaf-admission")
        def leaf(size, held=True):
            named = s.os.stat("build.log", dir_fd=self.fds[-1], follow_symlinks=False)
            if version(named)[:6] != identity or named.st_size != size:
                raise Refused("leaf-changed")
            if held and version(s.os.fstat(fd)) != version(named):
                raise Refused("leaf-replaced")
            return version(named)
        leaf(0)
        write_all(s, fd, data, deadline)
        final_version = leaf(len(data))
        timely()
        self.owned.close(fd)
        timely()
        if leaf(len(data), False) != final_version:
            raise Refused("leaf-changed-after-close")
        self.check(True)
        timely()


def write_all(s, fd, data, deadline):
    cursor = 0
    while cursor < len(data):
        if s.clock() >= deadline:
            raise Refused("write-deadline")
        try:
            count = s.os.write(fd, data[cursor:])
        except InterruptedError:
            continue
        if s.clock() >= deadline:
            raise Refused("write-deadline")
        if type(count) is not int or not 0 < count <= len(data) - cursor:
            raise Refused("write-progress")
        cursor += count


class OwnershipLost(Exception):
    pass


class Child:
    """One wait owner. Hold the zombie across both requests and fixed graces."""
    def __init__(self, s, owned, selector, pid, reader, deadline, receipt, excerpt):
        self.s, self.owned, self.selector = s, owned, selector
        self.pid, self.reader, self.deadline = pid, reader, deadline
        self.r, self.ex = receipt, excerpt
        self.pidfd = None
        self.exited = self.terminal = False
        self.registered = set()
        self.fault_at = None
        self.selector_broken = False

    def fault(self, reason="capture-error"):
        if self.r["terminationReason"] == "none":
            self.r["terminationReason"] = reason
        if self.fault_at is None:
            self.fault_at = self.s.clock()

    def remove(self, fd):
        if fd in self.registered:
            self.registered.remove(fd)
            try:
                self.selector.unregister(fd)
            except Exception:
                self.selector_broken = True
                self.fault()

    def observe(self):
        if self.terminal:
            raise OwnershipLost()
        try:
            info = self.s.os.waitid(self.s.os.P_PID, self.pid,
                                  self.s.os.WEXITED | self.s.os.WNOHANG | self.s.os.WNOWAIT)
        except Exception as exc:
            # No reliable ownership proof remains after a wait failure.
            self.terminal = True
            raise OwnershipLost() from exc
        if info is not None and info.si_pid != 0:
            if info.si_pid != self.pid or info.si_code not in (self.s.os.CLD_EXITED, self.s.os.CLD_KILLED, self.s.os.CLD_DUMPED):
                self.terminal = True
                raise OwnershipLost()
            rc = info.si_status if info.si_code == self.s.os.CLD_EXITED else -info.si_status
            if self.exited and self.r["rawReturnCode"] != rc:
                self.terminal = True
                raise OwnershipLost()
            if not self.exited:
                self.r.update(rawReturnCode=rc, exitOrigin={"none": "pre-signal", "term": "post-term", "term-kill": "post-kill"}[self.r["signalsSent"]])
                self.exited = True
                self.remove(self.pidfd)
        elif self.exited:
            self.terminal = True
            raise OwnershipLost()

    def request(self, name, sig):
        self.observe()  # WNOWAIT immediately before each numeric group request
        self.r["signalsSent"] = name
        try:
            self.s.os.killpg(self.pid, sig)
        except Exception:
            self.fault()

    def run(self, setup):
        try:
            setup(self)
            self.selector.register(self.reader, selectors.EVENT_READ, "pipe")
            self.registered.add(self.reader)
            if self.pidfd is not None:
                self.selector.register(self.pidfd, selectors.EVENT_READ, "pid")
                self.registered.add(self.pidfd)
        except Exception:
            self.fault()
        while True:
            now = self.s.clock()
            if self.fault_at is None and now >= self.deadline:
                self.fault("deadline")
            if self.fault_at is not None:
                if self.reader is not None:
                    self.remove(self.reader)
                    fd, self.reader = self.reader, None
                    try:
                        self.owned.close(fd)
                    except Exception:
                        self.fault()
                if self.r["signalsSent"] == "none":
                    self.request("term", self.s.signal.SIGTERM)
                if self.s.clock() >= self.fault_at + TERM_GRACE and self.r["signalsSent"] == "term":
                    self.request("term-kill", self.s.signal.SIGKILL)
                if self.s.clock() >= self.fault_at + TERM_GRACE + KILL_GRACE:
                    self.observe()
                    break
                boundary = self.fault_at + (TERM_GRACE if self.r["signalsSent"] == "term" else TERM_GRACE + KILL_GRACE)
            else:
                if self.exited and self.r["pipeEOF"]:
                    break
                boundary = self.deadline
            remaining = max(0, boundary - self.s.clock())
            try:
                if self.selector_broken or not self.registered:
                    self.s.pause(remaining)
                    events = []
                else:
                    events = self.selector.select(remaining)
                for key, _ in events:
                    if key.data == "pid" and not self.exited:
                        self.observe()
                        if not self.exited:
                            self.selector_broken = True
                            self.fault()
                    elif key.data == "pipe" and self.reader is not None and self.fault_at is None:
                        try:
                            chunk = self.s.os.read(self.reader, min(65536, RAW_LIMIT - self.ex.raw) if self.ex.raw < RAW_LIMIT else 1)
                        except (BlockingIOError, InterruptedError):
                            continue
                        if chunk == b"":
                            self.r["pipeEOF"] = True
                            self.ex.feed(b"", eof=True)
                            self.remove(self.reader)
                            fd, self.reader = self.reader, None
                            self.owned.close(fd)
                        elif self.ex.feed(chunk):
                            self.fault("capacity")
                        if self.s.clock() >= self.deadline and self.fault_at is None:
                            self.fault("deadline")
            except OwnershipLost:
                raise
            except Exception:
                self.selector_broken = True
                self.fault()
        if self.exited:
            self.terminal = True  # even a refused reap is terminal
            try:
                pid, status = self.s.os.waitpid(self.pid, self.s.os.WNOHANG)
                rc = self.s.os.waitstatus_to_exitcode(status)
            except Exception as exc:
                raise OwnershipLost() from exc
            if pid != self.pid or rc != self.r["rawReturnCode"]:
                raise OwnershipLost()
            self.r["processState"] = "reaped"
        else:
            self.terminal = True
            self.r.update(processState="unjoined", rawReturnCode=None, exitOrigin="none")


def refusal_status(r):
    rc = r["rawReturnCode"]
    return (rc if rc > 0 else 128 - rc) if r["exitOrigin"] == "pre-signal" and rc not in (None, 0) else 126


def capture(root, device, inode, deadline_seconds, argv, *, api=None):
    s = System() if api is None else api
    if type(deadline_seconds) is not int or not 1 <= deadline_seconds <= 2700 or not argv:
        return 126
    r, ex, owned = _receipt_base(deadline_seconds), Excerpt(), Descriptors(s)
    dirs = selector = child = None
    mask = 0
    close_fault = False
    try:
        try:
            s.admit()
            selector = s.selector()
            if not all(callable(getattr(selector, name, None)) for name in ("register", "unregister", "select", "close")):
                raise Refused("selector-api")
            if callable(getattr(selector, "fileno", None)) and selector.fileno() <= 2:
                raise Refused("selector-fd-alias")
            mask = s.os.umask(0)
            s.os.umask(mask)
            limits = s.resource.getrlimit(s.resource.RLIMIT_FSIZE)
            s.resource.getrlimit(s.resource.RLIMIT_CORE)
            dirs = Directories(s, owned, root, device, inode)
            r["excerptPolicy"] = "failure-full"
            reader, writer = s.os.pipe2(s.os.O_CLOEXEC)
            # Track both immediately, including failures normalizing either endpoint.
            owned.owned.update((reader, writer))
            reader, writer = owned.add(reader), owned.add(writer)
            s.os.set_blocking(reader, False)
            deadline = s.clock() + deadline_seconds
            actions = [(s.os.POSIX_SPAWN_OPEN, 0, "/dev/null", s.os.O_RDONLY, 0),
                       (s.os.POSIX_SPAWN_DUP2, writer, 1), (s.os.POSIX_SPAWN_DUP2, writer, 2),
                       (s.os.POSIX_SPAWN_CLOSE, reader), (s.os.POSIX_SPAWN_CLOSE, writer)]
            try:
                pid = s.os.posix_spawnp(argv[0], argv, s.environ, file_actions=actions,
                                      setsid=True, setsigdef={s.signal.SIGPIPE, s.signal.SIGXFSZ})
            except Exception:
                r["terminationReason"] = "spawn-error"
                raise
            r["terminationReason"] = "none"
            child = Child(s, owned, selector, pid, reader, deadline, r, ex)
            def setup(c):
                try:
                    owned.close(writer)
                    c.pidfd = owned.add(s.os.pidfd_open(pid, 0))
                finally:
                    cap = min([65536] + [n for n in limits if n != s.resource.RLIM_INFINITY])
                    s.resource.setrlimit(s.resource.RLIMIT_FSIZE, (cap, cap))
                    s.resource.setrlimit(s.resource.RLIMIT_CORE, (0, 0))
            child.run(setup)
        except OwnershipLost:
            return refusal_status(r)
        except Exception:
            if child is not None:
                return refusal_status(r)
        success = (r["processState"] == "reaped" and r["exitOrigin"] == "pre-signal"
                   and r["rawReturnCode"] == 0 and r["pipeEOF"] and r["terminationReason"] == "none")
        body, counters = ex.render(success)
        r.update(counters)
        if dirs is not None:
            r["excerptPolicy"] = "success-receipt-only" if success else "failure-full"
        r["captureState"] = ("error" if r["terminationReason"] in ("capture-error", "spawn-error")
                             else "incomplete" if not r["pipeEOF"] else "truncated"
                             if r["droppedNormalizedBytes"] or r["truncatedLines"] else "complete")
        end = s.clock() + COMMIT_SECONDS
        if dirs is not None:
            log = {k: r[k] for k in LOG_KEYS}
            log["role"] = "log"
            line = b"archival-image-build-receipt " + canonical(log)
            data = body + line
            try:
                lines = data.split(b"\n")
                if (len(line) > 1000 or len(data) > 60000 or len(lines) - 1 > 230
                        or any(len(x) + 1 > 1000 for x in lines[:-1])
                        or sum(Excerpt.cost(x) for x in lines) > 196608):
                    raise Refused("render-budget")
                if child is None:
                    cap = min([65536] + [n for n in limits if n != s.resource.RLIM_INFINITY])
                    s.resource.setrlimit(s.resource.RLIMIT_FSIZE, (cap, cap))
                    s.resource.setrlimit(s.resource.RLIMIT_CORE, (0, 0))
                dirs.commit(data, mask, end)
                r["logCommitted"] = True
            except Exception:
                r.update(captureState="error", logCommitted=False)
        if selector is not None:
            try:
                selector.close()
            except Exception:
                close_fault = True
            selector = None
        close_fault = owned.finish() or close_fault
        if close_fault:
            r.update(captureState="error", logCommitted=False)
        r["shellExit"] = primary(r)
        if not validate_receipt(r, deadline_seconds):
            return refusal_status(r)
        data = canonical(r)
        if len(data) > 2048:
            return refusal_status(r)
        try:
            write_all(s, 1, data, end)
            s.os.close(1)
            if s.clock() >= end:
                raise Refused("control-close-deadline")
        except Exception:
            return r["shellExit"] or 126
        return r["shellExit"]
    finally:
        owned.finish()
        if selector is not None:
            try:
                selector.close()
            except Exception:
                pass


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args[:1] == ["--parse-receipt"]:
            if len(args) != 3 or args[1] != "--deadline-seconds":
                return 11
            return parse_receipt(0, int(args[2]))
        if len(args) < 7 or args[3] != "--deadline-seconds" or args[5] != "--":
            return 126
        return capture(args[0], int(args[1]), int(args[2]), int(args[4]), args[6:])
    except Exception:
        return 11 if args[:1] == ["--parse-receipt"] else 126


if __name__ == "__main__":
    raise SystemExit(main())
