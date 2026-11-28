#!/usr/bin/env python3
"""Prepared ordinary-Actions controls. No Docker; all temporary files in repo/build."""
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent

def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

h = load("capture-archival-image-build")
collector = load("collect-archival-diagnostics")


def parse(data, deadline=2700):
    stream = io.BytesIO(data)
    reads = []
    def read(fd, n):
        reads.append(n)
        assert 0 < n <= 2049
        return stream.read(n)
    result = h.parse_receipt(0, deadline, api=types.SimpleNamespace(read=read))
    assert sum(min(n, 2049) for n in reads[:1]) <= 2049
    return result


def receipt(rc=0, output=b""):
    r = h._receipt_base(2700)
    r.update(processState="reaped", exitOrigin="pre-signal", rawReturnCode=rc,
             terminationReason="none", pipeEOF=True, captureState="complete",
             excerptPolicy="success-receipt-only" if rc == 0 else "failure-full", logCommitted=True)
    e = h.Excerpt()
    e.feed(output, eof=True)
    _, counts = e.render(rc == 0)
    r.update(counts)
    if r["droppedNormalizedBytes"] or r["truncatedLines"]:
        r["captureState"] = "truncated"
    r["shellExit"] = rc if rc >= 0 else 128 - rc
    return r


class Fake:
    """A complete lifecycle fake; unexpected real OS access is impossible."""
    def __init__(self, *, exit_at=1, eof_at=2, rc=0, data=b"", failures=None):
        self.now = 0.0
        self.exit_at, self.eof_at, self.rc, self.data = exit_at, eof_at, rc, data
        self.failures = failures or {}
        self.calls, self.reg = [], {}
        self.os = self
        self.signal = signal
        for name in ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT", "CLD_EXITED", "CLD_KILLED", "CLD_DUMPED"):
            setattr(self, name, getattr(os, name))
        self.reaped = False
        self.waits = self.reads = self.selects = 0
    def hit(self, name):
        self.calls.append((name, self.now))
        if name in self.failures:
            value = self.failures.pop(name)
            if isinstance(value, BaseException):
                raise value
            return value
    def clock(self): return self.now
    def pause(self, duration):
        assert duration > 0, "busy spin"
        self.now += duration
    def register(self, fd, flags, data): self.reg[fd] = data
    def unregister(self, fd): del self.reg[fd]
    def select(self, duration):
        self.selects += 1
        assert self.selects < 20, "ready fd loop"
        self.hit("select")
        events = [(self.exit_at, fd) if kind == "pid" else (self.now if self.data else self.eof_at, fd)
                  for fd, kind in self.reg.items()]
        nearest = min((t for t, _ in events), default=float("inf"))
        self.now = min(self.now + duration, max(self.now, nearest))
        return [(types.SimpleNamespace(data=self.reg[fd]), 1) for t, fd in events if t <= self.now]
    def waitid(self, *args):
        assert not self.reaped
        self.waits += 1
        override = self.hit("waitid")
        if override is not None: return override
        if self.now < self.exit_at: return None
        return types.SimpleNamespace(si_pid=42, si_code=self.CLD_EXITED if self.rc >= 0 else self.CLD_KILLED, si_status=abs(self.rc))
    def waitpid(self, *args):
        assert not self.reaped
        self.reaped = True
        override = self.hit("waitpid")
        return override if override is not None else (42, self.rc)
    def waitstatus_to_exitcode(self, status): return status
    def read(self, fd, count):
        self.reads += 1
        self.hit("read")
        if self.data:
            chunk, self.data = self.data[:count], self.data[count:]
            return chunk
        return b""
    def close(self, fd): self.hit("close")
    def killpg(self, pid, sig):
        assert not self.reaped
        self.hit("TERM" if sig == signal.SIGTERM else "KILL")
    def set_inheritable(self, fd, value): pass


class CapacityStream(Fake):
    """Reusable chunk source through the actual Child read/probe loop."""
    def __init__(self, *, probe, **kwargs):
        super().__init__(**kwargs)
        self.probe, self.remaining = probe, 33554432
        self.block = b"x" * 65536
        self.read_requests = []

    def select(self, duration):
        self.selects += 1
        assert self.selects <= 520, "unbounded production read/readiness loop"
        self.hit("select")
        events = [(self.exit_at if kind == "pid" else self.now, fd)
                  for fd, kind in self.reg.items()]
        nearest = min((t for t, _ in events), default=float("inf"))
        self.now = min(self.now + duration, max(self.now, nearest))
        return [(types.SimpleNamespace(data=self.reg[fd]), 1)
                for t, fd in events if t <= self.now]

    def read(self, fd, count):
        assert fd == 5
        self.reads += 1
        self.read_requests.append(count)
        assert self.reads <= 513, "read after the one-byte capacity probe"
        self.hit("read")
        if self.remaining:
            assert count == min(65536, self.remaining)
            self.remaining -= count
            return self.block[:count]
        assert count == 1
        return b"\xff" if self.probe else b""


def child_run(fake, setup_error=False):
    r, e = h._receipt_base(2700), h.Excerpt()
    r["terminationReason"] = "none"
    owned = h.Descriptors(fake)
    owned.owned.update((5, 6))
    c = h.Child(fake, owned, fake, 42, 5, 2700, r, e)
    def setup(c):
        if setup_error: raise OSError(errno.ENOSYS, "pidfd")
        c.pidfd = 6
    c.run(setup)
    body, counters = e.render(False)
    r.update(counters)
    return r, body, c


class Parser(unittest.TestCase):
    def test_C1_empty_oversize_eof(self):
        for raw in (b"", b"x" * 2049, h.canonical(receipt()).rstrip(b"\n")):
            self.assertEqual(11, parse(raw))
        def unavailable(fd, n): raise TimeoutError()
        self.assertEqual(11, h.parse_receipt(api=types.SimpleNamespace(read=unavailable)))

    def test_C1_canonical_record_still_requires_eof(self):
        raw = h.canonical(receipt())
        requests = []
        def read(fd, count):
            requests.append(count)
            if len(requests) == 1:
                self.assertGreaterEqual(count, len(raw))
                return raw
            raise TimeoutError("EOF unavailable after complete canonical record")
        self.assertEqual(11, h.parse_receipt(api=types.SimpleNamespace(read=read)))
        self.assertEqual([2049, 2049 - len(raw)], requests)

    def test_C2_invalid_canonical_types(self):
        raw = h.canonical(receipt())
        for data in (raw + raw, raw + b"\n", raw.replace(b"\n", b"\r\n"), b"\0" + raw,
                     b' {"a":1}\n', b'{"a":1,"a":2}\n', b'{"a":NaN}\n', b'{"a":Infinity}\n',
                     raw.replace(b'"schema":1', b'"schema":true'), raw.replace(b',', b', ', 1)):
            self.assertEqual(11, parse(data), data[:100])
        for key in receipt():
            r = receipt(); del r[key]
            self.assertEqual(11, parse(h.canonical(r)), key)
        r = receipt(); r["extra"] = 0
        self.assertEqual(11, parse(h.canonical(r)))

    def test_C3_maximum_receipt(self):
        r = receipt(255)
        for k in h.COUNTERS: r[k] = h.LIMITS[k]
        r.update(processState="not-started", terminationReason="capture-error", excerptPolicy="success-receipt-only")
        self.assertLessEqual(len(h.canonical(r)), 2048)
        log = {k: r[k] for k in h.LOG_KEYS}; log["role"] = "log"
        self.assertLessEqual(len(b"archival-image-build-receipt " + h.canonical(log)), 1000)

    def test_C4_C5_crossfields_and_status(self):
        for rc, expected in ((0, 0), (100, 10), (-15, 10)):
            self.assertEqual(expected, parse(h.canonical(receipt(rc))))
        changes = dict(schema=True, role="log", cleanupAuthority="remove", deadlineSeconds=2699,
                       processState="not-started", exitOrigin="none", rawReturnCode=None,
                       signalsSent="term", terminationReason="capacity", pipeEOF=False,
                       captureState="incomplete", excerptPolicy="none", logCommitted=False,
                       rawBytes=-1, normalizedBytes=1, payloadBytes=1, droppedNormalizedBytes=1,
                       inputLines=1, droppedLines=1, truncatedLines=1, shellExit=126)
        for k, v in changes.items():
            r = receipt(); r[k] = v
            self.assertEqual(11, parse(h.canonical(r)), k)
        # Same resulting numeric failure is not permission to alter an unrelated field.
        r = receipt(100); r["signalsSent"] = "term"
        self.assertEqual(11, parse(h.canonical(r)))
        self.assertEqual(10, parse(h.canonical(h._receipt_base(2700))))
        r = receipt(); r["rawBytes"] = 33554433
        self.assertEqual(11, parse(h.canonical(r)))
        for key in h.COUNTERS:
            r = h._receipt_base(2700); r[key] = 1
            self.assertEqual(11, parse(h.canonical(r)), key)

    def test_C6_spoofed_payload_and_F3_policy(self):
        e = h.Excerpt(); e.feed(b"archival-image-build-receipt " + h.canonical(receipt()), eof=True)
        r = receipt(100); r.update(e.render(False)[1]); r["captureState"] = "complete"
        self.assertEqual(10, parse(h.canonical(r)))
        for data in (b"", b"hello\n"):
            r = receipt(output=data)
            self.assertEqual(0, parse(h.canonical(r)))
            self.assertEqual("truncated" if data else "complete", r["captureState"])
            self.assertEqual(len(data), r["droppedNormalizedBytes"])
            r.update(captureState="error", logCommitted=False, shellExit=126)
            self.assertEqual(10, parse(h.canonical(r)))


class Lifecycle(unittest.TestCase):
    def test_C7_ready_descriptors_both_orders(self):
        for exit_at, eof_at in ((1, 2), (2, 1), (1, 1)):
            f = Fake(exit_at=exit_at, eof_at=eof_at)
            r, _, _ = child_run(f)
            self.assertEqual(("reaped", "pre-signal", True, "none"),
                             (r["processState"], r["exitOrigin"], r["pipeEOF"], r["signalsSent"]))
            self.assertLessEqual(f.selects, 2)
            self.assertEqual(1, f.reads)
            self.assertEqual(1, f.waits)

    def test_C8_held_writer_keeps_zombie_through_KILL(self):
        f = Fake(eof_at=float("inf"))
        r, _, _ = child_run(f)
        self.assertEqual("deadline", r["terminationReason"])
        self.assertEqual([("TERM", 2700), ("KILL", 2710)], [x for x in f.calls if x[0] in ("TERM", "KILL")])
        self.assertEqual(("waitpid", 2715), f.calls[-1])
        self.assertFalse(r["pipeEOF"])
        self.assertEqual(124, h.primary(r))

    def test_C9_continuously_readable_deadline(self):
        f = Fake(exit_at=float("inf"), eof_at=float("inf"), data=b"x" * 40)
        original = f.read
        def read(fd, count):
            f.now += 1000
            return original(fd, 1)
        f.read = read
        r, _, _ = child_run(f)
        self.assertEqual("deadline", r["terminationReason"])
        self.assertEqual(3, f.reads)
        self.assertEqual(3015, f.now)

    def test_C10_unjoined_and_signal_errors(self):
        f = Fake(exit_at=float("inf"), eof_at=float("inf"), failures={"TERM": ProcessLookupError()})
        r, _, _ = child_run(f)
        self.assertEqual("unjoined", r["processState"])
        self.assertEqual(125, h.primary(r))
        self.assertEqual(2715, f.now)
        self.assertNotIn("waitpid", [x[0] for x in f.calls])

    def test_C11_presignal_failure_survives_commit_error(self):
        for rc, expected in ((100, 100), (-15, 143)):
            r = receipt(rc); r.update(captureState="error", logCommitted=False)
            self.assertEqual(expected, h.primary(r))
            self.assertEqual(10, parse(h.canonical(r)))
        r = receipt(-9); r.update(exitOrigin="post-kill", signalsSent="term-kill", terminationReason="deadline", shellExit=124)
        self.assertEqual(124, h.primary(r))
        self.assertEqual(10, parse(h.canonical(r)))

    def test_C12_read_select_pidfd_faults(self):
        for name in ("read", "select", "close"):
            f = Fake(failures={name: OSError(errno.EIO, name)})
            r, _, _ = child_run(f)
            self.assertEqual("capture-error", r["terminationReason"])
            self.assertEqual("term-kill", r["signalsSent"])
            self.assertLessEqual(f.now, 17)
        f = Fake()
        r, _, _ = child_run(f, True)
        self.assertEqual("post-term", r["exitOrigin"])
        self.assertEqual(15, f.now)
        self.assertLessEqual(f.waits, 3)

    def test_F1_ownership_refusal_no_further_requests(self):
        bad = types.SimpleNamespace(si_pid=43, si_code=os.CLD_EXITED, si_status=0)
        for stage, value in (("waitid", ChildProcessError()), ("waitid", bad),
                             ("waitpid", (0, 0)), ("waitpid", (43, 0)), ("waitpid", (42, 100)),
                             ("waitpid", ChildProcessError())):
            f = Fake(failures={stage: value})
            with self.assertRaises(h.OwnershipLost): child_run(f)
            self.assertFalse(any(x[0] in ("TERM", "KILL") for x in f.calls))


class Accounting(unittest.TestCase):
    def test_C13_incremental_partial_and_metadata(self):
        for chunks, eof, expected, lines in (([b"a"], False, b"a", 1), ([b"a\r\n"], True, b"a\r\n", 1),
              ([b"\xf0\x9f", b"\x98\x80\xff"], True, "😀\\xff".encode(), 1),
              ([b"a\xf0\x9f"], False, b"a", 1), ([b"\xf0\x9f"], True, b"\\xf0\\x9f", 1), ([], True, b"", 0)):
            e = h.Excerpt()
            for chunk in chunks: e.feed(chunk)
            if eof: e.feed(b"", eof=True)
            body, c = e.render()
            self.assertEqual(len(expected), c["normalizedBytes"])
            self.assertEqual(len(expected), c["payloadBytes"])
            self.assertEqual(lines, c["inputLines"])
            self.assertEqual(expected + (b"\n" if expected and not expected.endswith(b"\n") else b""), body)
            self.assertEqual((body, c), e.render())

    def test_C14_C15_escaped_and_long_line_bounds(self):
        e = h.Excerpt()
        for _ in range(320): e.feed(b"\x01" * 65536)
        body, c = e.render()
        self.assertEqual(20971520, c["normalizedBytes"])
        self.assertEqual(1, c["inputLines"])
        self.assertEqual(1, c["truncatedLines"])
        self.assertEqual(960, c["payloadBytes"])
        self.assertIn(b"20971520 bytes]", body)
        self.assertLessEqual(max(map(len, body.splitlines())), 999)
        e = h.Excerpt()
        for _ in range(400): e.feed(("\x01😀\\" * 120 + "\n").encode())
        body, c = e.render()
        self.assertLessEqual(len(body), 59000)
        self.assertLessEqual(sum(h.Excerpt.cost(x) for x in body.split(b"\n")) + 2004, 196608)
        self.assertLessEqual(len(e.head), 40); self.assertLessEqual(len(e.tail), 180)

    def test_C16_disjoint_marker_between_head_and_tail(self):
        e = h.Excerpt()
        for i in range(300): e.feed(f"row{i:03}\n".encode())
        body, c = e.render()
        self.assertEqual(300, c["inputLines"])
        self.assertEqual(80, c["droppedLines"])
        self.assertEqual(560, c["droppedNormalizedBytes"])
        self.assertEqual(1540, c["payloadBytes"])
        self.assertLess(body.index(b"row039"), body.index(b"[archival"))
        self.assertLess(body.index(b"[archival"), body.index(b"row120"))
        self.assertEqual(1, body.count(b"row039"))

    def test_C17_capacity_probe_excluded(self):
        for probe in (False, True):
            e = h.Excerpt()
            for _ in range(512): self.assertFalse(e.feed(b"x" * 65536))
            if probe: self.assertTrue(e.feed(b"\xff"))
            else: e.feed(b"", eof=True)
            _, c = e.render()
            self.assertEqual(33554432 + probe, c["rawBytes"])
            self.assertEqual(33554432, c["normalizedBytes"])
            self.assertEqual(1, c["inputLines"])


class Writes(unittest.TestCase):
    def test_F4_short_zero_eintr_late_partial(self):
        for sequence, good in (([1, 2], True), ([InterruptedError(), 3], True), ([0], False),
                               ([1, BrokenPipeError()], False), ([3], False)):
            now, calls = [0], []
            def write(fd, data):
                calls.append(bytes(data)); result = sequence.pop(0)
                if isinstance(result, BaseException): raise result
                if result == 3 and not good: now[0] = 5
                return result
            s = types.SimpleNamespace(os=types.SimpleNamespace(write=write), clock=lambda: now[0])
            if good: h.write_all(s, 1, b"abc", 5)
            else:
                with self.assertRaises((h.Refused, OSError)): h.write_all(s, 1, b"abc", 5)
            self.assertEqual(b"abc", calls[0])
            self.assertLessEqual(len(calls), 2)

    def test_F2_descriptor_aliases(self):
        calls = []
        s = types.SimpleNamespace(os=types.SimpleNamespace(close=lambda fd: calls.append(("close", fd)),
                    set_inheritable=lambda fd, val: calls.append(("inherit", fd, val))),
                    fcntl=types.SimpleNamespace(F_DUPFD_CLOEXEC=1030, fcntl=lambda fd, cmd, low: 3))
        owned = h.Descriptors(s)
        self.assertEqual(3, owned.add(0)); self.assertEqual({3}, owned.owned)
        self.assertEqual(("close", 0), calls[0]); self.assertEqual(("inherit", 3, False), calls[1])
        self.assertFalse(owned.finish())


class CaptureIntegration(unittest.TestCase):
    def run_capture(self, failure=None, rc=0, data=b"", limits=(-1, -1), exit_at=1, eof_at=2,
                    fake_factory=Fake, admission=None):
        f = fake_factory(rc=rc, data=data, exit_at=exit_at, eof_at=eof_at)
        f.build, f.environ = ROOT / "build", {}
        f.admit = (lambda: None) if admission is None else (lambda: admission(f))
        f.selector = lambda: f
        f.umask = lambda mask: 0o022
        f.pipe2 = lambda flags: (5, 7)
        f.set_blocking = lambda *a: None
        for name in ("O_CLOEXEC", "O_RDONLY", "POSIX_SPAWN_OPEN", "POSIX_SPAWN_DUP2", "POSIX_SPAWN_CLOSE"):
            setattr(f, name, getattr(os, name))
        f.output, f.log = bytearray(), b""
        order = []
        def spawn(*a, **kw):
            order.append(("spawn", a, kw))
            if failure == "spawn": raise FileNotFoundError()
            return 42
        f.posix_spawnp = spawn
        def pidfd(*a):
            if failure == "pidfd": raise OSError()
            return 6
        f.pidfd_open = pidfd
        def limits_set(which, values):
            order.append(("limit", which, values))
            if failure == "rlimit" and which == resource.RLIMIT_CORE: raise OSError()
        f.resource = types.SimpleNamespace(RLIMIT_FSIZE=resource.RLIMIT_FSIZE, RLIMIT_CORE=resource.RLIMIT_CORE,
            RLIM_INFINITY=-1, getrlimit=lambda which: limits, setrlimit=limits_set)
        def write(fd, data):
            self.assertEqual(1, fd)
            if failure == "control": raise BrokenPipeError()
            if failure == "control-partial":
                if f.output: raise BrokenPipeError()
                f.output.extend(data[:1]); return 1
            f.output.extend(data); return len(data)
        f.write = write
        native_close = f.close
        def close(fd=None):
            if fd == 1 and failure == "control-close": raise OSError(errno.EIO, "control-close")
            if fd is not None: native_close(fd)
        f.close = close
        class DirectoryFake:
            def __init__(self, *args): pass
            def commit(self, data, mask, deadline):
                f.log = data
                if failure == "commit": raise OSError(errno.EFBIG, "commit")
        with patch.object(h, "Directories", DirectoryFake):
            result = h.capture(str(f.build / "decomp-archival-ci.abcdef"), 1, 2, 2700,
                               ["docker", "build", "--tag", "image", "."], api=f)
        return result, f, order

    def test_C12_C20_spawn_limits_control_commit(self):
        for limits, cap in (((1024, 2048), 1024), ((-1, -1), 65536), ((4096, 4096), 4096)):
            rc, f, order = self.run_capture(limits=limits)
            self.assertEqual(0, rc); self.assertEqual(0, parse(bytes(f.output)))
            self.assertEqual("spawn", order[0][0])
            self.assertEqual(("limit", resource.RLIMIT_FSIZE, (cap, cap)), order[1])
            self.assertEqual(("limit", resource.RLIMIT_CORE, (0, 0)), order[2])
            self.assertTrue(order[0][2]["setsid"])
            self.assertEqual({signal.SIGPIPE, signal.SIGXFSZ}, order[0][2]["setsigdef"])
        for failure, expected in (("spawn", 126), ("pidfd", 126), ("rlimit", 126), ("control", 126), ("commit", 126)):
            rc, f, _ = self.run_capture(failure)
            self.assertEqual(expected, rc, failure)
            self.assertEqual(11 if failure == "control" else 10, parse(bytes(f.output)), failure)
        rc, f, _ = self.run_capture("commit", rc=100, data=b"Unable to locate package ninja-build\n")
        self.assertEqual(100, rc); self.assertEqual(10, parse(bytes(f.output)))
        self.assertIn(b"Unable to locate package ninja-build", f.log)
        self.assertFalse(any(x[0] in ("TERM", "KILL") for x in f.calls))

    def test_control_close_failure_never_success(self):
        rc, f, _ = self.run_capture("control-close")
        self.assertEqual(126, rc)
        self.assertEqual(0, parse(bytes(f.output)))
        self.assertFalse(any(x[0] in ("TERM", "KILL") for x in f.calls))

    def test_control_partial_is_not_replaced(self):
        rc, f, _ = self.run_capture("control-partial")
        self.assertEqual(126, rc)
        self.assertEqual(b"{", bytes(f.output))
        self.assertEqual(11, parse(bytes(f.output)))
        self.assertFalse(any(x[0] in ("TERM", "KILL") for x in f.calls))

    def test_final_deadline_unjoined_and_refused_reap(self):
        for exit_at, expected in ((1, 124), (float("inf"), 125)):
            rc, f, _ = self.run_capture(exit_at=exit_at, eof_at=float("inf"))
            self.assertEqual(expected, rc)
            self.assertEqual(10, parse(bytes(f.output)))
            self.assertTrue(f.log)
            self.assertTrue(json.loads(f.output)["logCommitted"])

    def test_F3_success_empty_and_nonempty_frozen(self):
        for data in (b"", b"omitted\n"):
            for failure in (None, "commit"):
                rc, f, _ = self.run_capture(failure, data=data)
                r = json.loads(f.output)
                self.assertEqual(0 if failure is None else 126, rc)
                self.assertEqual("success-receipt-only", r["excerptPolicy"])
                self.assertEqual(0, r["payloadBytes"])
                self.assertEqual(len(data), r["droppedNormalizedBytes"])
                self.assertEqual(1 if data else 0, r["droppedLines"])
                self.assertTrue(f.log.startswith(b"archival-image-build-receipt "))

    def test_C17_capture_capacity_refusal_and_exact_cap_eof(self):
        for probe in (False, True):
            def factory(**kwargs):
                return CapacityStream(probe=probe, **kwargs)
            rc, f, _ = self.run_capture(fake_factory=factory)
            self.assertEqual([65536] * 512 + [1], f.read_requests)
            self.assertEqual(513, f.reads)
            self.assertLessEqual(f.selects, 514)
            r = json.loads(f.output)
            self.assertEqual(33554432 + int(probe), r["rawBytes"])
            self.assertEqual(33554432, r["normalizedBytes"])
            self.assertTrue(r["logCommitted"])
            self.assertTrue(f.log.endswith(b"\n"))
            if probe:
                self.assertEqual(126, rc)
                self.assertEqual(10, parse(bytes(f.output)))
                self.assertEqual("capacity", r["terminationReason"])
                self.assertEqual("incomplete", r["captureState"])
                self.assertFalse(r["pipeEOF"])
                self.assertEqual("reaped", r["processState"])
                self.assertEqual("post-term", r["exitOrigin"])
                self.assertEqual([("TERM", 0.0), ("KILL", 10.0)],
                                 [x for x in f.calls if x[0] in ("TERM", "KILL")])
                self.assertEqual([("waitpid", 15.0)], [x for x in f.calls if x[0] == "waitpid"])
                self.assertEqual(15.0, f.now)
            else:
                self.assertEqual(0, rc)
                self.assertEqual(0, parse(bytes(f.output)))
                self.assertEqual("none", r["terminationReason"])
                self.assertTrue(r["pipeEOF"])
                self.assertEqual("truncated", r["captureState"])
                self.assertFalse(any(x[0] in ("TERM", "KILL") for x in f.calls))

    def test_F2_capture_admission_failure_never_spawns(self):
        variants = ("pipe2", "posix_spawnp", "pidfd_open", "waitid", "waitpid", "SIGCHLD")
        for missing in variants:
            def admission(fake):
                # Invoke the real admission logic over isolated attribute copies;
                # no native fstat/fcntl/getsignal call is needed in these controls.
                system = h.System()
                system.os = types.SimpleNamespace(**vars(os))
                system.signal = types.SimpleNamespace(**vars(signal))
                system.fcntl = types.SimpleNamespace(**vars(h.fcntl))
                system.os.fstat = lambda fd: object()
                system.fcntl.fcntl = lambda fd, command: os.O_WRONLY
                system.signal.getsignal = lambda sig: signal.SIG_IGN if missing == "SIGCHLD" else signal.SIG_DFL
                if missing != "SIGCHLD":
                    setattr(system.os, missing, None)
                system.admit()
            rc, f, order = self.run_capture(admission=admission)
            self.assertEqual(126, rc, missing)
            self.assertEqual([], order, missing)  # includes zero spawn and zero limit changes
            self.assertEqual(10, parse(bytes(f.output)), missing)
            r = json.loads(f.output)
            self.assertEqual("not-started", r["processState"])
            self.assertEqual("capture-error", r["terminationReason"])
            self.assertEqual("none", r["excerptPolicy"])
            self.assertFalse(r["logCommitted"])
            self.assertEqual(b"", f.log)
            self.assertEqual(0, f.reads)

    def test_F2_missing_static_api_refuses_before_spawn(self):
        for name in ("pipe2", "posix_spawnp", "pidfd_open", "waitid", "waitpid", "read", "write"):
            s = h.System()
            with patch.object(s.os, name, None):
                with self.assertRaises(h.Refused): s.admit()
        s = h.System()
        with patch.object(s.signal, "getsignal", return_value=signal.SIG_IGN):
            with self.assertRaises(h.Refused): s.admit()


class Filesystem(unittest.TestCase):
    def setUp(self):
        (ROOT / "build").mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="decomp-archival-ci.", dir=ROOT / "build")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.reports = self.root / "output/archival-image/reports"
        self.reports.mkdir(parents=True)
        st = self.root.stat(); self.identity = (st.st_dev, st.st_ino)
        self.s = h.System()
        self.owned = h.Descriptors(self.s)
        self.addCleanup(self.owned.finish)
        self.mask = os.umask(0); os.umask(self.mask)
    def admit(self): return h.Directories(self.s, self.owned, self.root, *self.identity)
    def commit(self, d, data=b"actual log\n"):
        d.commit(data, self.mask, self.s.clock() + 5)
    def test_C18_exclusive_and_links(self):
        log = self.reports / "build.log"
        other = self.root / "original"; other.write_bytes(b"unchanged")
        for kind in ("regular", "symlink", "hardlink", "fifo"):
            if kind == "regular": log.write_bytes(b"original")
            elif kind == "symlink": log.symlink_to(other)
            elif kind == "hardlink": os.link(other, log)
            else: os.mkfifo(log)
            with self.assertRaises(h.Refused): self.admit()
            self.assertTrue(log.exists()); self.assertEqual(b"unchanged", other.read_bytes())
            log.unlink()
    def test_renamed_root_and_archival_image(self):
        for path in (self.root, self.root / "output/archival-image"):
            d = self.admit()
            moved = path.with_name(path.name + "-moved")
            path.rename(moved)
            try:
                with self.assertRaises((OSError, h.Refused)): self.commit(d)
            finally:
                moved.rename(path)

    def test_C19_expected_insertion_and_selfmutation(self):
        d = self.admit(); self.commit(d)
        self.assertEqual(b"actual log\n", (self.reports / "build.log").read_bytes())
        with self.assertRaises((h.Refused, OSError)): self.commit(d)
    def test_C18_named_edge_and_leaf_close_replacement(self):
        d = self.admit()
        self.reports.rename(self.reports.with_name("reports-old")); self.reports.mkdir()
        with self.assertRaises(h.Refused): self.commit(d)
    def test_F4_after_close_identity_mode_and_extra_entry(self):
        for change in ("replace", "mode", "extra"):
            with self.subTest(change=change):
                d = self.admit()
                original = self.s.os.close
                fired = False
                def close(fd):
                    nonlocal fired
                    original(fd)
                    log = self.reports / "build.log"
                    if not fired and log.exists():
                        fired = True
                        if change == "replace":
                            log.rename(self.reports / "old"); log.write_bytes(b"actual log\n")
                        elif change == "mode": log.chmod(0o600 if (0o644 & ~self.mask) != 0o600 else 0o644)
                        else: (self.reports / "extra").write_bytes(b"")
                with patch.object(self.s.os, "close", side_effect=close):
                    with self.assertRaises(h.Refused): self.commit(d)
                for file in self.reports.iterdir(): file.unlink()

    def test_C14_F5_collector_lone_tail_pop_and_refusal(self):
        e = h.Excerpt()
        for _ in range(300): e.feed(("\x01😀\\" * 100 + "\n").encode())
        e.feed(b"Unable to locate package ninja-build\n", eof=True)
        body, _ = e.render()
        log = body + b"archival-image-build-receipt evidence\n"
        self.commit(self.admit(), log)
        rows = []
        self.assertEqual(0, collector.collect(self.root, self.identity, rows.append))
        self.assertIn("Unable to locate package ninja-build", "".join(rows))
        self.assertIn("archival-image-build-receipt evidence", "".join(rows))
        self.assertLessEqual(len("".join(rows)), 200704 + 2048)
        # Force the unchanged collector's pop boundary, then explicit header refusal.
        with patch.object(collector, "MAX_OUTPUT_BYTES", 4096):
            rows = []; self.assertEqual(0, collector.collect(self.root, self.identity, rows.append))
            records = list(map(json.loads, rows))
            self.assertTrue(next(x for x in records if x["kind"] == "file")["truncated"])
            self.assertNotIn("Unable to locate package ninja-build", "".join(rows))
        with patch.object(collector, "MAX_OUTPUT_BYTES", 2200):
            rows = []; self.assertEqual(2, collector.collect(self.root, self.identity, rows.append))
            self.assertIn("diagnostic-byte-budget", "".join(rows))
        self.assertTrue(self.root.exists())


class ActionsProcess(unittest.TestCase):
    setUp = Filesystem.setUp
    """Finite actual primitives, run only by the ordinary Actions test invocation."""
    def run_child(self, program, closed_stderr=False):
        # Separate helper process: limits and SIGCHLD cannot affect the test runner.
        code = ("import importlib.util,sys; "
                "s=importlib.util.spec_from_file_location('helper',sys.argv[1]); "
                "h=importlib.util.module_from_spec(s); s.loader.exec_module(h); "
                "h.TERM_GRACE=.15; h.KILL_GRACE=.15; "
                + ("import os; os.close(2); " if closed_stderr else "") +
                "sys.exit(h.capture(sys.argv[2],int(sys.argv[3]),int(sys.argv[4]),1,[sys.executable,'-c',sys.argv[5]]))")
        result = subprocess.run([sys.executable, "-I", "-B", "-c", code,
                    str(ROOT / "scripts/capture-archival-image-build.py"), str(self.root),
                    *map(str, self.identity), program], capture_output=True, timeout=5)
        self.assertEqual(b"", result.stderr)
        return result
    def test_real_EOF_before_exit(self):
        result = self.run_child("import os,time; os.close(1); os.close(2); time.sleep(.05)")
        self.assertEqual(0, result.returncode)
        self.assertEqual(0, parse(result.stdout, 1))
    def test_real_exit_before_EOF(self):
        result = self.run_child("import os,time; p=os.fork(); time.sleep(.05) if p==0 else None; os._exit(0)")
        self.assertEqual(0, result.returncode)
        self.assertEqual(0, parse(result.stdout, 1))
    def test_C22_APT100(self):
        result = self.run_child("print('Unable to locate package ninja-build'); raise SystemExit(100)")
        self.assertEqual(100, result.returncode)
        self.assertEqual(10, parse(result.stdout, 1))
        self.assertIn(b"Unable to locate package ninja-build", (self.reports / "build.log").read_bytes())
    def test_C23_descendant_writer(self):
        result = self.run_child("import os,time; p=os.fork(); time.sleep(3) if p==0 else None; os._exit(0)")
        self.assertEqual(124, result.returncode)
        r = json.loads(result.stdout)
        self.assertEqual("pre-signal", r["exitOrigin"])
        self.assertEqual("term-kill", r["signalsSent"])
    def test_C24_TERM_ignored(self):
        result = self.run_child("import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(3)")
        self.assertEqual(124, result.returncode)
        r = json.loads(result.stdout)
        self.assertEqual(-9, r["rawReturnCode"])
        self.assertEqual("post-kill", r["exitOrigin"])
    def test_C25_closed_stderr(self):
        result = self.run_child("print('child stdout only')", closed_stderr=True)
        # An epoll descriptor aliasing closed stderr is an admitted refusal.
        self.assertEqual(126, result.returncode)
        self.assertEqual(10, parse(result.stdout, 1))


class Shell(unittest.TestCase):
    def test_C26_C27_actual_PIPESTATUS_block(self):
        original = (ROOT / "scripts/validate-archival-docker.sh").read_text()
        block = original[original.index("# archival-image-build: begin"):original.index("# archival-image-build: end")]
        self.assertIn('image_build_status=("${PIPESTATUS[@]}")\nset -e', block)
        for helper, parser, expected in ((100, 10, 100), (0, 11, 126), (100, 0, 100), (0, 0, 0)):
            with tempfile.TemporaryDirectory(prefix="capture-shell-", dir=ROOT / "build") as tmp:
                root = Path(tmp); (root / "scripts").mkdir(); (root / "build").mkdir()
                (root / "scripts/capture-archival-image-build.py").write_text(
                    f"import sys\nraise SystemExit({parser} if '--parse-receipt' in sys.argv else {helper})\n")
                # Preserve actual pipeline and control flow, prove monotonic trap veto.
                script = ('set -euo pipefail\nvalidation_root=unused\nvalidation_device=0\nvalidation_inode=0\nimage=x\n'
                          'image_build_started=0\nimage_build_verified=0\nimage_built=0\n'
                          'trap \'s=$?; if ((image_build_started && !image_build_verified)); then echo retain; else echo verified; fi; exit "$s"\' EXIT\n'
                          + block + '\nimage_built=1\necho built=$image_built\n')
                result = subprocess.run(["bash", "-c", script], cwd=root, capture_output=True, timeout=5)
                self.assertEqual(expected, result.returncode)
                self.assertIn(b"verified" if expected == 0 else b"retain", result.stdout)
                self.assertEqual(expected == 0, b"built=1" in result.stdout)

    def test_C28_preserved_sources_and_C21_root(self):
        for name, expected in (("collect-archival-diagnostics.py", "96ecf6c23476528c8e014f4774f0b9bc4d4f8d89"),
                               ("test-archival-diagnostics.py", "845ec699a7a38b905b776c36d0b08aba485084ad")):
            data = (ROOT / "scripts" / name).read_bytes()
            self.assertEqual(expected, hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest())
        self.assertEqual(collector.BUILD, h.BUILD)
        helper_source = (ROOT / "scripts/capture-archival-image-build.py").read_text()
        self.assertNotIn("Popen", helper_source)
        self.assertNotIn("communicate(", helper_source)
        self.assertEqual((10.0, 5.0, 5.0), (h.TERM_GRACE, h.KILL_GRACE, h.COMMIT_SECONDS))
        script = (ROOT / "scripts/validate-archival-docker.sh").read_text()
        boundary = 'mkdir -p "$validation_root/input" "$validation_root/output"\n'
        self.assertEqual(1, script.count(boundary))
        prefix = script.split(boundary)[0]
        self.assertEqual(1, prefix.count("10s docker run")); self.assertEqual(1, prefix.count("20s rm -rf"))
        self.assertIn("image_build_started && !image_build_verified", prefix)
        self.assertIn("-- docker build --tag", script)
        self.assertIn("2740s", script); self.assertIn("2750s", script)


class AdditionalControls(unittest.TestCase):
    setUp = Filesystem.setUp
    admit = Filesystem.admit
    commit = Filesystem.commit
    def test_F4_short_write_and_final_check_deadline(self):
        d = self.admit()
        native = self.s.os.write
        calls = []
        def short(fd, data):
            calls.append(len(data)); return native(fd, data[:2])
        with patch.object(self.s.os, "write", side_effect=short): self.commit(d)
        self.assertEqual([11, 9, 7, 5, 3, 1], calls)
        self.assertEqual(b"actual log\n", (self.reports / "build.log").read_bytes())

    def test_F4_late_final_close_withholds_commit(self):
        d = self.admit(); now = [0]
        self.s.clock = lambda: now[0]
        native = self.s.os.close
        def close(fd):
            native(fd); now[0] = 5
        with patch.object(self.s.os, "close", side_effect=close):
            with self.assertRaises(h.Refused): self.commit(d)
        self.assertTrue((self.reports / "build.log").exists())

    def test_C18_foreign_device_and_owner_mode_mutation(self):
        d = self.admit()
        original = self.s.os.fstat
        def foreign(fd):
            st = original(fd)
            names = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
            fields = {name: getattr(st, name) for name in names}
            fields["st_dev"] += 1
            return types.SimpleNamespace(**fields)
        with patch.object(self.s.os, "fstat", side_effect=foreign):
            with self.assertRaises(h.Refused): self.commit(d)
        self.assertFalse((self.reports / "build.log").exists())

    def test_F5_combined_receipt_and_reconstruction_pop(self):
        self.commit(self.admit(), b"archival-image-build-receipt evidence\n")
        other = self.root / "output/z-reconstruction/reports/build.log"
        other.parent.mkdir(parents=True)
        other.write_bytes((b"x" * 900 + b"\n") * 55 + b"reconstruction-tail\n")
        baseline = []
        self.assertEqual(0, collector.collect(self.root, self.identity, baseline.append))
        records = list(map(json.loads, baseline))
        first_two = sum(len(line) for line in baseline[:2])
        # Enough for root + receipt file + reconstruction header, too little for its lines.
        ceiling = first_two + 500 + collector.SUMMARY_RESERVE
        with patch.object(collector, "MAX_OUTPUT_BYTES", ceiling):
            rows = []; self.assertEqual(0, collector.collect(self.root, self.identity, rows.append))
        self.assertIn("archival-image-build-receipt evidence", "".join(rows))
        self.assertNotIn("reconstruction-tail", "".join(rows))
        self.assertTrue(any(r.get("truncated") for r in map(json.loads, rows)))
        with patch.object(collector, "MAX_OUTPUT_BYTES", first_two + 10 + collector.SUMMARY_RESERVE):
            rows = []; self.assertEqual(2, collector.collect(self.root, self.identity, rows.append))
        self.assertTrue(self.root.exists())

    def test_R4_maximum_legal_metadata_encoding(self):
        encode = lambda r: len(json.dumps(r, ensure_ascii=True, separators=(",", ":"))) + 1
        root = dict(kind="root", name="decomp-archival-ci." + "_" * 32,
                    device=2**64-1, inode=2**64-1, uid=2**32-1, gid=2**32-1, mode=0o7777)
        header = dict(kind="file", path="output/archival-image/reports/build.log", uid=2**32-1,
                      gid=2**32-1, mode=0o7777, size=2**63-1, truncated=False, lines=[])
        self.assertLessEqual(encode(root) + encode(header), 4096)


class ActualRetention(unittest.TestCase):
    def test_C26_actual_cleanup_retains_after_passed_collector(self):
        source = (ROOT / "scripts/validate-archival-docker.sh").read_text()
        boundary = 'mkdir -p "$validation_root/input" "$validation_root/output"\n'
        prefix = source.split(boundary)[0]
        for status in (100, 126):
            with tempfile.TemporaryDirectory(prefix="capture-retention-", dir=ROOT / "build") as tmp:
                root = Path(tmp)
                (root / "scripts").mkdir(); (root / "bin").mkdir(); (root / "build").mkdir()
                (root / "scripts/collect-archival-diagnostics.py").write_bytes((ROOT / "scripts/collect-archival-diagnostics.py").read_bytes())
                fake = root / "bin/rm"
                fake.write_text('#!/bin/sh\necho forbidden-removal >&2\nexit 99\n'); fake.chmod(0o700)
                script = root / "scripts/test.sh"
                script.write_text(prefix + '\nmkdir -p "$validation_root/output/archival-image/reports"\n'
                                  'printf "evidence\\n" > "$validation_root/output/archival-image/reports/build.log"\n'
                                  'image_build_started=1\nimage_build_verified=0\n' + f'exit {status}\n')
                result = subprocess.run(["bash", str(script)], cwd=root,
                           env={**os.environ, "PATH": str(root / "bin") + os.pathsep + os.environ["PATH"]},
                           capture_output=True, timeout=5)
                self.assertEqual(status, result.returncode)
                self.assertNotIn(b"forbidden-removal", result.stderr)
                self.assertIn(b'"status":"passed"', result.stderr)
                self.assertEqual(1, len(list((root / "build").glob("decomp-archival-ci.*"))))


if __name__ == "__main__":
    unittest.main()
