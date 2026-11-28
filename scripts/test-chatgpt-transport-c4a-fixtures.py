#!/usr/bin/env python3
"""Finite POSIX wrapper controls; fake keytools never invoke Java or a network."""
import ctypes
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
SUBJECT = Path(os.environ.get("C4A_FIXTURE_SUBJECT", ROOT / "scripts/generate-chatgpt-transport-c4a-fixtures.py")).resolve()
assert SUBJECT.is_relative_to(ROOT)
spec = importlib.util.spec_from_file_location("c4a_fixture_subject", SUBJECT)
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class FixtureControls(unittest.TestCase):
    def setUp(self):
        (ROOT / "build").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="c4a-fixture-controls-", dir=ROOT / "build")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def tool(self, body):
        path = self.root / "keytool"
        path.write_text(f"#!{sys.executable} -B\n" + body)
        path.chmod(0o700)
        return path

    def output_tool(self, count):
        return self.tool(
            "import os,sys\nfrom pathlib import Path\n"
            f"remaining={count}\n"
            "while remaining:\n remaining-=os.write(1,b'x'*min(remaining,4096))\n"
            "Path(sys.argv[sys.argv.index('-keystore')+1]).write_bytes(b'fixture')\n")

    def test_exact_output_limit_succeeds_and_next_byte_refuses_without_disk_log(self):
        subject.run_keytool(self.output_tool(32768), self.root / "server.p12", "test", "example.invalid")
        self.assertEqual((self.root / "server.p12").read_bytes(), b"fixture")
        with self.assertRaisesRegex(RuntimeError, "output exceeded"):
            subject.run_keytool(self.output_tool(32769), self.root / "next.p12", "test", "example.invalid")
        self.assertEqual(list(self.root.glob("*.log")), [])

    def test_stdout_is_a_pipe_not_a_disk_file(self):
        tool = self.tool(
            "import os,stat,sys\nfrom pathlib import Path\n"
            "assert stat.S_ISFIFO(os.fstat(1).st_mode), 'output must not be a disk file'\n"
            "Path(sys.argv[sys.argv.index('-keystore')+1]).write_bytes(b'fixture')\n")
        subject.run_keytool(tool, self.root / "server.p12", "test", "example.invalid")

    def descendant(self, leader_status):
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        marker = self.root / "survived"
        pidfile = self.root / "child.pid"
        child_body = f"import time;from pathlib import Path;time.sleep(0.4);Path({str(marker)!r}).write_text('survived')"
        tool = self.tool(
            "import os,subprocess,sys\nfrom pathlib import Path\n"
            f"child=subprocess.Popen([{sys.executable!r},'-B','-c',{child_body!r}])\n"
            f"Path({str(pidfile)!r}).write_text(str(child.pid))\n"
            "Path(sys.argv[sys.argv.index('-keystore')+1]).write_bytes(b'fixture')\n"
            f"os._exit({leader_status})\n")
        pid = None
        reaped = False
        try:
            if leader_status:
                with self.assertRaisesRegex(RuntimeError, "keytool failed"):
                    subject.run_keytool(tool, self.root / "server.p12", "test", "example.invalid")
            else:
                subject.run_keytool(tool, self.root / "server.p12", "test", "example.invalid")
            pid = int(pidfile.read_text())
            cutoff = time.monotonic() + 3
            while time.monotonic() < cutoff:
                found, status = os.waitpid(pid, os.WNOHANG)
                if found:
                    reaped = True
                    self.assertEqual(os.waitstatus_to_exitcode(status), -signal.SIGKILL)
                    break
                time.sleep(0.01)
            self.assertTrue(reaped, "same-group descendant did not stop")
            self.assertFalse(marker.exists(), "descendant ran after leader completion")
        finally:
            if pid is None and pidfile.exists():
                pid = int(pidfile.read_text())
            if pid is not None and not reaped:
                # It is an unreaped adopted child of this isolated test process.
                observed = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                if observed is None:
                    os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            self.assertEqual(libc.prctl(36, previous.value, 0, 0, 0), 0)

    def test_failed_leader_does_not_leave_same_group_descendant(self):
        self.descendant(9)

    def test_successful_leader_does_not_leave_same_group_descendant(self):
        self.descendant(0)

    def test_timeout_reaps_direct_child(self):
        pidfile = self.root / "direct.pid"
        tool = self.tool(f"import os,time\nfrom pathlib import Path\nPath({str(pidfile)!r}).write_text(str(os.getpid()))\ntime.sleep(10)\n")
        old = subject.COMMAND_TIMEOUT_SECONDS
        subject.COMMAND_TIMEOUT_SECONDS = 0.1
        try:
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                subject.run_keytool(tool, self.root / "server.p12", "test", "example.invalid")
            with self.assertRaises(ChildProcessError):
                os.waitid(os.P_PID, int(pidfile.read_text()), os.WEXITED | os.WNOWAIT | os.WNOHANG)
            self.assertEqual(list(self.root.glob("*.log")), [])
        finally:
            subject.COMMAND_TIMEOUT_SECONDS = old
            if pidfile.exists():
                pid = int(pidfile.read_text())
                try:
                    if os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
                        os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass

    def test_cleanup_error_does_not_replace_original_output_failure(self):
        original = subject.terminate
        def fail_after_reap(process):
            original(process)
            raise OSError("synthetic cleanup failure")
        subject.terminate = fail_after_reap
        try:
            with self.assertRaisesRegex(RuntimeError, "output exceeded"):
                subject.run_keytool(self.output_tool(1024 * 1024), self.root / "server.p12", "test", "example.invalid")
        finally:
            subject.terminate = original

    def test_build_root_refused_before_deletion(self):
        build = self.root / "build"
        build.mkdir()
        sentinel = build / "keep"
        sentinel.write_text("preserve")
        result = subprocess.run([sys.executable, "-B", str(SUBJECT), "--keytool", str(self.tool("pass\n")),
                                 "--output", str(build)], cwd=self.root, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(sentinel.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
