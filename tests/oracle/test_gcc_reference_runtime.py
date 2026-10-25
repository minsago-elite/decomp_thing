from __future__ import annotations

import hashlib
import os
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PROBE = runpy.run_path(str(ROOT / "oracle/gcc/reference_runtime_probe.py"))
CAPTURE = runpy.run_path(str(ROOT / "scripts/capture-gcc-preprocessing-reference.py"))


class RuntimeClosureTest(unittest.TestCase):
    def inspect(self, header, dynamic, listing):
        inspect = PROBE["inspect"]
        with mock.patch.dict(inspect.__globals__, {
            "command": mock.Mock(side_effect=[header, dynamic, listing]),
            "identity": lambda path: {"path": path, "resolvedPath": path, "bytes": 1, "sha256": "0" * 64},
        }):
            return inspect("/w/prog")

    def test_rejects_unexpected_interpreter_and_search_paths(self):
        with self.assertRaisesRegex(ValueError, "unexpected ELF interpreter"):
            self.inspect("[Requesting program interpreter: /w/loader]", "", "")
        for tag in ("RPATH", "RUNPATH"):
            with self.assertRaisesRegex(ValueError, "search path is not admitted"):
                self.inspect("", f"({tag}) Library runpath: [/w]", "")

    def test_rejects_unresolved_or_missing_needed_libraries(self):
        header = "[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]"
        needed = "(NEEDED) Shared library: [libc.so.6]"
        with self.assertRaisesRegex(ValueError, "unsupported loader entry"):
            self.inspect(header, needed, "libc.so.6 => not found")
        with self.assertRaisesRegex(ValueError, "incomplete dependency closure"):
            self.inspect(header, needed, "/lib64/ld-linux-x86-64.so.2 (0x1234)")

    def test_rejects_library_resolving_into_workspace(self):
        inspect = PROBE["inspect"]
        with mock.patch.dict(inspect.__globals__, {
            "command": mock.Mock(side_effect=[
                "[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]",
                "(NEEDED) Shared library: [libc.so.6]",
                "libc.so.6 => /lib/libc.so.6 (0x1234)",
            ]),
            "identity": lambda path: {"path": path, "resolvedPath": "/w/injected", "bytes": 1, "sha256": "0" * 64},
        }):
            with self.assertRaisesRegex(ValueError, "leaves the immutable image roots"):
                inspect("/w/prog")


class GuardedProgramTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / "build/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)

    def run_guard(self, target, closure):
        execute = CAPTURE["execute_reference_program"]
        # Exercise the actual guard protocol; the small test programs below are trusted fixtures.
        def local_guard(runtime, workspace, arguments, stdin, *, workspace_read_only):
            self.assertTrue(workspace_read_only)
            return subprocess.run(arguments, input=stdin, capture_output=True, timeout=10)
        with mock.patch.dict(execute.__globals__, {"run_container": local_guard}):
            return execute("test-runtime", self.workspace, str(target), closure)

    def closure(self, target):
        data = target.read_bytes()
        return {"elf": {"path": str(target), "resolvedPath": str(target.resolve()),
                        "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()},
                "interpreter": None, "libraries": []}

    def test_changed_executable_is_guard_failure_not_program_observation(self):
        marker = self.workspace / "started"
        target = self.workspace / "program"
        target.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        target.chmod(0o755)
        closure = self.closure(target)
        target.write_text(target.read_text() + "exit 7\n")
        with self.assertRaisesRegex(SystemExit, "guard or launcher failed.*runtime input changed"):
            self.run_guard(target, closure)
        self.assertFalse(marker.exists())

    def test_nonzero_program_exit_and_raw_streams_remain_observations(self):
        target = self.workspace / "program"
        target.write_text("#!/usr/bin/python3\nimport os\nos.write(1,b'out\\x00\\xff')\nos.write(2,b'err\\x00\\xfe')\nraise SystemExit(7)\n")
        target.chmod(0o755)
        result = self.run_guard(target, self.closure(target))
        self.assertEqual((result.returncode, result.stdout, result.stderr), (7, b"out\x00\xff", b"err\x00\xfe"))

    def test_changed_library_prevents_program_start(self):
        marker = self.workspace / "started"
        target = self.workspace / "program"
        target.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        target.chmod(0o755)
        library = self.workspace / "library"
        library.write_bytes(b"original runtime bytes")
        closure = self.closure(target)
        closure["libraries"] = [self.closure(library)["elf"]]
        library.write_bytes(b"replaced runtime bytes")
        with self.assertRaisesRegex(SystemExit, "runtime input changed"):
            self.run_guard(target, closure)
        self.assertFalse(marker.exists())

    def test_program_does_not_inherit_launcher_environment(self):
        target = self.workspace / "program"
        target.write_text('#!/bin/sh\nprintf "%s" "$UNDECLARED_GCC_TEST_VALUE"\n')
        target.chmod(0o755)
        with mock.patch.dict(os.environ, {"UNDECLARED_GCC_TEST_VALUE": "must-not-reach-child"}):
            result = self.run_guard(target, self.closure(target))
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))

    def test_target_must_match_measured_executable(self):
        target = self.workspace / "program"
        target.write_bytes(b"not executed")
        closure = self.closure(target)
        with self.assertRaisesRegex(SystemExit, "does not match measured executable"):
            self.run_guard(self.workspace / "different", closure)


if __name__ == "__main__":
    unittest.main()
