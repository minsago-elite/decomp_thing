"""Bounded, nonexecuting loader-plan controls for the generic bubblewrap backend."""
from __future__ import annotations

import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from oracle.behavior_corpus import BehaviorCorpusError
from oracle.behavior_corpus_bwrap_loader import (
    LoaderProbePlan,
    SUBJECT_PATH,
    elf_interpreter,
    loader_probe_plan,
    validate_probe_libraries,
)

ROOT = Path(__file__).resolve().parents[2]
BASE = ("--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv")


def elf_with_interpreter(interpreter: bytes, *, count: int = 1) -> bytes:
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, 3, 62, 1)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HHH", header, 52, 64, 56, count)
    entry = struct.pack("<IIQQQQQQ", 3, 4, 64 + 56 * count, 0, 0, len(interpreter), len(interpreter), 1)
    return bytes(header) + entry * count + interpreter


class LoaderProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / "build").mkdir(exist_ok=True)
        directory = tempfile.TemporaryDirectory(dir=ROOT / "build")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def subject(self, interpreter: bytes, *, count: int = 1) -> Path:
        path = self.root / "subject"
        path.write_bytes(elf_with_interpreter(interpreter, count=count))
        return path

    def test_subject_selected_host_program_is_rejected_without_execution(self) -> None:
        marker = self.root / "executed"
        attacker = self.root / "interpreter"
        attacker.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        attacker.chmod(0o755)
        subject = self.subject(os.fsencode(attacker) + b"\0")
        with mock.patch("subprocess.run", side_effect=AssertionError("host execution is forbidden")), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("host execution is forbidden")):
            with self.assertRaisesRegex(BehaviorCorpusError, "differs from"):
                loader_probe_plan(subject, Path("/usr/bin/bwrap"), BASE)
        self.assertFalse(marker.exists())

    def test_missing_interpreter_is_rejected_without_execution(self) -> None:
        subject = self.subject(b"/lib/does-not-exist-loader-for-test\0")
        with self.assertRaisesRegex(BehaviorCorpusError, "missing or unsupported"):
            loader_probe_plan(subject, Path("/usr/bin/bwrap"), BASE)

    def test_actual_running_host_elf_uses_only_readonly_system_probe_mounts(self) -> None:
        # /proc/self/exe is the actual running, dynamically linked Python, not an authored ELF model.
        plan = loader_probe_plan(Path("/proc/self/exe"), Path("/usr/bin/bwrap"), BASE)
        self.assertEqual(plan.command[-3:], (elf_interpreter(Path("/proc/self/exe")), "--list", SUBJECT_PATH))
        self.assertEqual(plan.command[1:1 + len(BASE)], BASE)
        self.assertNotIn("--bind", plan.command)
        self.assertNotIn("--proc", plan.command)
        self.assertNotIn("--dev", plan.command)
        self.assertNotIn("--tmpfs", plan.command)
        self.assertNotIn("--share-net", plan.command)
        self.assertNotIn("/home", plan.command)
        self.assertNotIn("/work", plan.command)
        self.assertIn("--remount-ro", plan.command)
        self.assertEqual(plan.command[plan.command.index("--chdir") + 1], "/")
        self.assertEqual(validate_probe_libraries(plan, [], 1), [plan.interpreter])

    def test_resolved_output_cannot_select_nonlibrary_host_files(self) -> None:
        plan = loader_probe_plan(Path("/proc/self/exe"), Path("/usr/bin/bwrap"), BASE)
        unrelated = self.root / "private-file"
        unrelated.write_text("must not be returned for host snapshotting")
        with self.assertRaisesRegex(BehaviorCorpusError, "outside"):
            validate_probe_libraries(plan, [str(unrelated)], 64)

    def test_library_symlink_cannot_escape_the_bound_root(self) -> None:
        library_root = self.root / "lib"
        library_root.mkdir()
        outside = self.root / "outside"
        outside.write_text("outside")
        link = library_root / "escape.so"
        link.symlink_to(outside)
        plan = LoaderProbePlan((), str(link), (library_root,))
        with self.assertRaisesRegex(BehaviorCorpusError, "outside"):
            validate_probe_libraries(plan, [str(link)], 64)

    def test_loader_counts_against_closure_bound(self) -> None:
        library_root = self.root / "lib"
        library_root.mkdir()
        loader, dependency = library_root / "loader", library_root / "dependency"
        loader.write_bytes(b"loader")
        dependency.write_bytes(b"dependency")
        plan = LoaderProbePlan((), str(loader), (library_root,))
        with self.assertRaisesRegex(BehaviorCorpusError, "exceeds"):
            validate_probe_libraries(plan, [str(dependency)], 1)
        self.assertEqual(validate_probe_libraries(plan, [str(loader), str(loader)], 1), [str(loader)])

    def test_malformed_interpreter_records_refuse(self) -> None:
        for payload in (b"relative\0", b"/lib/../tmp/loader\0", b"/lib/loader", b"/lib/one\0two\0", b"/lib/\xff\0"):
            with self.subTest(payload=payload):
                with self.assertRaises(BehaviorCorpusError):
                    elf_interpreter(self.subject(payload))

    def test_duplicate_and_oversized_interpreter_tables_refuse(self) -> None:
        for count in (0, 2, 65):
            with self.subTest(count=count):
                with self.assertRaises(BehaviorCorpusError):
                    elf_interpreter(self.subject(b"/lib/loader\0", count=count))
        with self.assertRaisesRegex(BehaviorCorpusError, "exceeds"):
            elf_interpreter(self.subject(b"/" + b"a" * 4096 + b"\0"))

    def test_truncated_and_out_of_file_metadata_refuse(self) -> None:
        subject = self.subject(b"/lib/loader\0")
        data = bytearray(subject.read_bytes())
        struct.pack_into("<Q", data, 32, (1 << 64) - 1)
        subject.write_bytes(data)
        with self.assertRaisesRegex(BehaviorCorpusError, "table"):
            elf_interpreter(subject)
        subject.write_bytes(b"\x7fELF\x02\x01\x01")
        with self.assertRaisesRegex(BehaviorCorpusError, "ELF64"):
            elf_interpreter(subject)


if __name__ == "__main__":
    unittest.main()
