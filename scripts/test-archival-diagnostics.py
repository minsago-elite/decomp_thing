#!/usr/bin/env python3
"""Owned data and fake Docker commands; never builds or runs a container."""

import errno
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


REPOSITORY = Path(__file__).resolve().parent.parent
SOURCE = REPOSITORY / "scripts/collect-archival-diagnostics.py"
SPEC = importlib.util.spec_from_file_location("archival_diagnostics_controls", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Unable to load archival diagnostic collector controls")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class DiagnosticCollector(unittest.TestCase):
    def setUp(self):
        collector.BUILD.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="decomp-archival-ci.", dir=collector.BUILD)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "output"
        self.output.mkdir()
        metadata = self.root.stat()
        self.identity = (metadata.st_dev, metadata.st_ino)

    def file(self, name="symbols-a/reports/build.log", data=b"authored inside evidence\n"):
        path = self.output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def collect(self, identity=None, **kwargs):
        records = []
        status = collector.collect(self.root, identity or self.identity, records.append, **kwargs)
        raw = "".join(records)
        self.assertTrue(raw.isascii())
        self.assertLessEqual(len(raw), collector.MAX_OUTPUT_BYTES)
        decoded = [json.loads(line) for line in records]
        self.assertEqual("summary", decoded[-1]["kind"])
        self.assertEqual(status == 0, decoded[-1]["status"] == "passed")
        return status, raw, decoded

    def test_actual_collector_selects_build_module_ghidra_and_main_evidence_with_owner_facts(self):
        self.file()
        self.file("symbols-a/reports/build/modules/deep/unit.log", b"module diagnostic\n")
        self.file("symbols-a/reports/ghidra_stdout.log", b"Ghidra stdout diagnostic\n")
        self.file("symbols-a/reports/ghidra_stderr.log", b"Ghidra stderr diagnostic\n")
        self.file("symbols-a/reports/ghidra_resource_usage.json", b'{"remainingWallClockNanosAtLaunch":123}')
        self.file("symbols-a/src/main.c", b"int main(void) { return 0; }\n")
        self.file("symbols-a/private-not-selected.txt", b"NOT-DIAGNOSTIC")
        status, raw, rows = self.collect()
        self.assertEqual(0, status)
        files = [row for row in rows if row["kind"] == "file"]
        self.assertEqual(6, len(files))
        self.assertTrue(all(set(("uid", "gid", "mode", "size")) <= row.keys() for row in files))
        self.assertIn("Ghidra stdout diagnostic", raw)
        self.assertIn("Ghidra stderr diagnostic", raw)
        self.assertNotIn("NOT-DIAGNOSTIC", raw)

    def test_ghidra_log_retains_bounded_final_cleanup_evidence(self):
        data = (b"x" * 600 + b"\n") * 64 + b"cleanup owner state\n"
        self.file("symbols-a/analysis/reports/ghidra_stdout.log", data)
        status, raw, rows = self.collect()
        self.assertEqual(0, status)
        report = next(row for row in rows if row.get("kind") == "file")
        self.assertEqual(len(data), report["size"])
        self.assertFalse(report["truncated"])
        self.assertIn("cleanup owner state", raw)

    def test_newline_absolute_operand_counterexample_stays_inside_retained_directories(self):
        outside = tempfile.TemporaryDirectory(prefix="archival-external-control-", dir=collector.BUILD)
        self.addCleanup(outside.cleanup)
        secret = Path(outside.name) / "reports/build.log"
        secret.parent.mkdir()
        secret.write_bytes(b"EXTERNAL-CONTROL-MUST-NOT-BE-READ")
        # The old find/read loop split this pathname into an absolute sed operand.
        self.file("prefix\n/" + secret.as_posix().lstrip("/"), b"OWNED-NEWLINE-EVIDENCE")
        status, raw, _ = self.collect()
        self.assertEqual(0, status)
        self.assertIn("OWNED-NEWLINE-EVIDENCE", raw)
        self.assertNotIn("EXTERNAL-CONTROL-MUST-NOT-BE-READ", raw)

    def test_linked_selected_file_and_hardlink_alias_refuse_without_payload_reads(self):
        target = self.file("unselected-original", b"DO-NOT-READ-ALIASED-PAYLOAD")
        log = self.output / "symbols-a/reports/build.log"
        log.parent.mkdir(parents=True)
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                if kind == "symlink": log.symlink_to(target)
                else: os.link(target, log)
                with patch.object(collector.os, "read", side_effect=AssertionError("aliased payload open")):
                    status, raw, _ = self.collect()
                self.assertEqual(2, status)
                self.assertNotIn("DO-NOT-READ-ALIASED-PAYLOAD", raw)
                log.unlink()

    def test_special_selected_fifo_refuses_before_open_or_read(self):
        log = self.output / "symbols-a/reports/build.log"
        log.parent.mkdir(parents=True)
        os.mkfifo(log)
        with patch.object(collector.os, "read", side_effect=AssertionError("FIFO payload read")):
            status, _, rows = self.collect()
        self.assertEqual(2, status)
        self.assertTrue(any(row.get("reason") == "diagnostic-not-unaliased-regular" for row in rows))

    def test_missing_and_unreadable_evidence_are_explicit_incomplete_results(self):
        status, _, rows = self.collect()
        self.assertEqual(2, status)
        self.assertTrue(any(row.get("reason") == "diagnostic-files-missing" for row in rows))
        self.file()
        original_open = os.open
        def opening(name, *args, **kwargs):
            if name == "build.log": raise PermissionError(errno.EACCES, "PRIVATE unreadable /outside")
            return original_open(name, *args, **kwargs)
        with patch.object(collector.os, "open", side_effect=opening):
            status, raw, rows = self.collect()
        self.assertEqual(2, status)
        self.assertNotIn("PRIVATE", raw)
        self.assertTrue(any(row.get("errno") == errno.EACCES for row in rows))

    def test_replacement_during_actual_read_withholds_changed_excerpt(self):
        target = self.file(data=b"CHANGED-ENTRY-MUST-NOT-BE-PRINTED")
        native_read = os.read
        mutated = False
        def reading(descriptor, count):
            nonlocal mutated
            raw = native_read(descriptor, count)
            if not mutated:
                mutated = True
                target.rename(target.with_name("retained-original"))
                target.write_bytes(b"replacement")
            return raw
        with patch.object(collector.os, "read", side_effect=reading):
            status, raw, _ = self.collect()
        self.assertEqual(2, status)
        self.assertNotIn("CHANGED-ENTRY-MUST-NOT-BE-PRINTED", raw)

    def test_wrong_root_identity_refuses_before_any_payload_read(self):
        self.file(data=b"WRONG-ROOT-PAYLOAD")
        with patch.object(collector.os, "read", side_effect=AssertionError("wrong-root read")):
            status, raw, _ = self.collect((self.identity[0], self.identity[1] + 1))
        self.assertEqual(2, status)
        self.assertNotIn("WRONG-ROOT-PAYLOAD", raw)

    def test_global_entry_path_and_depth_budgets_stop_before_payload_work(self):
        self.file()
        for name, value in (("MAX_ENTRIES", 2), ("MAX_PATH_BYTES", 1), ("MAX_DEPTH", 2)):
            with self.subTest(bound=name), patch.object(collector, name, value), \
                    patch.object(collector.os, "read", side_effect=AssertionError("work after inventory refusal")):
                status, _, _ = self.collect()
            self.assertEqual(2, status)

    def test_long_lines_file_prefix_and_escaped_aggregate_bytes_remain_bounded(self):
        self.file(data=("\u0001" * 3000 + "\n").encode() * 300)
        for i in range(12): self.file(f"symbols-a/reports/build/modules/{i}.log", b'"\\' * 20000)
        self.file("symbols-a/reports/build/modules/binary.log", b"\xff" * 2000)
        status, _, rows = self.collect()
        self.assertEqual(0, status)
        files = [row for row in rows if row["kind"] == "file"]
        self.assertTrue(files)
        self.assertTrue(any(row["truncated"] for row in files))
        self.assertTrue(all(len(row["lines"]) <= collector.MAX_LINES for row in files))
        self.assertTrue(all(len(line.encode("utf-8")) <= collector.MAX_LINE_BYTES for row in files for line in row["lines"]))

    def test_deadline_expiry_during_read_cannot_commit_excerpt_or_complete(self):
        self.file(data=b"LATE-EXCERPT")
        now = [0.0]
        native_read = os.read
        def reading(descriptor, count):
            result = native_read(descriptor, count)
            now[0] = collector.COLLECTION_SECONDS
            return result
        with patch.object(collector.os, "read", side_effect=reading):
            status, raw, _ = self.collect(clock=lambda: now[0])
        self.assertEqual(2, status)
        self.assertNotIn("LATE-EXCERPT", raw)

    def test_aggregate_exhaustion_is_explicit_and_stops_further_payload_opens(self):
        for i in range(30): self.file(f"symbols-a/reports/build/modules/{i:02}.log", b"x" * 2000)
        opened = []
        native_open = os.open
        def opening(name, *args, **kwargs):
            if str(name).endswith(".log"): opened.append(name)
            return native_open(name, *args, **kwargs)
        with patch.object(collector, "MAX_OUTPUT_BYTES", 4096), patch.object(collector.os, "open", side_effect=opening):
            status, _, rows = self.collect()
        self.assertEqual(2, status)
        self.assertLess(len(opened), 30)
        self.assertTrue(any(row.get("reason") == "diagnostic-byte-budget" for row in rows))

    def test_unselected_directory_link_is_not_followed_or_accepted_as_missing_evidence(self):
        outside = tempfile.TemporaryDirectory(prefix="archival-external-control-", dir=collector.BUILD)
        self.addCleanup(outside.cleanup)
        target = Path(outside.name) / "reports/build.log"
        target.parent.mkdir()
        target.write_bytes(b"OUTSIDE-LINK-TARGET")
        (self.output / "symbols-a").symlink_to(Path(outside.name), target_is_directory=True)
        with patch.object(collector.os, "read", side_effect=AssertionError("directory link followed")):
            status, raw, rows = self.collect()
        self.assertEqual(2, status)
        self.assertNotIn("OUTSIDE-LINK-TARGET", raw)
        self.assertTrue(any(row.get("kind") == "omission" for row in rows))

    def test_cli_file_write_limit_never_raises_an_existing_limit_and_disables_cores(self):
        infinity = collector.resource.RLIM_INFINITY
        for limits, ceiling in (((1024, 2048), 1024), ((infinity, infinity), collector.MAX_OUTPUT_BYTES), ((4096, 4096), 4096)):
            with self.subTest(limits=limits), patch.object(sys, "argv", [str(SOURCE), str(self.root), *map(str, self.identity), "--check-root"]), \
                    patch.object(collector.resource, "getrlimit", return_value=limits), \
                    patch.object(collector.resource, "setrlimit") as setting:
                self.assertEqual(0, collector.main())
            self.assertEqual((collector.resource.RLIMIT_FSIZE, (ceiling, ceiling)), setting.call_args_list[0].args)
            self.assertEqual((collector.resource.RLIMIT_CORE, (0, 0)), setting.call_args_list[1].args)


class ArchivalCleanupShell(unittest.TestCase):
    def setUp(self):
        (REPOSITORY / "build").mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="archival-cleanup-controls-", dir=REPOSITORY / "build")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "scripts").mkdir()
        (self.root / "build").mkdir()
        (self.root / "bin").mkdir()
        (self.root / "scripts/collect-archival-diagnostics.py").write_bytes(SOURCE.read_bytes())
        original = (REPOSITORY / "scripts/validate-archival-docker.sh").read_text()
        boundary = 'mkdir -p "$validation_root/input" "$validation_root/output"\n'
        self.assertEqual(1, original.count(boundary))
        prefix = original.split(boundary)[0]
        self.assertEqual(1, prefix.count("10s docker run"))
        self.assertEqual(1, prefix.count("20s rm -rf"))
        # Same actual trap/commands; shorten only fake-command deadlines, not admission or collection.
        self.prefix = prefix.replace("10s docker run", "0.25s docker run").replace("20s rm -rf", "0.25s rm -rf").replace("--kill-after=1s", "--kill-after=0.25s")
        fake = '''#!/usr/bin/env python3
import json, os, signal, sys, time
from pathlib import Path
root=Path(os.environ["ARCHIVAL_CONTROL_ROOT"])
name=Path(sys.argv[0]).name
with (root/"calls.jsonl").open("a") as out:out.write(json.dumps([name,*sys.argv[1:]])+"\\n")
if os.environ.get("ARCHIVAL_CONTROL_HANG")==name:
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 time.sleep(60)
if name=="rm":
 target=Path(sys.argv[-1])
 if target.parent!=root/"build" or not target.name.startswith("decomp-archival-ci."):sys.exit(99)
 os.execv("/usr/bin/rm",["rm",*sys.argv[1:]])
sys.exit(0)
'''
        for name in ("docker", "rm"):
            path = self.root / "bin" / name
            path.write_text(fake)
            path.chmod(0o700)

    def run_case(self, *, status=17, hang="", setup=""):
        script = self.root / "scripts/control.sh"
        script.write_text(self.prefix + '''
mkdir -p "$validation_root/input" "$validation_root/output/symbols-a/reports"
image_built=1  # Authored completed-build state; Docker itself is always fake here.
printf 'AUTHORED-BUILD-EVIDENCE\\n' > "$validation_root/output/symbols-a/reports/build.log"
''' + setup + f"\nexit {status}\n")
        environment = {**os.environ, "PATH": str(self.root / "bin") + os.pathsep + os.environ["PATH"],
                       "ARCHIVAL_CONTROL_ROOT": str(self.root), "ARCHIVAL_CONTROL_HANG": hang}
        began = time.monotonic()
        result = subprocess.run(["bash", str(script)], cwd=self.root, env=environment,
                                capture_output=True, text=True, timeout=8)
        self.assertLess(time.monotonic() - began, 8)
        calls = [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()] if (self.root / "calls.jsonl").exists() else []
        records = list((self.root / "build/archival-ci-diagnostics").glob("*.jsonl"))
        return result, calls, records

    def test_original_failure_is_preserved_after_retained_diagnostics_and_owned_cleanup(self):
        result, calls, records = self.run_case()
        self.assertEqual(17, result.returncode, result.stderr)
        self.assertEqual(["docker", "rm"], [call[0] for call in calls])
        self.assertEqual(1, len(records))
        self.assertIn("AUTHORED-BUILD-EVIDENCE", records[0].read_text())
        self.assertEqual([], list((self.root / "build").glob("decomp-archival-ci.*")))

    def test_hung_permission_repair_is_bounded_not_retried_and_retains_root(self):
        result, calls, records = self.run_case(hang="docker")
        self.assertEqual(17, result.returncode, result.stderr)
        self.assertEqual(["docker"], [call[0] for call in calls])
        self.assertTrue(records)
        self.assertTrue(list((self.root / "build").glob("decomp-archival-ci.*")))

    def test_incomplete_collection_retains_tree_and_original_failure(self):
        result, calls, records = self.run_case(setup='/usr/bin/rm "$validation_root/output/symbols-a/reports/build.log"\nmkfifo "$validation_root/output/symbols-a/reports/build.log"\n')
        self.assertEqual(17, result.returncode, result.stderr)
        self.assertEqual(["docker"], [call[0] for call in calls])
        self.assertIn('"status":"incomplete"', records[0].read_text())
        self.assertTrue(list((self.root / "build").glob("decomp-archival-ci.*")))

    def test_hung_removal_fails_an_otherwise_successful_validation(self):
        result, calls, records = self.run_case(status=0, hang="rm")
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual(["docker", "rm"], [call[0] for call in calls])
        self.assertIn("AUTHORED-BUILD-EVIDENCE", records[0].read_text())
        self.assertTrue(list((self.root / "build").glob("decomp-archival-ci.*")))

    def test_failed_normal_permission_call_is_not_relaunched_by_exit_cleanup(self):
        result, calls, records = self.run_case(hang="docker", setup="repair_permissions\n")
        self.assertIn(result.returncode, (124, 137), result.stderr)
        self.assertEqual(["docker"], [call[0] for call in calls])
        self.assertTrue(records)
        self.assertTrue(list((self.root / "build").glob("decomp-archival-ci.*")))

    def test_replaced_root_is_never_repaired_or_removed(self):
        result, calls, records = self.run_case(setup='mv "$validation_root" "$validation_root-moved"\nmkdir -p "$validation_root/output"\n')
        self.assertEqual(17, result.returncode, result.stderr)
        self.assertEqual([], calls)
        self.assertTrue(records)
        self.assertEqual(2, len(list((self.root / "build").glob("decomp-archival-ci.*"))))


if __name__ == "__main__":
    unittest.main()
