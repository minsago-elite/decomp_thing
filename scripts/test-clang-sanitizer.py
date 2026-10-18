#!/usr/bin/env python3
"""Authored fake command controls; no compiler, JVM or native fixture runs."""

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
LAUNCHER = REPOSITORY / "scripts/run-clang-sanitizer.py"
SPEC = importlib.util.spec_from_file_location("clang_sanitizer_control", LAUNCHER)
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


class ExecRequested(BaseException):
    pass


class SanitizerLimitSetup(unittest.TestCase):
    def test_limits_and_default_signal_precede_the_exact_timeout_and_fixture(self):
        events = []
        def execute(command, arguments):
            events.append(("exec", command, arguments))
            raise ExecRequested
        with patch.object(launcher.resource, "getrlimit", return_value=(-1, -1)), \
                patch.object(launcher.resource, "setrlimit", side_effect=lambda *a: events.append(("limit", *a))), \
                patch.object(launcher.signal, "signal", side_effect=lambda *a: events.append(("signal", *a))), \
                patch.object(launcher.os, "execvp", side_effect=execute):
            with self.assertRaises(ExecRequested): launcher.main(["/authored/fixture"])
        self.assertEqual([
            ("limit", launcher.resource.RLIMIT_FSIZE, (1048577, 1048577)),
            ("limit", launcher.resource.RLIMIT_CORE, (0, 0)),
            ("signal", launcher.signal.SIGXFSZ, launcher.signal.SIG_DFL),
            ("exec", "timeout", ["timeout", "--signal=TERM", "--kill-after=1s", "10s", "/authored/fixture"]),
        ], events)

    def test_a_smaller_inherited_soft_or_hard_limit_refuses_without_raising_it(self):
        for limits in ((0, 0), (1024, -1), (1048576, 1048576), (-1, 1048576)):
            with self.subTest(limits=limits), \
                    patch.object(launcher.resource, "getrlimit", return_value=limits), \
                    patch.object(launcher.resource, "setrlimit") as setting, \
                    patch.object(launcher.os, "execvp") as execute, patch.object(launcher.os, "write"):
                self.assertEqual(125, launcher.main(["/authored/fixture"]))
                setting.assert_not_called(); execute.assert_not_called()

    def test_setup_errors_stop_before_exec_without_private_error_text(self):
        for failure_at in ("file-limit", "core-limit", "signal"):
            def setting(kind, value):
                if kind == (launcher.resource.RLIMIT_FSIZE if failure_at == "file-limit" else launcher.resource.RLIMIT_CORE):
                    if failure_at != "signal": raise OSError("PRIVATE setup path")
            with self.subTest(stage=failure_at), \
                    patch.object(launcher.resource, "getrlimit", return_value=(-1, -1)), \
                    patch.object(launcher.resource, "setrlimit", side_effect=setting), \
                    patch.object(launcher.signal, "signal", side_effect=ValueError("PRIVATE signal") if failure_at == "signal" else None), \
                    patch.object(launcher.os, "execvp") as execute, patch.object(launcher.os, "write") as writing:
                self.assertEqual(125, launcher.main(["/authored/fixture"]))
                execute.assert_not_called()
                self.assertEqual((2, b"Clang sanitizer bounds could not be established\n"), writing.call_args.args)

    def test_exec_error_and_unwritable_failure_diagnostic_keep_status_125(self):
        with patch.object(launcher.resource, "getrlimit", return_value=(-1, -1)), \
                patch.object(launcher.resource, "setrlimit"), patch.object(launcher.signal, "signal"), \
                patch.object(launcher.os, "execvp", side_effect=OSError("PRIVATE executable")), \
                patch.object(launcher.os, "write", side_effect=OSError("no diagnostic budget")):
            self.assertEqual(125, launcher.main(["/authored/fixture"]))

    def test_missing_extra_relative_and_nul_arguments_refuse_before_resource_work(self):
        for arguments in ([], ["/one", "/two"], ["relative"], ["/nul\0path"]):
            with self.subTest(arguments=arguments), patch.object(launcher.resource, "getrlimit") as limits, \
                    patch.object(launcher.os, "execvp") as execute, patch.object(launcher.os, "write"):
                self.assertEqual(125, launcher.main(arguments))
                limits.assert_not_called(); execute.assert_not_called()


class ExistingClangLane(unittest.TestCase):
    def setUp(self):
        (REPOSITORY / "build").mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="clang-sanitizer-controls-", dir=REPOSITORY / "build")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "scripts").mkdir()
        fixture_dir = self.root / "benchmarks/fixtures/c-vul/src"
        fixture_dir.mkdir(parents=True)
        for name in ("01_out_of_bounds_write.c", "05_format_string.c", "07_null_pointer_deref.c", "08_uninitialized_memory.c"):
            (fixture_dir / name).write_text("authored compiler-stub input; never compiled\n")
        # The entire real lane, including checks and cleanup, is copied unchanged.
        self.script = self.root / "scripts/validate-clang.sh"
        self.script.write_bytes((REPOSITORY / "scripts/validate-clang.sh").read_bytes())
        helper = LAUNCHER.read_text()
        self.assertEqual(1, helper.count('WALL_LIMIT = "10s"'))
        self.assertEqual(1, helper.count('KILL_GRACE = "1s"'))
        # Only the authored fake-command durations change. Real bounds/exec code remains.
        (self.root / "scripts/run-clang-sanitizer.py").write_text(
            helper.replace('WALL_LIMIT = "10s"', 'WALL_LIMIT = "0.25s"')
                  .replace('KILL_GRACE = "1s"', 'KILL_GRACE = "0.25s"'))
        fake_compiler = self.root / "fake-clang"
        fake_compiler.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root=Path(os.environ["CLANG_CONTROL_ROOT"])
with (root/"compiler-calls.jsonl").open("a") as out:out.write(json.dumps(sys.argv[1:])+"\\n")
if sys.argv[1:]==["--version"]:
 print("AUTHORED FAKE compiler; no compiler executes");sys.exit(0)
if any(a.endswith("05_format_string.c") for a in sys.argv):
 print("format string is not a string literal",file=sys.stderr);sys.exit(1)
if any(a.endswith("08_uninitialized_memory.c") for a in sys.argv):
 print("used uninitialized",file=sys.stderr);sys.exit(1)
target=Path(sys.argv[sys.argv.index("-o")+1])
target.write_bytes((root/"fake-fixture-template.py").read_bytes());target.chmod(0o700)
''')
        fake_compiler.chmod(0o700)
        (self.root / "gradlew").write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
Path(os.environ["CLANG_CONTROL_ROOT"],"gradle-call.json").write_text(json.dumps({"argv":sys.argv[1:],"compiler":os.environ.get("DECOMP_TEST_CLANG"),"required":os.environ.get("DECOMP_REQUIRE_CLANG_TESTS")}))
''')
        (self.root / "gradlew").chmod(0o700)
        (self.root / "fake-fixture-template.py").write_text('''#!/usr/bin/env python3
import json,os,resource,signal,sys,time
from pathlib import Path
root=Path(os.environ["CLANG_CONTROL_ROOT"]); name=Path(sys.argv[0]).name
mode=os.environ["CLANG_CONTROL_MODE"] if name==os.environ["CLANG_CONTROL_FIXTURE"] else "expected"
diagnostic=b"ERROR: AddressSanitizer: stack-buffer-overflow\\n" if name=="out-of-bounds" else b"runtime error: member access within null pointer\\n"
def record():
 row={"name":name,"path":sys.argv[0],"fileLimit":resource.getrlimit(resource.RLIMIT_FSIZE),"coreLimit":resource.getrlimit(resource.RLIMIT_CORE),"asan":os.environ.get("ASAN_OPTIONS"),"ubsan":os.environ.get("UBSAN_OPTIONS"),"stdoutBytes":os.fstat(1).st_size,"stderrBytes":os.fstat(2).st_size}
 with (root/"fixture-calls.jsonl").open("a") as out:out.write(json.dumps(row)+"\\n")
if mode!="missing-diagnostic":os.write(2,diagnostic)
if mode=="hang":
 signal.signal(signal.SIGTERM,signal.SIG_IGN);record();time.sleep(60)
if mode=="file-signal":
 record();signal.signal(signal.SIGXFSZ,signal.SIG_DFL);os.kill(os.getpid(),signal.SIGXFSZ)
if mode.startswith("status-"):record();sys.exit(int(mode.split("-")[1]))
if mode in ("stdout-overflow","stderr-overflow","exact-limit"):
 streams=(1,2) if mode=="exact-limit" else (1,) if mode=="stdout-overflow" else (2,)
 for fd in streams:
  wanted=1048576 if mode=="exact-limit" else 1048577
  remaining=wanted-os.fstat(fd).st_size
  while remaining:
   block=b"X"*min(65536,remaining);written=os.write(fd,block);remaining-=written
  if mode!="exact-limit":
   try:os.write(fd,b"overflow must not extend the capped file")
   except OSError:pass
record()
sys.exit(0 if mode=="unexpected-success" else 1)
''')

    def run_case(self, mode="expected", fixture="out-of-bounds"):
        for name in ("fixture-calls.jsonl", "compiler-calls.jsonl", "gradle-call.json"):
            (self.root / name).unlink(missing_ok=True)
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(self.root),
                       "DECOMP_TEST_CLANG": str(self.root / "fake-clang"),
                       "CLANG_CONTROL_ROOT": str(self.root), "CLANG_CONTROL_MODE": mode,
                       "CLANG_CONTROL_FIXTURE": fixture}
        began = time.monotonic()
        result = subprocess.run(["bash", str(self.script)], cwd=self.root, env=environment,
                                capture_output=True, text=True, timeout=8)
        self.assertLess(time.monotonic() - began, 8)
        path = self.root / "fixture-calls.jsonl"
        calls = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        self.assertEqual([], list((self.root / "build").glob("decomp-clang-ci.*")))
        self.assertLess(len(result.stdout.encode()) + len(result.stderr.encode()), 16384)
        return result, calls

    def test_existing_lane_preserves_flags_options_diagnostics_and_required_gradle_selection(self):
        result, calls = self.run_case()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(["out-of-bounds", "null-dereference"], [c["name"] for c in calls])
        for c in calls:
            self.assertEqual([1048577, 1048577], c["fileLimit"])
            self.assertEqual([0, 0], c["coreLimit"])
            self.assertEqual("detect_leaks=0:halt_on_error=1", c["asan"])
            self.assertEqual("halt_on_error=1", c["ubsan"])
            self.assertEqual(self.root / "build", Path(c["path"]).parent.parent)
        compiler = [json.loads(line) for line in (self.root / "compiler-calls.jsonl").read_text().splitlines()]
        sanitized = [c for c in compiler if "-fsanitize=address,undefined" in c]
        self.assertEqual(2, len(sanitized))
        self.assertTrue(all(c[:5] == ["-std=c11", "-O1", "-g", "-fno-omit-frame-pointer", "-fsanitize=address,undefined"] for c in sanitized))
        gradle = json.loads((self.root / "gradle-call.json").read_text())
        self.assertEqual(["--no-daemon", "test", "--tests", "decompengine.project.ClangGeneratedProjectTest", "--tests", "decompengine.oracle.fulltree.FullTreeSourceEntityIdentityProducerTest"], gradle["argv"])
        self.assertEqual("1", gradle["required"])
        self.assertEqual(str(self.root / "fake-clang"), gradle["compiler"])

    def test_success_exit_cannot_pass_even_after_an_expected_diagnostic(self):
        for fixture in ("out-of-bounds", "null-dereference"):
            with self.subTest(fixture=fixture):
                result, _ = self.run_case("unexpected-success", fixture)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("did not reject", result.stderr)
                self.assertFalse((self.root / "gradle-call.json").exists())

    def test_nonzero_without_the_original_diagnostic_still_fails(self):
        for fixture in ("out-of-bounds", "null-dereference"):
            with self.subTest(fixture=fixture):
                result, _ = self.run_case("missing-diagnostic", fixture)
                self.assertNotEqual(0, result.returncode)
                self.assertFalse((self.root / "gradle-call.json").exists())

    def test_hung_fake_fixture_cannot_pass_from_an_already_printed_diagnostic(self):
        for fixture in ("out-of-bounds", "null-dereference"):
            with self.subTest(fixture=fixture):
                result, _ = self.run_case("hang", fixture)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("invocation incomplete", result.stderr)
                self.assertFalse((self.root / "gradle-call.json").exists())

    def test_either_stream_overflow_is_capped_and_refused_before_matching(self):
        for fixture in ("out-of-bounds", "null-dereference"):
            for mode, key in (("stdout-overflow", "stdoutBytes"), ("stderr-overflow", "stderrBytes")):
                with self.subTest(fixture=fixture, stream=mode):
                    result, calls = self.run_case(mode, fixture)
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("exceeded 1 MiB", result.stderr)
                    self.assertEqual(1048577, calls[-1][key])
                    self.assertTrue(all(c[k] <= 1048577 for c in calls for k in ("stdoutBytes", "stderrBytes")))
                    self.assertFalse((self.root / "gradle-call.json").exists())

    def test_exact_one_mib_per_stream_remains_accepted(self):
        for fixture in ("out-of-bounds", "null-dereference"):
            with self.subTest(fixture=fixture):
                result, calls = self.run_case("exact-limit", fixture)
                self.assertEqual(0, result.returncode, result.stderr)
                selected = next(c for c in calls if c["name"] == fixture)
                self.assertEqual((1048576, 1048576), (selected["stdoutBytes"], selected["stderrBytes"]))

    def test_file_limit_signal_is_not_expected_sanitizer_rejection(self):
        result, _ = self.run_case("file-signal")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("invocation incomplete", result.stderr)
        self.assertFalse((self.root / "gradle-call.json").exists())

    def test_reserved_timeout_setup_and_invocation_statuses_never_grant_diagnostic_credit(self):
        for status in (124, 125, 126, 127, 137, 153):
            with self.subTest(status=status):
                result, _ = self.run_case("status-" + str(status))
                self.assertNotEqual(0, result.returncode)
                self.assertIn("invocation incomplete", result.stderr)
                self.assertFalse((self.root / "gradle-call.json").exists())


if __name__ == "__main__":
    unittest.main()
