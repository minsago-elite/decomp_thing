"""Exercise the actual workflow selector and qualification shell without a JVM launch."""

from __future__ import annotations

import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/gcc-cc1-full-export.yml"
SCRIPT = ROOT / "scripts/ci-qualify-gcc-cc1-full-export.sh"
NATIVE_TEST = (
    "decompengine.oracle.gcc.GccProductionFullExportQualificationTest."
    "live selected GCC native call observations retain profile-bound capture evidence"
)


class GccLiveCaptureSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        parent = ROOT / "build/test-tmp/gcc-live-capture-selection"
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def select(self, mode: str, labels: object) -> tuple[subprocess.CompletedProcess[str], dict | None]:
        # Run the source embedded in the workflow, rather than a copy of its routing logic.
        source = WORKFLOW.read_text().split("        shell: python\n        run: |\n", 1)[1]
        source = textwrap.dedent(source.split("\n  cc1-live-full-export:", 1)[0])
        output = self.directory / "workflow-output"
        output.unlink(missing_ok=True)
        process = subprocess.run(
            [sys.executable, "-c", source],
            env={**os.environ, "CAPTURE_MODE": mode, "PR_LABELS": json.dumps(labels), "GITHUB_OUTPUT": str(output)},
            capture_output=True,
            text=True,
            check=False,
        )
        result = json.loads(output.read_text().removeprefix("matrix=")) if output.exists() else None
        return process, result

    def test_every_nonempty_label_combination_keeps_independent_capture_lanes(self) -> None:
        choices = (
            ("qualify:cc1-full-export", "cc1", "qualification", "compiler-engines-exporter17-parallel.json"),
            ("qualify:driver-full-export", "driver", "qualification", "compiler-engines-exporter17.json"),
            ("qualify:driver-native-calls", "driver", "driver-native-calls", "compiler-engines-exporter17.json"),
        )
        for enabled in itertools.product((False, True), repeat=3):
            if not any(enabled):
                continue
            selected = [choice for choice, include in zip(choices, enabled) if include]
            with self.subTest(labels=[choice[0] for choice in selected]):
                process, matrix = self.select("", [choice[0] for choice in selected] + ["unrelated-label"])
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertEqual(matrix, {"include": [
                    {"target": target, "capture_mode": mode, "profile": profile}
                    for _, target, mode, profile in selected
                ]})

    def test_manual_modes_preserve_target_and_serial_or_parallel_profile(self) -> None:
        cases = (
            ("cc1-full-export", "cc1", "qualification", "compiler-engines-exporter17-parallel.json"),
            ("cc1-runtime-diagnostics", "cc1", "cc1-runtime-diagnostics", "compiler-engines-exporter17.json"),
            ("cc1-native-calls", "cc1", "cc1-native-calls", "compiler-engines-exporter17.json"),
            ("cc1-engine-cli", "cc1", "cc1-engine-cli", "compiler-engines-exporter17.json"),
            ("driver-native-calls", "driver", "driver-native-calls", "compiler-engines-exporter17.json"),
        )
        for mode, target, capture, profile in cases:
            with self.subTest(mode=mode):
                process, matrix = self.select(mode, ["qualify:driver-full-export"])
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertEqual(matrix, {"include": [{"target": target, "capture_mode": capture, "profile": profile}]})

    def test_unsupported_selections_fail_without_matrix_output(self) -> None:
        for mode, labels in (("unknown", []), ("", []), ("", ["qualify:driver-native-calls-extra"]),
                             ("", {"qualify:driver-native-calls": True})):
            with self.subTest(mode=mode, labels=labels):
                process, matrix = self.select(mode, labels)
                self.assertNotEqual(process.returncode, 0)
                self.assertIsNone(matrix)

    def test_native_label_is_recognized_by_event_and_concurrency_guards(self) -> None:
        workflow = WORKFLOW.read_text()
        concurrency = workflow.split("concurrency:\n", 1)[1].split("\njobs:", 1)[0]
        guard = workflow.split("  select-captures:\n", 1)[1].split("    runs-on:", 1)[0]
        self.assertIn('"qualify:driver-native-calls"', concurrency)
        self.assertIn('"qualify:driver-native-calls"', guard)
        self.assertIn("contains(github.event.pull_request.labels.*.name, 'qualify:driver-native-calls')", guard)
        self.assertIn("matrix: ${{ fromJSON(needs.select-captures.outputs.matrix) }}", workflow)
        self.assertIn("DECOMP_GCC_CLI_CAPTURE_MODE: ${{ matrix.capture_mode }}", workflow)
        self.assertIn("/oracle/gcc/16.2.0/${{ matrix.profile }}", workflow)

    def invoke(self, mode: str, engine: str, extra: tuple[str, ...] = ()) -> tuple[subprocess.CompletedProcess[str], dict | None]:
        project = self.directory / "project"
        (project / "scripts").mkdir(parents=True, exist_ok=True)
        copied = project / "scripts" / SCRIPT.name
        shutil.copyfile(SCRIPT, copied)
        output = project / "invocation.json"
        output.unlink(missing_ok=True)
        launcher = project / "gradlew"
        launcher.write_text(
            "#!" + sys.executable + "\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "Path(os.environ['FAKE_GRADLE_OUTPUT']).write_text(json.dumps({"
            "'arguments':sys.argv[1:],'environment':{key:os.environ[key] for key in "
            "('DECOMP_REQUIRE_GCC_CLI_FULL_EXPORT','DECOMP_REQUIRE_GCC_RUNTIME_DIAGNOSTICS',"
            "'DECOMP_REQUIRE_GCC_NATIVE_CALLS','DECOMP_GCC_CLI_FULL_EXPORT_ENGINE','RUN_REAL_GHIDRA') "
            "if key in os.environ}}))\n"
        )
        launcher.chmod(0o700)
        env = {**os.environ, "FAKE_GRADLE_OUTPUT": str(output), "DECOMP_GCC_CLI_FULL_EXPORT_ENGINE": engine}
        for name in ("INSTALLATION", "PROFILE", "ARCHIVE", "EXPORT_BINARY", "EXPORT_SCRATCH", "EVIDENCE_ROOT"):
            env["DECOMP_GCC_CLI_" + name] = str(project / name.lower())
        # The script must clear stale requirements before selecting exactly one test mode.
        for name in ("FULL_EXPORT", "RUNTIME_DIAGNOSTICS", "NATIVE_CALLS"):
            env["DECOMP_REQUIRE_GCC_" + ("CLI_" if name == "FULL_EXPORT" else "") + name] = "stale"
        process = subprocess.run(["bash", str(copied), mode, *extra], env=env, capture_output=True, text=True, check=False)
        return process, json.loads(output.read_text()) if output.exists() else None

    def test_both_native_modes_select_the_profile_bound_native_test(self) -> None:
        for mode, engine in (("cc1-native-calls", "cc1"), ("driver-native-calls", "driver")):
            with self.subTest(mode=mode):
                process, invocation = self.invoke(mode, engine)
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertIsNotNone(invocation)
                arguments = invocation["arguments"]
                self.assertEqual(arguments[arguments.index("--tests") + 1], NATIVE_TEST)
                env = invocation["environment"]
                self.assertEqual(env["DECOMP_REQUIRE_GCC_NATIVE_CALLS"], "true")
                self.assertEqual(env["DECOMP_GCC_CLI_FULL_EXPORT_ENGINE"], engine)
                self.assertEqual(env["RUN_REAL_GHIDRA"], "true")
                self.assertNotIn("DECOMP_REQUIRE_GCC_CLI_FULL_EXPORT", env)
                self.assertNotIn("DECOMP_REQUIRE_GCC_RUNTIME_DIAGNOSTICS", env)

    def test_existing_full_export_and_diagnostic_modes_keep_their_test_selection(self) -> None:
        for mode, engine, requirement, suffix in (
            ("qualification", "cc1", "DECOMP_REQUIRE_GCC_CLI_FULL_EXPORT", "live selected GCC full export retains its profile-bound model and receipt evidence"),
            ("qualification", "driver", "DECOMP_REQUIRE_GCC_CLI_FULL_EXPORT", "live selected GCC full export retains its profile-bound model and receipt evidence"),
            ("cc1-runtime-diagnostics", "cc1", "DECOMP_REQUIRE_GCC_RUNTIME_DIAGNOSTICS", "live cc1 runtime diagnostics retain bounded logs and available operation evidence"),
        ):
            with self.subTest(mode=mode, engine=engine):
                process, invocation = self.invoke(mode, engine)
                self.assertEqual(process.returncode, 0, process.stderr)
                arguments = invocation["arguments"]
                self.assertEqual(arguments[arguments.index("--tests") + 1].split("QualificationTest.", 1)[1], suffix)
                self.assertEqual(invocation["environment"][requirement], "true")
                self.assertNotIn("DECOMP_REQUIRE_GCC_NATIVE_CALLS", invocation["environment"])

    def test_wrong_engine_unknown_mode_and_extra_arguments_never_launch(self) -> None:
        for mode, engine, extra in (
            ("driver-native-calls", "cc1", ()), ("cc1-native-calls", "driver", ()),
            ("cc1-runtime-diagnostics", "driver", ()), ("qualification", "other", ()),
            ("unknown", "driver", ()), ("driver-native-calls", "driver", ("extra",)),
        ):
            with self.subTest(mode=mode, engine=engine, extra=extra):
                process, invocation = self.invoke(mode, engine, extra)
                self.assertEqual(process.returncode, 64)
                self.assertIsNone(invocation)


if __name__ == "__main__":
    unittest.main()
