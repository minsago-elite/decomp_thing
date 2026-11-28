from __future__ import annotations

import json
import runpy
import subprocess
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CAPTURE = runpy.run_path(str(REPOSITORY_ROOT / "scripts/capture-gcc-preprocessing-reference.py"))
phase_commands = CAPTURE["phase_commands"]
run_container = CAPTURE["run_container"]
ORCHESTRATION_RECORD = REPOSITORY_ROOT / "oracle/gcc/16.2.0/orchestration-phase-reference.json"
CC1 = "/usr/local/libexec/gcc/x86_64-linux-gnu/16.2.0/cc1"


class PhaseCommandTest(unittest.TestCase):
    def test_pipeline_connector_is_not_a_phase_argument(self):
        phases = phase_commands(
            f' {CC1} -quiet source.c "-mtune=generic" -o - |\n'
            " as --64 -o source.o\n"
        )
        self.assertEqual(
            [(phase["phase"], phase["argv"][-2:], phase["stdoutPipedToNextPhase"]) for phase in phases],
            [("compile", ["-o", "-"], True), ("assemble", ["-o", "source.o"], False)],
        )

    def test_quoted_bar_argument_is_kept(self):
        [phase] = phase_commands(f' {CC1} -quiet "|"\n')
        self.assertEqual(phase["argv"][-1], "|")
        self.assertFalse(phase["stdoutPipedToNextPhase"])

    def test_closed_plan_rejects_unknown_or_malformed_commands(self):
        for command in (' /w/undeclared-tool source.c\n', f' {CC1} "unclosed\n'):
            with self.assertRaises(SystemExit):
                phase_commands(command, strict=True)

    def test_verbose_parser_preserves_non_command_diagnostics(self):
        self.assertEqual(phase_commands(' /usr/local/include\n  int invalid = ;\n'), [])

    def test_checked_in_record_has_no_pipeline_marker_in_argv(self):
        record = json.loads(ORCHESTRATION_RECORD.read_text())
        piped = set()
        for case in record["cases"]:
            for source in ("plan", "executedPhases"):
                for phase in case["observed"][source]["phases"]:
                    self.assertNotEqual(phase["argv"][-1], "|", (case["id"], source))
                    if phase["stdoutPipedToNextPhase"]:
                        piped.add((case["id"], source, phase["phase"]))
        self.assertEqual(
            piped,
            {("compile-pipe", "plan", "compile"), ("compile-pipe", "executedPhases", "compile")},
        )


class ContainerSandboxTest(unittest.TestCase):
    def test_driver_temporaries_get_a_writable_tmp_on_every_runtime(self):
        for runtime in ("docker", "podman"):
            with mock.patch("subprocess.run") as run:
                run.return_value.stdout = CAPTURE["IMAGE_CONFIG"]
                run_container(runtime, Path("/workspace"), ["gcc", "-c", "source.c"], b"")
            command = run.call_args.args[0]
            self.assertIn("--read-only", command)
            index = command.index("--tmpfs")
            self.assertEqual(command[index + 1], "/tmp")
            self.assertLess(index, command.index(CAPTURE["IMAGE"]))

    def test_image_mismatch_prevents_any_execution(self):
        result = subprocess.CompletedProcess([], 0, stdout="sha256:" + "0" * 64, stderr="")
        with mock.patch("subprocess.run", return_value=result) as run:
            with self.assertRaisesRegex(SystemExit, "does not match pinned"):
                run_container("podman", Path("/workspace"), ["gcc", "--version"], b"")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][1:3], ["image", "inspect"])

    def test_image_authentication_precedes_run_and_readonly_program_mount(self):
        with mock.patch("subprocess.run") as run:
            run.return_value.stdout = CAPTURE["IMAGE_CONFIG"]
            run_container("podman", Path("/workspace"), ["/w/prog"], b"", workspace_read_only=True)
        self.assertEqual(run.call_args_list[0].args[0][1:3], ["image", "inspect"])
        self.assertIn("/workspace:/w:ro", run.call_args_list[1].args[0])

    def test_phase_basename_does_not_admit_an_unrelated_tool_path(self):
        identities = {"compile": {"path": CC1}}
        with self.assertRaisesRegex(SystemExit, "not admitted"):
            CAPTURE["validate_phase_tools"](
                [{"tool": "/w/cc1", "phase": "compile", "argv": ["/w/cc1"]}], identities)
        CAPTURE["validate_phase_tools"]([{"tool": CC1}], identities)

    def test_records_name_driver_temporaries_only_under_tmp(self):
        text = ORCHESTRATION_RECORD.read_text()
        self.assertNotRegex(text, r"\./cc[A-Za-z0-9]{6}")
        self.assertNotRegex(text, r"/tmp/cc[A-Za-z0-9]{6}")

    def test_produced_programs_bind_loader_libc_and_exact_output(self):
        record = json.loads(ORCHESTRATION_RECORD.read_text())
        for case in record["cases"]:
            observed = case["observed"]
            if "programBehavior" not in observed:
                continue
            program = observed["programBehavior"]
            closure = program["runtime"]
            artifact = next(a for a in observed["execution"]["artifacts"] if a["path"] == program["program"])
            self.assertEqual(closure["elf"]["sha256"], artifact["sha256"])
            self.assertEqual(closure["elf"]["bytes"], artifact["bytes"])
            self.assertEqual(closure["interpreter"]["path"], "/lib64/ld-linux-x86-64.so.2")
            self.assertIn("libc.so.6", [library["name"] for library in closure["libraries"]])

    def test_complete_verbose_transcripts_are_retained(self):
        record = json.loads(ORCHESTRATION_RECORD.read_text())
        for case in record["cases"]:
            trace = case["observed"]["executedPhases"]
            self.assertEqual(trace["stderr"]["sha256"], trace["stderrSha256"])

    def test_phase_runtime_closures_bind_declared_tool_identities(self):
        toolchain = json.loads(ORCHESTRATION_RECORD.read_text())["toolchain"]
        for identity in [toolchain["driver"], *toolchain["phaseTools"].values()]:
            self.assertEqual(toolchain["runtimeClosure"][identity["path"]]["elf"]["sha256"], identity["sha256"])


def completed(returncode: int, stderr: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], returncode, stdout=b"", stderr=stderr)


PLAN = f" {CC1} -quiet source.c -o /tmp/ccAAAAAA.s\n".encode()
PHASE_TOOLS = {"compile": {"path": CC1}}


class OrchestrationOutcomeTest(unittest.TestCase):
    def cases(self):
        return {spec["id"]: spec for spec in CAPTURE["ORCHESTRATION_CASES"]}

    def run_case(self, case_id, modes):
        """Run orchestrate() with `gcc -###`, `-v` and plain results taken from `modes`."""
        spec = self.cases()[case_id]

        def run_gcc(runtime, scratch, spec, label, extra):
            return Path("/unused"), modes[tuple(extra)]

        with mock.patch.dict(CAPTURE["orchestrate"].__globals__,
                             {"run_gcc": run_gcc, "collect": lambda workspace, inputs: []}):
            return CAPTURE["orchestrate"]("docker", Path("/unused"), spec, 1, PHASE_TOOLS)

    def test_declared_outcomes_match_the_checked_in_record(self):
        record = json.loads(ORCHESTRATION_RECORD.read_text())
        cases = self.cases()
        self.assertEqual([case["id"] for case in record["cases"]], list(cases))
        for case in record["cases"]:
            observed = case["observed"]
            self.assertEqual(observed["plan"]["exitCode"], 0, case["id"])
            self.assertTrue(observed["plan"]["phases"], case["id"])
            for mode in ("executedPhases", "execution"):
                self.assertEqual(bool(observed[mode]["exitCode"]), cases[case["id"]]["fails"], (case["id"], mode))

    def test_failed_or_empty_plan_is_refused(self):
        for plan in (completed(1, PLAN), completed(0, b"")):
            with self.assertRaisesRegex(SystemExit, "driver plan did not succeed"):
                self.run_case("compile-to-assembly", {("-###",): plan, ("-v",): completed(0), (): completed(0)})

    def test_repeatable_failure_of_a_success_case_is_refused(self):
        failure = completed(1, b"cc1: fatal error\n")
        for modes, mode in (
            ({("-v",): failure, (): failure}, "verbose trace"),
            ({("-v",): completed(0), (): failure}, "plain command"),
        ):
            with self.assertRaisesRegex(SystemExit, f"compile-save-temps: {mode} exited 1; .* to succeed"):
                self.run_case("compile-save-temps", {("-###",): completed(0, PLAN), **modes})

    def test_success_of_a_failure_case_is_refused(self):
        for modes, mode in (
            ({("-v",): completed(0), (): completed(1)}, "verbose trace"),
            ({("-v",): completed(1), (): completed(0)}, "plain command"),
        ):
            with self.assertRaisesRegex(SystemExit, f"failure-compile: {mode} exited 0; .* to fail"):
                self.run_case("failure-compile", {("-###",): completed(0, PLAN), **modes})

    def test_expected_outcomes_are_recorded(self):
        observed = self.run_case("failure-compile", {("-###",): completed(0, PLAN), ("-v",): completed(1),
                                                     (): completed(1)})
        self.assertEqual([observed[key]["exitCode"] for key in ("plan", "executedPhases", "execution")], [0, 1, 1])

    def test_container_launch_failure_is_refused(self):
        for status in (125, 126, 127):
            def run(command, **kwargs):
                if command[1:3] == ["image", "inspect"]:
                    return subprocess.CompletedProcess(command, 0, stdout=CAPTURE["IMAGE_CONFIG"], stderr="")
                return completed(status, b"engine error\n")

            with mock.patch("subprocess.run", side_effect=run):
                with self.assertRaisesRegex(SystemExit, f"container launch failed with status {status}"):
                    run_container("docker", Path("/workspace"), ["gcc", "-c", "failure.c"], b"")

    def test_refused_capture_writes_no_record(self):
        def records(runtime, scratch):
            spec = self.cases()["compile-save-temps"]
            failure = completed(1)
            modes = {("-###",): completed(0, PLAN), ("-v",): failure, (): failure}

            def run_gcc(runtime, scratch, spec, label, extra):
                return Path("/unused"), modes[tuple(extra)]

            with mock.patch.dict(CAPTURE["orchestrate"].__globals__, {"run_gcc": run_gcc}):
                CAPTURE["capture_orchestration_case"](runtime, scratch, spec, PHASE_TOOLS)

        with mock.patch.dict(CAPTURE["main"].__globals__, {"records": records}), \
                mock.patch.object(Path, "write_text") as write, \
                mock.patch("sys.argv", ["capture-gcc-preprocessing-reference.py"]):
            with self.assertRaisesRegex(SystemExit, "compile-save-temps: verbose trace exited 1"):
                CAPTURE["main"]()
        write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
