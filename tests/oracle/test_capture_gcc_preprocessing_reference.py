from __future__ import annotations

import json
import runpy
import subprocess
import tempfile
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
    def test_orchestration_uses_original_driver_frontend_and_closed_environment(self):
        scratch_parent = REPOSITORY_ROOT / "build/tmp"
        scratch_parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_parent) as directory:
            scratch = Path(directory)
            run_gcc = CAPTURE["run_gcc"]
            with mock.patch.dict(run_gcc.__globals__, {"run_container": mock.Mock()}) as globals_:
                run_gcc("podman", scratch, CAPTURE["ORCHESTRATION_CASES"][0], "plan", ["-###"])
                call = globals_["run_container"].call_args
        command = call.args[2]
        self.assertEqual(command[:2], ["env", "-i"])
        self.assertIn(CAPTURE["ORACLE_DRIVER_PATH"], command)
        environment = {part.split("=", 1)[0]: part.split("=", 1)[1] for part in command[2:] if "=" in part}
        self.assertEqual(environment, {**CAPTURE["ENVIRONMENT"], **CAPTURE["ORCHESTRATION_ENVIRONMENT"]})
        self.assertEqual(call.args[4], ((CAPTURE["ORACLE_DRIVER"], CAPTURE["ORACLE_DRIVER_PATH"]),
                                        (scratch / "oracle-cc1", CAPTURE["ORACLE_FRONTEND_PATH"])))

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

    def test_orchestration_owners_are_manifest_pinned_original_artifacts(self):
        record = json.loads(ORCHESTRATION_RECORD.read_text())
        for owner, name in (("oracleDriver", "oracle-manifest.json"), ("oracleFrontend", "cc1-oracle-manifest.json")):
            manifest = json.loads((ORCHESTRATION_RECORD.parent / name).read_text())
            self.assertEqual(record[owner]["sha256"], manifest["artifacts"]["stripped"]["sha256"])
        self.assertEqual(record["toolchain"]["driver"]["sha256"], record["oracleDriver"]["sha256"])
        self.assertEqual(record["toolchain"]["phaseTools"]["compile"]["sha256"], record["oracleFrontend"]["sha256"])
        self.assertEqual(record["toolchain"]["target"], "x86_64-pc-linux-gnu")


if __name__ == "__main__":
    unittest.main()
