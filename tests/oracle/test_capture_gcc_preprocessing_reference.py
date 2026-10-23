from __future__ import annotations

import json
import runpy
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
                run_container(runtime, Path("/workspace"), ["gcc", "-c", "source.c"], b"")
            command = run.call_args.args[0]
            self.assertIn("--read-only", command)
            index = command.index("--tmpfs")
            self.assertEqual(command[index + 1], "/tmp")
            self.assertLess(index, command.index(CAPTURE["IMAGE"]))

    def test_records_name_driver_temporaries_only_under_tmp(self):
        text = ORCHESTRATION_RECORD.read_text()
        self.assertNotRegex(text, r"\./cc[A-Za-z0-9]{6}")
        self.assertNotRegex(text, r"/tmp/cc[A-Za-z0-9]{6}")


if __name__ == "__main__":
    unittest.main()
