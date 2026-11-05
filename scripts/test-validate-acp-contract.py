#!/usr/bin/env python3
"""Exercise the real qualifier with synthetic JUnit and an inert Gradle command."""
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/validate-acp-contract.sh"
SOURCE = SCRIPT.read_text()
PYTHON_SOURCE = SOURCE.split("<<'PY'", 1)[1].split("\n", 1)[1].split("\nPY\n", 1)[0]
EXPECTED = next(ast.literal_eval(node.value) for node in ast.parse(PYTHON_SOURCE).body
                if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "expected" for target in node.targets))


class QualifierControlTest(unittest.TestCase):
    def setUp(self):
        temporary_root = ROOT / "build/test-tmp/acp-validator"
        temporary_root.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=temporary_root)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts/validate-acp-contract.sh")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.bin / "python3").symlink_to(sys.executable)
        (self.bin / "dirname").symlink_to(shutil.which("dirname"))
        self.executable(self.bin / "git", "#!/bin/bash\nprintf '%040d\\n' 1\n")
        self.executable(self.root / "gradlew", """#!/bin/bash
printf '%s\\n' "$DECOMP_REQUIRE_LIVE_ACP_CONTRACT" "$@" > invocation.txt
exit "$FIXTURE_GRADLE_STATUS"
""")
        self.reports = self.root / "build/test-results/test"
        self.reports.mkdir(parents=True)
        self.env = {**os.environ, "PATH": str(self.bin),
                    "DECOMP_TEST_ACP_QUOTA_TMPFS": str(self.root / "inert-quota"),
                    "FIXTURE_GRADLE_STATUS": "0"}

    @staticmethod
    def executable(path, content):
        path.write_text(content)
        path.chmod(0o700)

    def reports_with(self, **overrides):
        for index, name in enumerate(sorted(EXPECTED)):
            attributes = dict(name=f"decompengine.acp.{name}", tests="1", failures="0", errors="0", skipped="0")
            if index == 0:
                attributes.update(overrides)
            ET.ElementTree(ET.Element("testsuite", attributes)).write(self.reports / f"TEST-{name}.xml")

    def run_qualifier(self, status=0):
        self.env["FIXTURE_GRADLE_STATUS"] = str(status)
        return subprocess.run(["/bin/bash", "scripts/validate-acp-contract.sh"], cwd=self.root,
                              env=self.env, text=True, capture_output=True, timeout=10)

    def summary(self):
        return json.loads((self.root / "build/acp-contract-qualification/summary.json").read_text())

    def test_success_keeps_required_command_and_inventory(self):
        self.reports_with()
        result = self.run_qualifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.summary()["gradleExitCode"], 0)
        self.assertEqual(self.summary()["missingRequiredSuites"], [])
        self.assertEqual((self.root / "invocation.txt").read_text().splitlines(), [
            "1", "--no-daemon", "test", "--tests", "decompengine.acp.*", "--tests",
            "decompengine.agent.*", "--exclude-task", ":gccCompilerEnginePlanningIsolated"])

    def test_gradle_failure_retains_failed_xml_and_original_exit(self):
        self.reports_with(failures="1")
        result = self.run_qualifier(7)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(self.summary()["totals"]["failures"], 1)
        self.assertEqual(self.summary()["gradleExitCode"], 7)
        self.assertFalse(self.summary()["releaseQualified"])
        self.assertFalse(self.summary()["realAgentQualified"])

    def test_passing_xml_cannot_hide_gradle_failure(self):
        self.reports_with()
        result = self.run_qualifier(9)
        self.assertEqual(result.returncode, 9)
        self.assertEqual(self.summary()["gradleExitCode"], 9)
        self.assertIn("retained reports do not qualify", result.stderr)

    def test_missing_xml_still_emits_missing_inventory_after_gradle_failure(self):
        result = self.run_qualifier(4)
        self.assertEqual(result.returncode, 4)
        self.assertEqual(set(self.summary()["missingRequiredSuites"]), EXPECTED)
        self.assertEqual(self.summary()["totals"]["tests"], 0)

    def test_report_failures_remain_fatal_after_gradle_success(self):
        for field in ("failures", "errors", "skipped"):
            with self.subTest(field=field):
                self.reports_with(**{field: "1"})
                result = self.run_qualifier()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.summary()["totals"][field], 1)

    def test_verifier_execution_failure_preserves_exit_precedence(self):
        (self.bin / "python3").unlink()
        self.executable(self.bin / "python3", "#!/bin/bash\nprintf 'verifier invoked\\n' >&2\nexit 23\n")
        for gradle_status, expected in ((0, 23), (11, 11)):
            with self.subTest(gradle_status=gradle_status):
                result = self.run_qualifier(gradle_status)
                self.assertEqual(result.returncode, expected)
                self.assertEqual(result.stderr.count("verifier invoked"), 1)

    def test_malformed_xml_remains_fatal(self):
        (self.reports / "TEST-malformed.xml").write_text("<testsuite")
        result = self.run_qualifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ParseError", result.stderr)


if __name__ == "__main__":
    unittest.main()
