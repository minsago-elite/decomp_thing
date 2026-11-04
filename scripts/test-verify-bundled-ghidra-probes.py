#!/usr/bin/env python3
"""Portable controls for the bundled Ghidra installed-probe report gate."""
from pathlib import Path
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "scripts/verify-bundled-ghidra-probes.py"
SPEC = importlib.util.spec_from_file_location("bundled_ghidra_probe_report", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
# Gradle/JUnit Jupiter display names, independently pinned from the Kotlin declarations.
PROBE_NAMES = (
    "installed opener selects its own application exporter despite an earlier shadow resource()",
    "installed opener rejects reference root and paired overrides before source selection()",
)


class ProbeReportVerifierTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / "build/orchestration/ghidra-probes"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.reports = Path(self.temporary.name)

    def write_report(self, cases, filename="TEST-probes.xml"):
        rows = []
        for name, status in cases:
            child = f"<{status}/>" if status else ""
            rows.append(f'<testcase classname="{MODULE.CLASS}" name="{name}">{child}</testcase>')
        (self.reports / filename).write_text(f'<testsuite name="{MODULE.CLASS}">' + "".join(rows) + "</testsuite>")

    def all_passes(self):
        return [(name, None) for name in PROBE_NAMES]

    def test_all_required_probe_methods_pass_exactly_once(self):
        self.write_report(self.all_passes())
        self.assertEqual([], MODULE.verify(self.reports))

    def test_missing_report_fails(self):
        self.assertTrue(any("no JUnit XML" in error for error in MODULE.verify(self.reports)))

    def test_cli_returns_nonzero_for_missing_report(self):
        result = subprocess.run([sys.executable, "-B", str(MODULE_PATH), str(self.reports)],
                                text=True, capture_output=True, timeout=10)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("no JUnit XML", result.stderr)

    def test_cli_accepts_actual_gradle_method_names(self):
        self.write_report(self.all_passes())
        result = subprocess.run([sys.executable, "-B", str(MODULE_PATH), str(self.reports)],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_bare_kotlin_names_are_not_emitted_test_identities(self):
        self.write_report([(name[:-2], None) for name in PROBE_NAMES])
        self.assertTrue(MODULE.verify(self.reports))

    def test_non_junit_root_and_nested_cases_are_rejected(self):
        for replacement in ("not-junit", "testcase"):
            with self.subTest(root=replacement):
                self.write_report(self.all_passes())
                report = self.reports / "TEST-probes.xml"
                report.write_text(report.read_text().replace("testsuite", replacement))
                self.assertTrue(MODULE.verify(self.reports))
        self.write_report(self.all_passes())
        report = self.reports / "TEST-probes.xml"
        report.write_text(report.read_text().replace(">", "><properties>", 1).replace("</testsuite>", "</properties></testsuite>"))
        self.assertTrue(MODULE.verify(self.reports))

    def test_truncated_xml_is_rejected(self):
        (self.reports / "TEST-probes.xml").write_text("<testsuite>")
        self.assertTrue(MODULE.verify(self.reports))

    def test_wrong_suite_and_linked_report_are_rejected(self):
        self.write_report(self.all_passes())
        report = self.reports / "TEST-probes.xml"
        original = report.read_text()
        report.write_text(original.replace(f'<testsuite name="{MODULE.CLASS}">', '<testsuite name="other">'))
        self.assertTrue(MODULE.verify(self.reports))
        report.unlink()
        payload = self.reports / "payload.xml"
        payload.write_text(original)
        report.symlink_to(payload)
        self.assertTrue(MODULE.verify(self.reports))

    def test_file_and_byte_budgets_are_enforced(self):
        self.write_report(self.all_passes())
        with patch.object(MODULE, "MAX_REPORT_BYTES", 128):
            self.assertTrue(any("byte bound" in error for error in MODULE.verify(self.reports)))
        self.write_report(self.all_passes(), "TEST-second.xml")
        with patch.object(MODULE, "MAX_REPORT_FILES", 1):
            self.assertTrue(any("file count" in error for error in MODULE.verify(self.reports)))
        length = (self.reports / "TEST-probes.xml").stat().st_size
        with patch.object(MODULE, "MAX_TOTAL_BYTES", length):
            self.assertTrue(any("byte bound" in error for error in MODULE.verify(self.reports)))

    def test_each_skipped_target_fails(self):
        for name in PROBE_NAMES:
            with self.subTest(name=name):
                self.write_report([(name, "skipped")])
                errors = MODULE.verify(self.reports)
                self.assertTrue(any("skipped" in error for error in errors))
                self.assertTrue(any("missing required" in error for error in errors))
                (self.reports / "TEST-probes.xml").unlink()

    def test_failure_and_error_targets_fail(self):
        for status in ("failure", "error"):
            with self.subTest(status=status):
                self.write_report(self.all_passes()[:1] + [(PROBE_NAMES[1], status)])
                self.assertTrue(any(status in error for error in MODULE.verify(self.reports)))
                (self.reports / "TEST-probes.xml").unlink()

    def test_missing_method_fails(self):
        self.write_report(self.all_passes()[:1])
        self.assertTrue(any("missing required" in error for error in MODULE.verify(self.reports)))

    def test_duplicate_identity_fails_even_when_both_pass(self):
        passing = self.all_passes()
        self.write_report(passing, "TEST-one.xml")
        self.write_report([passing[0]], "TEST-two.xml")
        self.assertTrue(any("duplicate testcase identity" in error for error in MODULE.verify(self.reports)))

    def test_source_and_workflow_select_and_gate_actual_methods(self):
        source = (ROOT / "src/test/kotlin/decompengine/oracle/gcc/GccBundledGhidraDeploymentReferenceTest.kt").read_text()
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        section = workflow.split("  bundled-ghidra:\n", 1)[1].split("\n  archival-ghidra:\n", 1)[0]
        for name in PROBE_NAMES:
            self.assertIn(f"fun `{name[:-2]}`()", source)
        self.assertIn("--tests decompengine.oracle.gcc.GccBundledGhidraDeploymentReferenceTest", section)
        self.assertIn("python3 scripts/verify-bundled-ghidra-probes.py build/test-results/test", section)


if __name__ == "__main__":
    (ROOT / "build/orchestration/ghidra-probes").mkdir(parents=True, exist_ok=True)
    unittest.main(verbosity=2)
