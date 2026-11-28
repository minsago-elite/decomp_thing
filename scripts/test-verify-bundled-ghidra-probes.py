#!/usr/bin/env python3
"""Portable controls for the bundled Ghidra installed-probe report gate."""
from html import escape
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
# Independently pin all exact identities here; do not mirror the verifier's
# REQUIRED set to construct the expected cases.
DEPLOYMENT_CLASS = "decompengine.oracle.gcc.GccBundledGhidraDeploymentReferenceTest"
DOT_QUALIFIER_CLASS = "decompengine.project.GhidraDotDirectoryInvocationQualificationTest"
PROBE_IDENTITIES = (
    (DEPLOYMENT_CLASS, "installed opener selects its own application exporter despite an earlier shadow resource()"),
    (DEPLOYMENT_CLASS, "installed opener rejects reference root and paired overrides before source selection()"),
    (DOT_QUALIFIER_CLASS, "installed bundled worker records default dot directory invocation()"),
)


class ProbeReportVerifierTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / "build/orchestration/ghidra-invocation-ci"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.reports = Path(self.temporary.name)

    def write_report(self, cases, filename="TEST-probes.xml", suite=None):
        groups = {suite: cases} if suite is not None else {}
        if suite is None:
            for case in cases:
                groups.setdefault(case[0], []).append(case)
        for index, (suite_name, selected) in enumerate(groups.items()):
            rows = []
            for classname, name, status in selected:
                child = f"<{status}/>" if status else ""
                rows.append(f'<testcase classname="{escape(classname, quote=True)}" name="{escape(name, quote=True)}">{child}</testcase>')
            target_name = filename if len(groups) == 1 else f"TEST-{index}.xml"
            (self.reports / target_name).write_text(f'<testsuite name="{escape(suite_name, quote=True)}">' + "".join(rows) + "</testsuite>")

    def all_passes(self):
        return [(classname, name, None) for classname, name in PROBE_IDENTITIES]

    def test_all_three_required_identities_pass_exactly_once(self):
        self.write_report(self.all_passes())
        self.assertEqual([], MODULE.verify(self.reports))

    def test_missing_report_fails(self):
        self.assertTrue(any("no JUnit XML" in error for error in MODULE.verify(self.reports)))

    def test_cli_returns_nonzero_for_missing_report(self):
        result = subprocess.run([sys.executable, "-B", str(MODULE_PATH), str(self.reports)],
                                text=True, capture_output=True, timeout=10)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("no JUnit XML", result.stderr)

    def test_cli_accepts_exact_gradle_method_names(self):
        self.write_report(self.all_passes())
        result = subprocess.run([sys.executable, "-B", str(MODULE_PATH), str(self.reports)],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("all three required identities", result.stdout)

    def test_prior_gate_gap_old_two_case_report_is_rejected_for_missing_new_probe(self):
        """The prior verifier accepted these two passes; the class/name gate must now require #1893 too."""
        old_two = self.all_passes()[:2]
        self.write_report(old_two)
        self.assertEqual({DEPLOYMENT_CLASS}, {classname for classname, _, _ in old_two})
        errors = MODULE.verify(self.reports)
        self.assertTrue(any(DOT_QUALIFIER_CLASS in error for error in errors))
        self.assertTrue(any("missing required" in error for error in errors))

    def test_bare_names_and_wrong_class_are_not_emitted_test_identities(self):
        bare = [(classname, name[:-2], None) for classname, name in PROBE_IDENTITIES]
        self.write_report(bare)
        self.assertTrue(MODULE.verify(self.reports))
        for report in self.reports.glob("TEST-*.xml"):
            report.unlink()
        wrong_class = [("wrong.Class", name, None) if classname == DOT_QUALIFIER_CLASS else (classname, name, None)
                       for classname, name in PROBE_IDENTITIES]
        self.write_report(wrong_class)
        self.assertTrue(any("missing required" in error for error in MODULE.verify(self.reports)))

    def test_new_only_and_old_only_reports_fail(self):
        cases = self.all_passes()
        for selected in (cases[-1:], cases[:2]):
            with self.subTest(selected=[case[1] for case in selected]):
                self.write_report(selected)
                errors = MODULE.verify(self.reports)
                self.assertTrue(any("missing required" in error for error in errors))
                (self.reports / "TEST-probes.xml").unlink()

    def test_non_junit_root_and_nested_cases_are_rejected(self):
        for replacement in ("not-junit", "testcase"):
            with self.subTest(root=replacement):
                self.write_report(self.all_passes())
                self.assertEqual([], MODULE.verify(self.reports))
                report = self.reports / "TEST-1.xml"
                report.write_text(report.read_text().replace("testsuite", replacement))
                self.assertTrue(any("unsupported Gradle JUnit report structure" in error for error in MODULE.verify(self.reports)))
        self.write_report(self.all_passes())
        self.assertEqual([], MODULE.verify(self.reports))
        report = self.reports / "TEST-1.xml"
        report.write_text(report.read_text().replace(">", "><properties>", 1).replace("</testsuite>", "</properties></testsuite>"))
        self.assertTrue(any("unsupported Gradle JUnit report structure" in error for error in MODULE.verify(self.reports)))

    def test_truncated_xml_is_rejected(self):
        (self.reports / "TEST-probes.xml").write_text("<testsuite>")
        self.assertTrue(MODULE.verify(self.reports))

    def test_wrong_suite_and_linked_report_are_rejected(self):
        self.write_report(self.all_passes())
        self.assertEqual([], MODULE.verify(self.reports))
        report = self.reports / "TEST-1.xml"
        original = report.read_text()
        report.write_text(original.replace(f'<testsuite name="{DOT_QUALIFIER_CLASS}">', '<testsuite name="other">'))
        self.assertTrue(any("wrong suite identity" in error for error in MODULE.verify(self.reports)))
        report.unlink()
        payload = self.reports / "payload.xml"
        payload.write_text(original)
        report.symlink_to(payload)
        self.assertTrue(any("not an ordinary file" in error for error in MODULE.verify(self.reports)))

    def test_wrong_suite_for_dot_case_fails_even_when_old_suite_passes(self):
        self.write_report(self.all_passes()[:2])
        self.write_report([self.all_passes()[2]], filename="TEST-dot.xml", suite="wrong.suite")
        errors = MODULE.verify(self.reports)
        self.assertTrue(any("wrong suite identity" in error for error in errors))
        self.assertTrue(any("missing required" in error for error in errors))

    def test_file_and_byte_budgets_are_enforced(self):
        self.write_report([self.all_passes()[0]])
        with patch.object(MODULE, "MAX_REPORT_BYTES", 128):
            self.assertTrue(any("byte bound" in error for error in MODULE.verify(self.reports)))
        self.write_report([self.all_passes()[0]], "TEST-second.xml")
        with patch.object(MODULE, "MAX_REPORT_FILES", 1):
            self.assertTrue(any("file count" in error for error in MODULE.verify(self.reports)))
        length = (self.reports / "TEST-probes.xml").stat().st_size
        with patch.object(MODULE, "MAX_TOTAL_BYTES", length):
            self.assertTrue(any("byte bound" in error for error in MODULE.verify(self.reports)))

    def test_each_skipped_target_fails(self):
        for classname, name in PROBE_IDENTITIES:
            with self.subTest(name=name):
                self.write_report([(classname, name, "skipped")], suite=classname)
                errors = MODULE.verify(self.reports)
                self.assertTrue(any("skipped" in error for error in errors))
                self.assertTrue(any("missing required" in error for error in errors))
                (self.reports / "TEST-probes.xml").unlink()

    def test_failure_and_error_targets_fail(self):
        for status in ("failure", "error"):
            with self.subTest(status=status):
                cases = self.all_passes()
                cases[-1] = (*cases[-1][:2], status)
                self.write_report(cases)
                self.assertTrue(any(status in error for error in MODULE.verify(self.reports)))
                for report in self.reports.glob("TEST-*.xml"):
                    report.unlink()

    def test_missing_method_fails(self):
        self.write_report(self.all_passes()[:2])
        self.assertTrue(any("missing required" in error for error in MODULE.verify(self.reports)))

    def test_duplicate_identity_fails_even_when_both_pass(self):
        passing = self.all_passes()
        self.write_report([passing[-1]], "TEST-one.xml", suite=DOT_QUALIFIER_CLASS)
        self.write_report([passing[-1]], "TEST-two.xml", suite=DOT_QUALIFIER_CLASS)
        self.assertTrue(any("duplicate testcase identity" in error for error in MODULE.verify(self.reports)))

    def test_source_and_workflow_exact_wiring_are_static_checks(self):
        deployment = (ROOT / "src/test/kotlin/decompengine/oracle/gcc/GccBundledGhidraDeploymentReferenceTest.kt").read_text()
        qualifier = (ROOT / "src/test/kotlin/decompengine/project/GhidraDotDirectoryInvocationQualificationTest.kt").read_text()
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        section = workflow.split("  bundled-ghidra:\n", 1)[1].split("\n  archival-ghidra:\n", 1)[0]
        for _, name in PROBE_IDENTITIES[:2]:
            self.assertIn(f"fun `{name[:-2]}`()", deployment)
        self.assertIn(f"fun `{PROBE_IDENTITIES[2][1][:-2]}`()", qualifier)
        self.assertIn("--tests decompengine.oracle.gcc.GccBundledGhidraDeploymentReferenceTest", section)
        self.assertIn("--tests decompengine.project.GhidraDotDirectoryInvocationQualificationTest", section)
        self.assertIn("python3 scripts/verify-bundled-ghidra-probes.py build/test-results/test", section)
        self.assertIn('RUN_REAL_GHIDRA: "true"', section)
        self.assertIn("unset GHIDRA_HOME", section)
        self.assertIn("build/orchestration/ghidra-invocation-qualification", section)
        # This only checks declaration/selection wiring; hosted JUnit is the runtime gate.


if __name__ == "__main__":
    (ROOT / "build/orchestration/ghidra-invocation-ci").mkdir(parents=True, exist_ok=True)
    unittest.main(verbosity=2)
