#!/usr/bin/env python3
"""Authored source/XML controls for recovery coverage; no JVM or subject invocation."""

import importlib.util
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


SPEC = importlib.util.spec_from_file_location(
    "recovery_inventory", Path(__file__).with_name("verify-web-job-recovery.py"))
RECOVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECOVERY)
SUITE = "decompengine.jobs.ExampleTest"


def report(methods, suite=SUITE, outcomes=None):
    outcomes = outcomes or [None] * len(methods)
    node = ET.Element("testsuite", name=suite, tests=str(len(methods)),
        failures=str(outcomes.count("failure")), errors=str(outcomes.count("error")),
        skipped=str(outcomes.count("skipped")))
    for method, outcome in zip(methods, outcomes):
        case = ET.SubElement(node, "testcase", classname=suite, name=method)
        if outcome:
            ET.SubElement(case, outcome).text = "PRIVATE failure text is not part of the inventory"
    return ET.tostring(node)


class RecoveryInventoryControls(unittest.TestCase):
    def inspect(self, methods, reports, allow_unrelated=False):
        return RECOVERY.inspect_reports({SUITE: methods}, reports, allow_unrelated)

    def test_exact_cases_and_actual_counts_pass_with_report_digest(self):
        payload = report(["first()", "second()"])
        result = self.inspect(["first()", "second()"], {"TEST.xml": payload})
        self.assertEqual([], result["verificationFailures"])
        self.assertEqual(dict(tests=2, failures=0, errors=0, skipped=0), result["totals"])
        self.assertEqual(["PASS", "PASS"], [x["status"] for x in result["suites"][SUITE]["cases"]])
        self.assertEqual(len(payload), result["suites"][SUITE]["xmlBytes"])
        self.assertEqual(64, len(result["suites"][SUITE]["xmlSha256"]))

    def test_nonempty_suite_cannot_hide_a_missing_scenario(self):
        result = self.inspect(["first()", "lost()"], {"TEST.xml": report(["first()"] )})
        self.assertIn("Missing testcase: " + SUITE + "::lost()", result["verificationFailures"])

    def test_duplicate_identity_is_not_a_replacement_for_a_missing_case(self):
        result = self.inspect(["first()", "lost()"], {"TEST.xml": report(["first()", "first()"] )})
        self.assertIn("Duplicate testcase: " + SUITE, result["verificationFailures"])
        self.assertIn("Missing testcase: " + SUITE + "::lost()", result["verificationFailures"])

    def test_duplicate_suite_and_unexpected_case_are_refused(self):
        result = self.inspect(["first()"], {"a.xml": report(["first()", "extra()"]),
                                            "b.xml": report(["first()"] )})
        self.assertIn("Duplicate suite: " + SUITE, result["verificationFailures"])
        self.assertIn("Unexpected testcase: " + SUITE + "::extra()", result["verificationFailures"])

    def test_report_counts_cannot_hide_an_actual_skip(self):
        node = ET.fromstring(report(["first()"], outcomes=["skipped"]))
        node.set("skipped", "0")
        result = self.inspect(["first()"], {"TEST.xml": ET.tostring(node)})
        self.assertTrue(any(x.startswith("Invalid JUnit report:") for x in result["verificationFailures"]))

    def test_each_terminal_failure_kind_and_skip_refuses_coverage(self):
        for outcome in ("failure", "error", "skipped"):
            with self.subTest(outcome=outcome):
                result = self.inspect(["first()"], {"TEST.xml": report(["first()"], outcomes=[outcome])})
                self.assertIn("Recovery scenarios contain failures, errors or skipped tests", result["verificationFailures"])
                self.assertNotIn("PRIVATE", str(result))

    def test_missing_empty_and_malformed_reports_are_refused(self):
        for reports in ({}, {"empty.xml": report([])}, {"bad.xml": b"<testsuite"}):
            with self.subTest(reports=list(reports)):
                self.assertTrue(self.inspect(["first()"], reports)["verificationFailures"])

    def test_cross_class_testcase_cannot_satisfy_a_suite(self):
        node = ET.fromstring(report(["first()"])); node.find("testcase").set("classname", "different.Class")
        self.assertTrue(self.inspect(["first()"], {"TEST.xml": ET.tostring(node)})["verificationFailures"])

    def test_conflicting_case_outcomes_are_refused(self):
        node = ET.fromstring(report(["first()"], outcomes=["skipped"]))
        ET.SubElement(node.find("testcase"), "failure")
        self.assertTrue(self.inspect(["first()"], {"TEST.xml": ET.tostring(node)})["verificationFailures"])

    def test_other_core_suites_are_allowed_only_in_report_consumption_mode(self):
        reports = {"recovery.xml": report(["first()"]),
                   "unrelated.xml": report(["other()"], suite="decompengine.other.Test")}
        self.assertEqual([], self.inspect(["first()"], reports, True)["verificationFailures"])
        self.assertTrue(self.inspect(["first()"], reports)["verificationFailures"])

    def test_nested_source_scenario_remains_required_despite_lost_discovery(self):
        source = """class ExampleTest {
            @Test fun `outer`() {
                @Test fun `nested and undiscovered`() { }
            }
        }"""
        methods = RECOVERY.source_test_methods(source)
        self.assertEqual(["outer()", "nested and undiscovered()"], methods)
        result = self.inspect(methods, {"TEST.xml": report(["outer()"] )})
        self.assertIn("Missing testcase: " + SUITE + "::nested and undiscovered()", result["verificationFailures"])

    def test_multiline_and_inline_literal_declarations_are_supported(self):
        self.assertEqual(["one()", "two()"], RECOVERY.source_test_methods(
            "@Test\nfun `one`() {}\n@Test fun `two`() = verify()"))

    def test_unhandled_annotation_shape_alias_and_duplicate_names_are_refused(self):
        for source in ("@Test fun named() {}", "@Test fun `has parameters`(value: Int) {}",
                       "@org.junit.jupiter.api.Test fun `qualified`() {}",
                       "@org.junit.jupiter.params.ParameterizedTest fun `parameterized`() {}",
                       "import kotlin.test.Test as Scenario\n@Test fun `ordinary`() {}\n@Scenario fun `hidden`() {}",
                       "@Test fun `same`() {}\n@Test fun `same`() {}"):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    RECOVERY.source_test_methods(source)


if __name__ == "__main__":
    unittest.main()
