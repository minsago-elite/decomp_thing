#!/usr/bin/env python3
"""Coverage-verifier controls; no compiler, privileged runtime, or reconstructed program runs."""

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("live_coverage", ROOT / "scripts/verify-module-compilation-live-tests.py")
COVERAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COVERAGE)


class LiveCoverageControls(unittest.TestCase):
    def setUp(self):
        temporary = ROOT / "build/task-tmp/live-coverage-tests"
        temporary.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=temporary)
        self.root = Path(self.temporary.name)
        self.reports = self.root / "reports"
        self.reports.mkdir()
        self.inventory = self.root / "inventory.json"
        self.summary = self.root / "summary.json"
        self.tests = {"decompengine.project.FirstTest": ["first live test", "second & <live> test"],
                      "decompengine.project.SecondTest": ["other live test"]}
        self.value = {"schemaVersion": 1, "provider": COVERAGE.INVENTORY_PROVIDER,
                      "classes": list(self.tests), "testCount": 3,
                      "tests": [{"class": name, "method": method, "reportName": method + "()"}
                                for name, methods in self.tests.items() for method in methods]}
        self.write_inventory()
        for name, methods in self.tests.items():
            self.write_report(name, methods)

    def tearDown(self):
        self.temporary.cleanup()

    def write_inventory(self):
        self.inventory.write_text(json.dumps(self.value), encoding="utf-8")

    def write_report(self, name, methods, counters=None, child=None, case_class=None, suite_class=None):
        attributes = {"name": suite_class or name, "tests": str(len(methods)), "failures": "0", "errors": "0", "skipped": "0"}
        attributes.update(counters or {})
        suite = ET.Element("testsuite", attributes)
        ET.SubElement(suite, "properties")
        for method in methods:
            case = ET.SubElement(suite, "testcase", {"classname": case_class or name, "name": method + "()", "time": "0.001"})
            if child:
                ET.SubElement(case, child)
        ET.SubElement(suite, "system-out").text = "bounded log with <escaped> XML"
        ET.SubElement(suite, "system-err")
        path = self.reports / f"TEST-{name}.xml"
        ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)
        return path

    def verify(self):
        return COVERAGE.verify(self.inventory, self.reports)

    def run_cli(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return COVERAGE.main(["--inventory", str(self.inventory), "--reports", str(self.reports), "--output", str(self.summary)])

    def test_complete_exact_reports_produce_fresh_summary(self):
        self.assertEqual(0, self.run_cli())
        summary = json.loads(self.summary.read_text())
        self.assertEqual((2, 3, 2), (summary["classCount"], summary["testCount"], summary["reportCount"]))
        self.assertEqual((0, 0, 0), (summary["failures"], summary["errors"], summary["skipped"]))
        self.assertEqual(64, len(summary["inventorySha256"]))
        before = self.summary.read_bytes()
        self.assertEqual(1, self.run_cli())
        self.assertEqual(before, self.summary.read_bytes())

    def test_quietly_missing_method_rejects_even_with_matching_suite_total(self):
        name = next(iter(self.tests))
        self.write_report(name, self.tests[name][:1])
        with self.assertRaisesRegex(ValueError, "live test membership differs"):
            self.verify()
        self.assertEqual(1, self.run_cli())
        self.assertFalse(self.summary.exists())

    def test_absent_and_unexpected_class_files_reject(self):
        name = next(iter(self.tests))
        path = self.reports / f"TEST-{name}.xml"
        payload = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(ValueError, "report file membership differs"):
            self.verify()
        path.write_bytes(payload)
        self.write_report("decompengine.project.UnselectedTest", ["extra"])
        with self.assertRaisesRegex(ValueError, "report file membership differs"):
            self.verify()

    def test_renamed_report_file_cannot_impersonate_selected_class(self):
        name = next(iter(self.tests))
        (self.reports / f"TEST-{name}.xml").rename(self.reports / "TEST-spoof.xml")
        with self.assertRaisesRegex(ValueError, "report file membership differs"):
            self.verify()

    def test_testcase_and_suite_class_spoofing_reject(self):
        name = next(iter(self.tests))
        for keyword in ("case_class", "suite_class"):
            with self.subTest(keyword=keyword):
                self.write_report(name, self.tests[name], **{keyword: "decompengine.project.OtherTest"})
                with self.assertRaises(ValueError):
                    self.verify()

    def test_failure_error_skip_elements_reject_despite_zero_counters(self):
        name = next(iter(self.tests))
        for child in ("failure", "error", "skipped", "unknown"):
            with self.subTest(child=child):
                self.write_report(name, self.tests[name], child=child)
                with self.assertRaisesRegex(ValueError, "testcase has a failure, error, skip"):
                    self.verify()

    def test_failure_error_skip_counters_reject_despite_no_elements(self):
        name = next(iter(self.tests))
        for field in ("failures", "errors", "skipped"):
            with self.subTest(field=field):
                self.write_report(name, self.tests[name], counters={field: "1"})
                with self.assertRaisesRegex(ValueError, "suite has failures, errors, or skips"):
                    self.verify()

    def test_test_totals_and_numeric_types_must_reconcile(self):
        name = next(iter(self.tests))
        for count in ("3", "0", "-1", "1.0", "true", "99999999999"):
            with self.subTest(count=count):
                self.write_report(name, self.tests[name], counters={"tests": count})
                with self.assertRaises(ValueError):
                    self.verify()

    def test_duplicate_and_replacement_cases_reject(self):
        name = next(iter(self.tests))
        self.write_report(name, self.tests[name] + self.tests[name][:1])
        with self.assertRaisesRegex(ValueError, "duplicate XML testcase"):
            self.verify()
        self.write_report(name, [self.tests[name][0], "unselected replacement"])
        with self.assertRaisesRegex(ValueError, "live test membership differs"):
            self.verify()

    def test_inventory_is_closed_and_versioned_with_exact_integer_types(self):
        for field, replacement in (("schemaVersion", True), ("schemaVersion", 2), ("provider", "source-only"),
                                   ("testCount", True), ("testCount", 2), ("unexpected", "field")):
            with self.subTest(field=field, replacement=replacement):
                value = {**self.value, field: replacement}
                with self.assertRaises(ValueError):
                    COVERAGE.load_inventory(json.dumps(value).encode())
        for field in self.value:
            with self.subTest(missing=field), self.assertRaises(ValueError):
                COVERAGE.load_inventory(json.dumps({key: value for key, value in self.value.items() if key != field}).encode())

    def test_duplicate_json_keys_and_noninteger_numbers_reject(self):
        for payload in (b'{"schemaVersion":1,"schemaVersion":1}', b'{"schemaVersion":NaN}',
                        b'{"schemaVersion":1.0}', b'{"schemaVersion":12345678901}', b'\xff'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                COVERAGE.load_inventory(payload)

    def test_each_class_requires_unique_current_methods_and_report_names(self):
        controls = [
            {**self.value, "classes": self.value["classes"] * 2},
            {**self.value, "classes": self.value["classes"] + ["decompengine.EmptyTest"]},
            {**self.value, "tests": self.value["tests"] + [self.value["tests"][0]], "testCount": 4},
        ]
        for fields in ({"method": "different"}, {"reportName": "custom display name"}, {"extra": "ignored"},
                       {"class": "decompengine.UnselectedTest"}, {"method": "line\nbreak"}, {"method": None}):
            controls.append({**self.value, "tests": [{**self.value["tests"][0], **fields}] + self.value["tests"][1:]})
        for value in controls:
            with self.subTest(value=value), self.assertRaises(ValueError):
                COVERAGE.load_inventory(json.dumps(value).encode())

    def test_xml_entities_nested_suites_and_missing_totals_reject(self):
        name = next(iter(self.tests))
        path = self.reports / f"TEST-{name}.xml"
        for payload in (b'<!DOCTYPE testsuite [<!ENTITY injected "x">]><testsuite/>',
                        b'<testsuites><testsuite/></testsuites>',
                        f'<testsuite name="{name}"/>'.encode()):
            with self.subTest(payload=payload):
                path.write_bytes(payload)
                with self.assertRaises(ValueError):
                    self.verify()

    def test_symbolic_link_inputs_and_outside_build_output_reject(self):
        alias = self.root / "inventory-alias.json"
        alias.symlink_to(self.inventory)
        with self.assertRaisesRegex(ValueError, "without symbolic links"):
            COVERAGE.verify(alias, self.reports)
        name = next(iter(self.tests))
        path = self.reports / f"TEST-{name}.xml"
        saved = self.root / "saved.xml"
        path.rename(saved)
        path.symlink_to(saved)
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            self.verify()
        with self.assertRaises(ValueError):
            COVERAGE.build_path(ROOT / "unwanted-summary.json")

    def test_input_byte_bounds_reject_before_parsing(self):
        with self.inventory.open("wb") as stream:
            stream.truncate(COVERAGE.MAX_INVENTORY_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "size bound"):
            self.verify()
        self.write_inventory()
        name = next(iter(self.tests))
        with (self.reports / f"TEST-{name}.xml").open("wb") as stream:
            stream.truncate(COVERAGE.MAX_REPORT_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "size bound"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
