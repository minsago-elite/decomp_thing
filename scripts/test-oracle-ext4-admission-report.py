#!/usr/bin/env python3
"""Unprivileged report-gate controls; these never count as mounted-state evidence."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("admission_report", ROOT / "scripts/verify-oracle-ext4-admission.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class ReportGateTests(unittest.TestCase):
    def setUp(self):
        temporary_root = ROOT / "build/issue930-tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=temporary_root)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / f"TEST-{GATE.CLASS}.xml"

    def write(self, names=GATE.REQUIRED, status=None, classname=GATE.CLASS):
        suite = ET.Element("testsuite")
        for name in names:
            case = ET.SubElement(suite, "testcase", classname=classname, name=name + "()")
            if status:
                ET.SubElement(case, status)
        self.path.write_bytes(ET.tostring(suite))

    def test_accepts_exact_named_success(self):
        self.write()
        result = GATE.verify(self.root)
        self.assertEqual(18, result["passed"])
        self.assertEqual(0, result["skipped"])

    def test_rejects_each_nonpassing_status(self):
        for status in ("skipped", "failure", "error"):
            with self.subTest(status=status):
                self.write(status=status)
                with self.assertRaises(ValueError):
                    GATE.verify(self.root)

    def test_rejects_missing_control(self):
        self.write(GATE.REQUIRED[:-1])
        with self.assertRaises(ValueError):
            GATE.verify(self.root)

    def test_rejects_duplicate_control(self):
        self.write(GATE.REQUIRED + GATE.REQUIRED[:1])
        with self.assertRaises(ValueError):
            GATE.verify(self.root)

    def test_rejects_renamed_control(self):
        self.write(GATE.REQUIRED[:-1] + ("synthetic JSON mount replacement",))
        with self.assertRaises(ValueError):
            GATE.verify(self.root)

    def test_rejects_other_class(self):
        self.write(classname="example.SyntheticMountTest")
        with self.assertRaises(ValueError):
            GATE.verify(self.root)

    def test_rejects_linked_report(self):
        target = self.root / "other.xml"
        target.write_text("<testsuite/>")
        self.path.symlink_to(target)
        with self.assertRaises(ValueError):
            GATE.verify(self.root)

    def test_rejects_missing_report(self):
        with self.assertRaises(ValueError):
            GATE.verify(self.root)

    def test_rejects_declaration(self):
        self.path.write_text('<!DOCTYPE testsuite [<!ENTITY extra "bad">]><testsuite/>')
        with self.assertRaises(ValueError):
            GATE.verify(self.root)

    def test_rejects_oversized_report(self):
        self.path.write_bytes(b" " * (1024 * 1024 + 1))
        with self.assertRaises(ValueError):
            GATE.verify(self.root)

    def test_required_methods_match_actual_kotlin_controls(self):
        import re
        source = ROOT / "src/test/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAdmissionMountedTest.kt"
        names = re.findall(r"@Test\s+fun `([^`]+)`", source.read_text())
        self.assertCountEqual(GATE.REQUIRED, names)


if __name__ == "__main__":
    unittest.main()
