#!/usr/bin/env python3
"""Authored controls for the narrow configured execution inventory check."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("interface_inventory", ROOT / "scripts/verify-gcc-interface-qualification.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class InterfaceQualificationInventoryTest(unittest.TestCase):
    def setUp(self):
        base = ROOT / "build/interface-qualification-inventory-controls"
        base.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temp.cleanup)
        self.report = Path(self.temp.name) / "report.xml"

    def xml(self, *, name=module.METHOD, tests="1", failures="0", errors="0", skips="0", child="", extra=""):
        return (f'<testsuite name="{module.CLASS}" tests="{tests}" failures="{failures}" errors="{errors}" skipped="{skips}">'
                f'<testcase classname="{module.CLASS}" name="{name}">{child}</testcase>{extra}</testsuite>')

    def check(self, text, success=False, exit_code=0):
        self.report.write_text(text)
        observed = module.inspect(self.report, exit_code)
        self.assertEqual(success, observed["executionVerified"])
        self.assertFalse(observed["productionInterfacesAdmitted"])
        self.assertFalse(observed["releaseEligible"])
        return observed

    def test_exact_selected_method(self):
        result = self.check(self.xml(), True)
        self.assertEqual(1, result["executedMethods"])
        self.assertEqual(64, len(result["reportSha256"]))

    def test_skip_even_when_counts_are_forged_zero(self):
        self.check(self.xml(child="<skipped/>"))
        self.check(self.xml(skips="1", child="<skipped/>"))

    def test_wrong_missing_and_duplicate_inventory(self):
        self.check(self.xml(name="different()"))
        self.check(self.xml(tests="0"))
        self.check(self.xml(extra=f'<testcase classname="{module.CLASS}" name="{module.METHOD}"/>'))
        self.check(self.xml().replace("testcase", "not-testcase"))

    def test_failures_errors_or_gradle_failure(self):
        self.check(self.xml(failures="1", child="<failure/>"))
        self.check(self.xml(child="<error/>"))
        self.check(self.xml(), exit_code=1)

    def test_missing_symlink_and_nonregular(self):
        self.assertFalse(module.inspect(self.report, 0)["executionVerified"])
        target = self.report.with_name("target.xml")
        target.write_text(self.xml())
        self.report.symlink_to(target)
        self.assertFalse(module.inspect(self.report, 0)["executionVerified"])
        self.report.unlink()
        self.report.mkdir()
        self.assertFalse(module.inspect(self.report, 0)["executionVerified"])

    def test_bound_malformed_and_entities(self):
        self.check("x" * (module.MAXIMUM_REPORT_BYTES + 1))
        self.check("<testsuite")
        self.check('<!DOCTYPE testsuite [<!ENTITY a "x">]>' + self.xml())


if __name__ == "__main__":
    unittest.main()
