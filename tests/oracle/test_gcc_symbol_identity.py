from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROFILE = REPOSITORY_ROOT / "oracle/gcc/16.2.0"

from oracle.gcc.report_accuracy_coverage import (  # noqa: E402
    CoverageError,
    build_report as build_coverage,
)
from oracle.gcc.report_symbol_identity import enumerate_population  # noqa: E402


class RetainedSymbolIdentityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.report = json.loads(
            (PROFILE / "surviving-symbol-identity.json").read_text(encoding="utf-8")
        )

    def test_report_covers_exactly_the_oracle_population(self) -> None:
        population = enumerate_population(PROFILE / "function-recovery-oracle.json")
        self.assertEqual(
            [(item["name"], hex(item["rva"])) for item in population],
            [(item["name"], item["rva"]) for item in self.report["symbols"]],
        )
        self.assertEqual(self.report["summary"]["population"], len(population))
        self.assertFalse(self.report["productionVerified"])

    def test_accuracy_coverage_reports_measured_identity(self) -> None:
        dimension = build_coverage(PROFILE)["dimensions"]["survivingSymbolIdentity"]
        score = dimension["currentScore"]
        self.assertEqual(dimension["status"], "measured-not-release-eligible")
        self.assertEqual(score["status"], "measured")
        self.assertEqual(
            score["identityRecovery"], {"numerator": 6, "denominator": 6, "value": 1.0}
        )
        self.assertFalse(score["productionVerified"])
        self.assertFalse(score["releaseEligible"])

    def test_retained_coverage_report_is_current(self) -> None:
        retained = json.loads(
            (PROFILE / "accuracy-coverage.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            retained["dimensions"]["survivingSymbolIdentity"],
            build_coverage(PROFILE)["dimensions"]["survivingSymbolIdentity"],
        )


class TamperedSymbolIdentityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.profile = Path(self.directory.name) / "16.2.0"
        shutil.copytree(PROFILE, self.profile)
        self.path = self.profile / "surviving-symbol-identity.json"
        self.report = json.loads(self.path.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.directory.cleanup()

    def _rewrite(self) -> None:
        self.path.write_text(json.dumps(self.report), encoding="utf-8")

    def test_missing_report_is_unavailable(self) -> None:
        self.path.unlink()
        dimension = build_coverage(self.profile)["dimensions"]["survivingSymbolIdentity"]
        self.assertEqual(dimension["currentScore"]["status"], "unavailable")
        self.assertEqual(
            dimension["status"], "oracle-population-known-recovery-unavailable"
        )

    def test_rejects_altered_population(self) -> None:
        self.report["symbols"][0]["rva"] = "0x1"
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "population differs"):
            build_coverage(self.profile)

    def test_rejects_dropped_symbol(self) -> None:
        del self.report["symbols"][-1]
        self._rewrite()
        with self.assertRaises(CoverageError):
            build_coverage(self.profile)

    def test_rejects_inflated_summary(self) -> None:
        self.report["symbols"][0]["outcome"] = "missing"
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "summary disagrees"):
            build_coverage(self.profile)

    def test_rejects_foreign_manifest(self) -> None:
        self.report["provenance"]["artifactManifestSha256"] = "0" * 64
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "another manifest"):
            build_coverage(self.profile)

    def test_rejects_foreign_input(self) -> None:
        self.report["provenance"]["strippedInputSha256"] = "0" * 64
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "another input"):
            build_coverage(self.profile)


if __name__ == "__main__":
    unittest.main()
