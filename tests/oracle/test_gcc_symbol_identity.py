from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROFILE = REPOSITORY_ROOT / "oracle/gcc/16.2.0"
FIXTURES = REPOSITORY_ROOT / "tests/oracle/fixtures/gcc-bound-model"
# Keep tampered profile copies inside the repository's ignored build tree.
SCRATCH = REPOSITORY_ROOT / "build/test-scratch"

from oracle.function_recovery import (  # noqa: E402
    ScoringError,
    load_function_oracle,
    load_program_model,
)
from oracle.gcc.bound_recovered_model import (  # noqa: E402
    TWIN,
    verify_binding,
    verify_qualification,
)
from oracle.gcc.report_accuracy_coverage import (  # noqa: E402
    CoverageError,
    build_report as build_coverage,
)
from oracle.gcc.report_symbol_identity import enumerate_population  # noqa: E402


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class BoundModelRecordTest(unittest.TestCase):
    def setUp(self) -> None:
        self.binding = _fixture("structural-full-export-binding.json")
        self.qualification = _fixture("qualification.json")

    def test_accepts_captured_records(self) -> None:
        verify_binding(self.binding)
        verify_qualification(self.qualification, self.binding)

    def test_rejects_unknown_binding_key(self) -> None:
        self.binding["admitted"] = True
        with self.assertRaisesRegex(CoverageError, "closed schema"):
            verify_binding(self.binding)

    def test_rejects_unknown_lineage_key(self) -> None:
        self.binding["receiptLineage"]["extra"] = "0" * 64
        with self.assertRaisesRegex(CoverageError, "closed schema"):
            verify_binding(self.binding)

    def test_rejects_v1_binding(self) -> None:
        self.binding["schemaVersion"] = 1
        with self.assertRaisesRegex(CoverageError, "schemaVersion"):
            verify_binding(self.binding)

    def test_rejects_malformed_digest(self) -> None:
        self.binding["outputTreeSha256"] = "ABC"
        with self.assertRaisesRegex(CoverageError, "SHA-256"):
            verify_binding(self.binding)

    def test_rejects_foreign_target(self) -> None:
        self.binding["targetDescriptor"]["machine"] = 3
        with self.assertRaisesRegex(CoverageError, "targetDescriptor.machine"):
            verify_binding(self.binding)

    def test_rejects_partial_export(self) -> None:
        self.binding["exporter"]["recoveryMode"] = "fast"
        with self.assertRaisesRegex(CoverageError, "full export"):
            verify_binding(self.binding)

    def test_rejects_release_eligible_qualification(self) -> None:
        self.qualification["releaseEligible"] = True
        with self.assertRaisesRegex(CoverageError, "releaseEligible must be false"):
            verify_qualification(self.qualification, self.binding)

    def test_rejects_qualification_for_another_model(self) -> None:
        self.qualification["programModelSha256"] = "0" * 64
        with self.assertRaisesRegex(CoverageError, "program models disagree"):
            verify_qualification(self.qualification, self.binding)

    def test_rejects_qualification_for_another_operation(self) -> None:
        self.qualification["operationId"] = "0" * 64
        with self.assertRaisesRegex(CoverageError, "operation disagrees"):
            verify_qualification(self.qualification, self.binding)

    def test_rejects_model_snapshot_that_differs_from_binding(self) -> None:
        artifact = load_function_oracle(
            PROFILE / "function-recovery-oracle.json"
        ).artifacts[TWIN]
        SCRATCH.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            path = Path(directory) / "program_model.json"
            path.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ScoringError, "bound SHA-256"):
                load_program_model(
                    path,
                    twin=TWIN,
                    artifact=artifact,
                    model_image_base=artifact.elf_image_base,
                    expected_sha256="0" * 64,
                )


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
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=SCRATCH)
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
        self.report["summary"]["exact"] += 1
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "summary disagrees"):
            build_coverage(self.profile)

    def test_rejects_shifted_failure_counts(self) -> None:
        self.report["summary"]["missing"] += 1
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "summary disagrees"):
            build_coverage(self.profile)

    def test_rejects_mislabeled_outcome(self) -> None:
        symbol = self.report["symbols"][0]
        symbol["recoveredName"] = symbol["name"] + "_other"
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "symbol is malformed"):
            build_coverage(self.profile)

    def test_rejects_missing_symbol_with_status(self) -> None:
        symbol = self.report["symbols"][0]
        symbol["outcome"] = "missing"
        symbol["recoveredName"] = None
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "symbol is malformed"):
            build_coverage(self.profile)

    def test_rejects_release_eligibility_claim(self) -> None:
        self.report["provenance"]["qualification"]["releaseEligible"] = True
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "release eligibility"):
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
