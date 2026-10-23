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


class RetainedCallEdgeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.report = json.loads(
            (PROFILE / "call-edge-score.json").read_text(encoding="utf-8")
        )

    def test_report_retains_every_outcome(self) -> None:
        summary = self.report["summary"]
        self.assertEqual(summary["referenceCount"], len(self.report["oracleEdges"]))
        self.assertEqual(summary["falsePositives"], len(self.report["fabricatedEdges"]))
        self.assertEqual(summary["falseNegatives"], len(self.report["missingEdges"]))
        self.assertFalse(self.report["productionVerified"])

    def test_accuracy_coverage_reports_measured_edges(self) -> None:
        dimension = build_coverage(PROFILE)["dimensions"]["callEdges"]
        score = dimension["currentScore"]
        self.assertEqual(dimension["status"], "measured-not-release-eligible")
        self.assertEqual(dimension["oracle"]["edgeCount"], 5860)
        self.assertEqual(
            score["precision"],
            {"numerator": 5780, "denominator": 6197, "value": 0.932709},
        )
        self.assertEqual(
            score["recall"],
            {"numerator": 5780, "denominator": 5860, "value": 0.986348},
        )
        self.assertFalse(score["productionVerified"])
        self.assertFalse(score["releaseEligible"])


class TamperedCallEdgeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.profile = Path(self.directory.name) / "16.2.0"
        shutil.copytree(PROFILE, self.profile)
        self.path = self.profile / "call-edge-score.json"
        self.report = json.loads(self.path.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.directory.cleanup()

    def _rewrite(self) -> None:
        self.path.write_text(json.dumps(self.report), encoding="utf-8")

    def test_missing_report_is_unavailable(self) -> None:
        self.path.unlink()
        dimension = build_coverage(self.profile)["dimensions"]["callEdges"]
        self.assertEqual(dimension["currentScore"]["status"], "unavailable")
        self.assertEqual(dimension["status"], "unavailable")
        self.assertEqual(dimension["oracle"]["status"], "unavailable")

    def test_rejects_unscoreable_endpoint(self) -> None:
        self.report["fabricatedEdges"][0]["calleeRva"] = "0x1"
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "not scoreable oracle functions"):
            build_coverage(self.profile)

    def test_rejects_missing_edge_outside_oracle(self) -> None:
        fabricated = self.report["fabricatedEdges"][0]
        self.report["missingEdges"][0].update(
            callerRva=fabricated["callerRva"], calleeRva=fabricated["calleeRva"]
        )
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "missing edges are not oracle edges"):
            build_coverage(self.profile)

    def test_rejects_fabricated_oracle_edge(self) -> None:
        edge = self.report["oracleEdges"][0]
        self.report["fabricatedEdges"][0].update(
            callerRva=edge["callerRva"], calleeRva=edge["calleeRva"]
        )
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "include oracle edges"):
            build_coverage(self.profile)

    def test_rejects_dropped_fabricated_edge(self) -> None:
        del self.report["fabricatedEdges"][-1]
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "summary disagrees"):
            build_coverage(self.profile)

    def test_rejects_hidden_tail_call(self) -> None:
        tail = next(edge for edge in self.report["oracleEdges"] if edge["tailCall"])
        tail["tailCall"] = False
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "summary disagrees"):
            build_coverage(self.profile)

    def test_rejects_inflated_ratio(self) -> None:
        self.report["summary"]["recall"]["value"] = 1.0
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "ratios disagree"):
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

    def test_rejects_foreign_full_artifact(self) -> None:
        self.report["provenance"]["fullArtifactSha256"] = "0" * 64
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "another full artifact"):
            build_coverage(self.profile)


if __name__ == "__main__":
    unittest.main()
