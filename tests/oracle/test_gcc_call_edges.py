from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import elftools

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

    def test_documented_command_uses_supported_options(self) -> None:
        document = (
            REPOSITORY_ROOT / "docs/gcc-oracle-accuracy-coverage.md"
        ).read_text(encoding="utf-8")
        command = re.search(
            r"python3 oracle/gcc/report_call_edges\.py(.*?)```", document, re.S
        )
        self.assertIsNotNone(command)
        documented = set(re.findall(r"--[a-z][a-z-]*", command.group(1)))
        usage = subprocess.run(
            [sys.executable, "oracle/gcc/report_call_edges.py", "--help"],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            check=True,
            text=True,
        ).stdout
        supported = set(re.findall(r"--[a-z][a-z-]*", usage))
        self.assertTrue(documented)
        self.assertLessEqual(documented, supported)


class TamperedCallEdgeTest(unittest.TestCase):
    def setUp(self) -> None:
        parent = REPOSITORY_ROOT / "build/python-test-tmp"
        parent.mkdir(exist_ok=True, parents=True)
        self.directory = tempfile.TemporaryDirectory(
            prefix="gcc-call-edges-", dir=parent
        )
        self.profile = Path(self.directory.name) / "16.2.0"
        shutil.copytree(PROFILE, self.profile)
        self.path = self.profile / "call-edge-score.json"
        self.report = json.loads(self.path.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.directory.cleanup()

    def _rewrite(self) -> None:
        self.path.write_text(json.dumps(self.report), encoding="utf-8")

    def test_fixture_stays_inside_repository(self) -> None:
        self.assertTrue(self.profile.resolve().is_relative_to(REPOSITORY_ROOT))

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

    def test_rejects_swapped_tail_call(self) -> None:
        edges = self.report["oracleEdges"]
        tail = next(edge for edge in edges if edge["tailCall"])
        plain = next(edge for edge in edges if not edge["tailCall"])
        tail["tailCall"], plain["tailCall"] = False, True
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "disagrees with the full artifact DWARF"):
            build_coverage(self.profile)

    def test_rejects_altered_call_site_kinds(self) -> None:
        kinds = self.report["oracle"]["callSiteKinds"]
        kind = next(iter(kinds))
        kinds[kind] += 1
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "disagrees with the full artifact DWARF"):
            build_coverage(self.profile)

    def test_rejects_release_eligibility_claim(self) -> None:
        self.report["provenance"]["qualification"]["releaseEligible"] = True
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "must not claim release eligibility"):
            build_coverage(self.profile)

    def test_rejects_unpinned_decoder(self) -> None:
        with mock.patch.object(elftools, "__version__", "0.0"):
            with self.assertRaisesRegex(CoverageError, "requires pyelftools"):
                build_coverage(self.profile)

    def test_rejects_inflated_ratio(self) -> None:
        self.report["summary"]["recall"]["value"] = 1.0
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "ratios disagree"):
            build_coverage(self.profile)

    def test_rejects_inflated_unrestricted_precision(self) -> None:
        self.report["summary"]["unrestricted"]["precision"]["value"] = 1.0
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "unrestricted summary disagrees"):
            build_coverage(self.profile)

    def test_rejects_dropped_unscored_edge(self) -> None:
        del self.report["callerWithoutCallSiteEdges"][-1]
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "unrestricted summary disagrees"):
            build_coverage(self.profile)

    def test_rejects_unscored_edge_from_caller_with_call_sites(self) -> None:
        edge = self.report["oracleEdges"][0]
        self.report["callerWithoutCallSiteEdges"][0].update(
            callerRva=edge["callerRva"], calleeRva=edge["calleeRva"]
        )
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "caller with call sites"):
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
