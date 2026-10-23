from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
import shutil
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROFILE = REPOSITORY_ROOT / "oracle/gcc/16.2.0"
# Keep tampered profile copies inside the repository's ignored build tree.
SCRATCH = REPOSITORY_ROOT / "build/test-scratch"

from oracle.gcc.report_accuracy_coverage import (  # noqa: E402
    CoverageError,
    build_report as build_coverage,
)
from oracle.gcc import report_function_starts, report_symbol_identity  # noqa: E402

COVERAGE_DOC = REPOSITORY_ROOT / "docs/gcc-oracle-accuracy-coverage.md"


class RetainedFunctionStartTest(unittest.TestCase):
    def setUp(self) -> None:
        self.report = json.loads(
            (PROFILE / "function-start-score.json").read_text(encoding="utf-8")
        )

    def test_report_retains_every_outcome(self) -> None:
        summary = self.report["summary"]
        self.assertEqual(summary["falsePositives"], len(self.report["falsePositives"]))
        self.assertEqual(summary["falseNegatives"], len(self.report["falseNegatives"]))
        self.assertEqual(summary["nearMisses"], len(self.report["nearMisses"]))
        self.assertEqual(
            summary["ignoredExcludedCount"],
            len(self.report["ignoredExcludedRecoveries"]),
        )
        self.assertFalse(self.report["productionVerified"])

    def test_accuracy_coverage_reports_measured_starts(self) -> None:
        dimension = build_coverage(PROFILE)["dimensions"]["functionStarts"]
        score = dimension["currentScore"]
        self.assertEqual(dimension["status"], "measured-not-release-eligible")
        self.assertEqual(score["status"], "measured")
        self.assertEqual(
            score["precision"],
            {"numerator": 3269, "denominator": 3273, "value": 0.998778},
        )
        self.assertEqual(
            score["recall"],
            {"numerator": 3269, "denominator": 3284, "value": 0.995432},
        )
        self.assertFalse(score["productionVerified"])
        self.assertFalse(score["releaseEligible"])

    def test_retained_coverage_report_is_current(self) -> None:
        retained = json.loads(
            (PROFILE / "accuracy-coverage.json").read_text(encoding="utf-8")
        )
        self.assertEqual(retained, build_coverage(PROFILE))


class TamperedFunctionStartTest(unittest.TestCase):
    def setUp(self) -> None:
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.profile = Path(self.directory.name) / "16.2.0"
        shutil.copytree(PROFILE, self.profile)
        self.path = self.profile / "function-start-score.json"
        self.report = json.loads(self.path.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.directory.cleanup()

    def _rewrite(self) -> None:
        self.path.write_text(json.dumps(self.report), encoding="utf-8")

    def test_missing_report_is_unavailable(self) -> None:
        self.path.unlink()
        dimension = build_coverage(self.profile)["dimensions"]["functionStarts"]
        self.assertEqual(dimension["currentScore"]["status"], "unavailable")
        self.assertEqual(dimension["status"], "oracle-covered-recovery-unavailable")

    def test_rejects_unscoreable_false_negative(self) -> None:
        self.report["falseNegatives"][0]["oracleRva"] = "0x1"
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "do not partition"):
            build_coverage(self.profile)

    def test_rejects_inflated_true_positives_without_outcome_lists(self) -> None:
        summary = self.report["summary"]
        summary["truePositives"] += len(self.report["falseNegatives"])
        summary["scoredRecoveredCount"] -= len(self.report["falsePositives"])
        summary["falseNegatives"] = summary["falsePositives"] = 0
        self.report["falseNegatives"] = []
        self.report["falsePositives"] = []
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "do not partition"):
            build_coverage(self.profile)

    def test_rejects_dropped_exact_match(self) -> None:
        del self.report["exactMatchRvas"][0]
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "do not partition"):
            build_coverage(self.profile)

    def test_rejects_duplicated_outcome(self) -> None:
        self.report["exactMatchRvas"].append(self.report["exactMatchRvas"][0])
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "do not partition"):
            build_coverage(self.profile)

    def test_rejects_missing_exact_match_list(self) -> None:
        del self.report["exactMatchRvas"]
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "must be arrays"):
            build_coverage(self.profile)

    def test_rejects_scoreable_false_positive(self) -> None:
        self.report["falsePositives"][0]["recoveredRva"] = self.report[
            "falseNegatives"
        ][0]["oracleRva"]
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "include scoreable oracle starts"):
            build_coverage(self.profile)

    def test_rejects_dropped_false_positive(self) -> None:
        del self.report["falsePositives"][-1]
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "summary disagrees"):
            build_coverage(self.profile)

    def test_rejects_inflated_ratio(self) -> None:
        self.report["summary"]["precision"]["value"] = 1.0
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

    def test_rejects_release_eligibility_claim(self) -> None:
        self.report["provenance"]["qualification"]["releaseEligible"] = True
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "must not claim release eligibility"):
            build_coverage(self.profile)


class DocumentedRegenerationCommandTest(unittest.TestCase):
    """The documented regeneration commands must parse with each reporter's CLI."""

    def test_documented_commands_parse(self) -> None:
        parsers = {
            "oracle/gcc/report_function_starts.py": report_function_starts.build_parser(),
            "oracle/gcc/report_symbol_identity.py": report_symbol_identity.build_parser(),
        }
        text = COVERAGE_DOC.read_text(encoding="utf-8")
        blocks = re.findall(r"```bash\n(.*?)```", text, flags=re.DOTALL)
        seen = set()
        commands = [
            shlex.split(line)
            for block in blocks
            for line in block.replace("\\\n", " ").splitlines()
            if line.strip()
        ]
        for argv in commands:
            if len(argv) < 2 or argv[0] != "python3" or argv[1] not in parsers:
                continue
            seen.add(argv[1])
            with self.subTest(script=argv[1]):
                try:
                    parsers[argv[1]].parse_args(argv[2:])
                except SystemExit:
                    self.fail(f"documented {argv[1]} command does not parse: {argv[2:]}")
        self.assertEqual(set(parsers), seen)


if __name__ == "__main__":
    unittest.main()
