from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
import shutil
import tempfile
import unittest
from unittest import mock


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


    def test_report_is_compared_and_recorded_from_one_read(self) -> None:
        import oracle.gcc.report_accuracy_coverage as coverage

        report_path = PROFILE / "function-start-score.json"
        reads = []
        original = coverage._read_regular

        def counting_read(path, label, limit=None):
            if Path(path) == report_path:
                reads.append(path)
            return original(path, label, limit)

        with mock.patch.object(coverage, "_read_regular", counting_read):
            build_coverage(PROFILE)
        self.assertEqual(len(reads), 1)


    def test_evidence_records_the_validated_snapshots(self) -> None:
        import oracle.function_recovery as recovery
        import oracle.gcc.report_accuracy_coverage as coverage

        retained = {
            PROFILE / name: 0
            for name in (
                "stripped-recovered-program-model.json",
                "surviving-symbol-identity-binding.json",
                "surviving-symbol-identity-qualification.json",
            )
        }
        coverage_read = coverage._read_regular
        recovery_read = recovery._read_regular_snapshot

        def counting(original):
            def read(path, *args, **kwargs):
                if Path(path) in retained:
                    retained[Path(path)] += 1
                return original(path, *args, **kwargs)

            return read

        # The identity dimension reads the same binding and qualification, so
        # stub it out to count only the function-start reads.
        unavailable = {
            "status": "unavailable",
            "reasonCode": "stub",
            "productionVerified": False,
        }
        with mock.patch.object(
            coverage, "_read_regular", counting(coverage_read)
        ), mock.patch.object(
            recovery, "_read_regular_snapshot", counting(recovery_read)
        ), mock.patch.object(
            coverage, "_symbol_identity_score", return_value=unavailable
        ):
            build_coverage(PROFILE)
        # Each record is read once, for validation, and recorded from that read.
        self.assertEqual(set(retained.values()), {1})


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

    def test_rejects_consistent_outcome_edit_not_backed_by_model(self) -> None:
        # Promote a missed start to an exact match and drop a false positive,
        # recomputing every count and ratio so the outcomes stay consistent.
        missed = self.report["falseNegatives"].pop(0)["oracleRva"]
        self.report["exactMatchRvas"] = sorted(
            [*self.report["exactMatchRvas"], missed], key=lambda rva: int(rva, 16)
        )
        del self.report["falsePositives"][-1]
        summary = self.report["summary"]
        summary["exactMatches"] += 1
        summary["truePositives"] += 1
        summary["falseNegatives"] -= 1
        summary["falsePositives"] -= 1
        true_positives = summary["truePositives"]
        for key, denominator in (
            ("precision", summary["scoredRecoveredCount"]),
            ("recall", summary["referenceCount"]),
        ):
            summary[key] = {
                "numerator": true_positives,
                "denominator": denominator,
                "value": round(true_positives / denominator, 6),
            }
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "rescore of its retained recovered model"):
            build_coverage(self.profile)

    def test_rejects_missing_retained_model(self) -> None:
        (self.profile / "stripped-recovered-program-model.json").unlink()
        with self.assertRaisesRegex(CoverageError, "no retained recovered model"):
            build_coverage(self.profile)

    def test_rejects_substituted_retained_model(self) -> None:
        model_path = self.profile / "stripped-recovered-program-model.json"
        model = json.loads(model_path.read_text(encoding="utf-8"))
        model["functions"].pop()
        model_path.write_text(json.dumps(model), encoding="utf-8")
        with self.assertRaisesRegex(CoverageError, "program model rejected"):
            build_coverage(self.profile)

    def test_rejects_oversized_report_before_decoding(self) -> None:
        from oracle.function_recovery import MAX_REPORT_BYTES

        with self.path.open("r+b") as stream:
            stream.truncate(MAX_REPORT_BYTES + 1)
        # Rejected from the file size, before the payload is read or decoded.
        with self.assertRaisesRegex(CoverageError, "function start report exceeds"):
            build_coverage(self.profile)

    def test_rejects_model_length_disagreeing_with_binding(self) -> None:
        # The digest still matches, so only the bound length can catch this.
        for name, field in (
            ("surviving-symbol-identity-binding.json", ("programModel", "bytes")),
            ("surviving-symbol-identity-qualification.json", ("programModelBytes",)),
        ):
            path = self.profile / name
            record = json.loads(path.read_text(encoding="utf-8"))
            target = record
            for key in field[:-1]:
                target = target[key]
            target[field[-1]] += 1
            path.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaisesRegex(CoverageError, "bound byte length"):
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
