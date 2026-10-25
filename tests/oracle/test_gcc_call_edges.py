from __future__ import annotations

from dataclasses import replace
import hashlib
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

    def test_rejects_consistent_outcome_edit_not_backed_by_model(self) -> None:
        self.report["missingEdges"] = []
        self.report["fabricatedEdges"] = []
        summary = self.report["summary"]
        count = len(self.report["oracleEdges"])
        summary.update(truePositives=count, scoredRecoveredCount=count,
                       falseNegatives=0, falsePositives=0)
        ratio = {"numerator": count, "denominator": count, "value": 1.0}
        summary.update(precision=ratio, recall=ratio)
        unrestricted = count + len(self.report["callerWithoutCallSiteEdges"])
        summary["unrestricted"] = {
            "scoredRecoveredCount": unrestricted,
            "precision": {"numerator": count, "denominator": unrestricted,
                          "value": round(count / unrestricted, 6)},
            "recall": ratio,
        }
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "rescore of its retained recovered model"):
            build_coverage(self.profile)

    def test_report_evidence_uses_validated_snapshot_after_replacement(self) -> None:
        from oracle.gcc import report_call_edges

        payload = self.path.read_bytes()
        original = report_call_edges._oracle_edges

        def replace_report(*args, **kwargs):
            self.path.write_text("{}", encoding="utf-8")
            return original(*args, **kwargs)

        with mock.patch.object(report_call_edges, "_oracle_edges", replace_report):
            score = build_coverage(self.profile)["dimensions"]["callEdges"]["currentScore"]
        self.assertEqual(score["evidence"]["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(score["evidence"]["bytes"], len(payload))
        self.assertEqual(score["evidence"]["programModel"]["sha256"],
                         self.report["provenance"]["programModel"]["sha256"])

    def test_rejects_oversized_report_before_decoding(self) -> None:
        from oracle.function_recovery import MAX_REPORT_BYTES

        with self.path.open("r+b") as stream:
            stream.truncate(MAX_REPORT_BYTES + 1)
        with self.assertRaisesRegex(CoverageError, "call edge report exceeds"):
            build_coverage(self.profile)

    def test_call_edges_require_retained_model_independently_of_function_starts(self) -> None:
        (self.profile / "function-start-score.json").unlink()
        (self.profile / "stripped-recovered-program-model.json").unlink()
        with self.assertRaisesRegex(CoverageError, "call edge report has no retained recovered model"):
            build_coverage(self.profile)

    def _bound_model(self):
        from oracle.gcc.bound_recovered_model import load_bound_stripped_model

        return load_bound_stripped_model(
            self.profile,
            self.profile / "stripped-recovered-program-model.json",
            self.profile / "surviving-symbol-identity-binding.json",
            self.profile / "surviving-symbol-identity-qualification.json",
        )

    def test_rejects_grown_model_before_reopening_payload(self) -> None:
        from oracle.gcc.report_call_edges import _recovered_edges

        bound = self._bound_model()
        path = self.profile / "stripped-recovered-program-model.json"
        with path.open("r+b") as stream:
            stream.truncate(bound.model_record["bytes"] + 1)
        with self.assertRaisesRegex(CoverageError, "program model exceeds"):
            _recovered_edges(path, bound)

    def test_recovers_known_endpoints_from_validated_addresses(self) -> None:
        from oracle.gcc.report_call_edges import _recovered_edges

        bound = self._bound_model()
        caller = next(function for function in bound.model.functions
                      if function.rva == 0x3980)
        callee = next(function for function in bound.model.functions
                      if function.rva == 0xed570)
        # IDs are opaque model identities; changing a validated address must
        # change its recovered edge, even when the ID looks like an address.
        changed = replace(caller, rva=caller.rva + 1)
        model = replace(bound.model, functions=tuple(
            changed if function == caller else function
            for function in bound.model.functions
        ))
        edges = _recovered_edges(
            self.profile / "stripped-recovered-program-model.json",
            replace(bound, model=model),
        )
        self.assertIn((changed.rva, callee.rva), edges)
        self.assertNotIn((caller.rva, callee.rva), edges)

    def test_rejects_manifest_changed_after_model_binding(self) -> None:
        from oracle.gcc.report_call_edges import _full_artifact

        bound = self._bound_model()
        path = self.profile / "oracle-manifest.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(CoverageError, "manifest changed after model binding"):
            _full_artifact(self.profile, bound.provenance["artifactManifestSha256"])

    def test_bounds_reopened_manifest_before_decoding(self) -> None:
        from oracle.gcc import report_call_edges

        bound = self._bound_model()
        path = self.profile / "oracle-manifest.json"
        with path.open("r+b") as stream:
            stream.truncate(4097)
        with mock.patch.object(report_call_edges, "MAX_MANIFEST_BYTES", 4096):
            with self.assertRaisesRegex(CoverageError, "oracle artifact manifest exceeds"):
                report_call_edges._full_artifact(
                    self.profile, bound.provenance["artifactManifestSha256"]
                )

    def test_bounds_generated_report_before_outcome_materialization(self) -> None:
        from collections import Counter
        from oracle.gcc import report_call_edges

        # One independently supplied oracle edge is enough to exercise the
        # projection guard; decoder behavior is covered by the retained test.
        with mock.patch.object(report_call_edges, "MAX_REPORT_BYTES", 1024), \
             mock.patch.object(report_call_edges, "_oracle_edges", return_value=(
                 {(0x3980, 0xed570): {False}}, {0x3980}, Counter()
             )):
            with self.assertRaisesRegex(CoverageError, "projected output byte limit"):
                report_call_edges.build_report(
                    self.profile,
                    self.profile / "stripped-recovered-program-model.json",
                    self.profile / "surviving-symbol-identity-binding.json",
                    self.profile / "surviving-symbol-identity-qualification.json",
                )

    def test_projection_charges_escaped_provenance(self) -> None:
        from collections import Counter
        from oracle.gcc import report_call_edges

        bound = self._bound_model()
        provenance = json.loads(json.dumps(bound.provenance))
        provenance["qualification"]["limitation"] = "\u265e" * 12000
        with mock.patch.object(report_call_edges, "MAX_REPORT_BYTES", 32 * 1024), \
             mock.patch.object(report_call_edges, "load_bound_stripped_model",
                               return_value=replace(bound, provenance=provenance)), \
             mock.patch.object(report_call_edges, "_recovered_edges", return_value=set()), \
             mock.patch.object(report_call_edges, "_oracle_edges",
                               return_value=({}, set(), Counter())):
            with self.assertRaisesRegex(CoverageError, "projected output byte limit"):
                report_call_edges.build_report(
                    self.profile,
                    self.profile / "stripped-recovered-program-model.json",
                    self.profile / "surviving-symbol-identity-binding.json",
                    self.profile / "surviving-symbol-identity-qualification.json",
                )

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
        with self.assertRaisesRegex(CoverageError, "rescore of its retained recovered model"):
            build_coverage(self.profile)

    def test_rejects_altered_call_site_kinds(self) -> None:
        kinds = self.report["oracle"]["callSiteKinds"]
        kind = next(iter(kinds))
        kinds[kind] += 1
        self._rewrite()
        with self.assertRaisesRegex(CoverageError, "rescore of its retained recovered model"):
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
