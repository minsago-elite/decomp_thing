from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.full_tree_release_evidence import (  # noqa: E402
    FullTreeReleaseEvidenceError,
    render_full_tree_release_summary,
    validate_full_tree_release_asset_lock,
    validate_full_tree_release_evidence,
)
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402


SHA = "a" * 64


def _hashed(value: dict, field: str) -> dict:
    return {**value, field: hashlib.sha256(canonical_json_bytes(value)).hexdigest()}


def _artifact(role: str) -> dict:
    return {"bytes": 1, "role": role, "sha256": SHA}


def _metric(**changes: int) -> dict:
    value = {"denominator": 1, "exact": 1, "excluded": 0, "fabricated": 0, "missing": 0, "partial": 0}
    value.update(changes)
    return value


class FullTreeReleaseEvidenceTest(unittest.TestCase):
    def test_checked_release_asset_lock_binds_machine_report_and_urls(self) -> None:
        profile = REPOSITORY_ROOT / "oracle/llvm/22.1.6"
        lock_payload = (profile / "full-tree-release-assets.json").read_bytes()
        lock = json.loads(lock_payload)
        self.assertEqual(canonical_json_bytes(lock), lock_payload)
        report_payload = (profile / "full-tree-release-evidence.json").read_bytes()
        validate_full_tree_release_asset_lock(lock, report_payload=report_payload)
        mutated = json.loads(json.dumps(lock))
        mutated["assets"][0]["bytes"] += 1
        with self.assertRaisesRegex(FullTreeReleaseEvidenceError, "machine report"):
            validate_full_tree_release_asset_lock(mutated, report_payload=report_payload)

    def _report(self) -> dict:
        observation_determinism = _hashed(
            {
                "contentContractSha256": SHA, "differingShards": [], "firstIndexSha256": SHA,
                "firstRun": {"maximumWorkers": 1, "runSha256": SHA}, "identical": True,
                "schemaVersion": 2, "secondIndexSha256": SHA,
                "secondRun": {"maximumWorkers": 2, "runSha256": "b" * 64}, "shards": 1,
            },
            "reportSha256",
        )
        truth_determinism = _hashed(
            {"differingFiles": [], "files": 2, "firstIndexSha256": SHA, "identical": True, "schemaVersion": 1, "secondIndexSha256": SHA},
            "reportSha256",
        )
        execution = {
            "artifact": _artifact("execution-evidence"), "bounds": {}, "evidenceSha256": SHA,
            "observed": {}, "runSha256": SHA,
        }
        observation_stage = {
            "counts": {"entities": 1}, "determinism": observation_determinism,
            "executions": [execution, execution],
            "indexes": [_artifact("fixture-observations-first"), _artifact("fixture-observations-second")],
        }
        truth_stage = {
            "counts": {"globals": 1}, "determinism": truth_determinism,
            "indexes": [_artifact("fixture-truth-first"), _artifact("fixture-truth-second")],
        }
        function_metric = {"denominator": 1, "excluded": 0, "fabricated": 0, "missing": 0, "recallDenominator": 1, "recallNumerator": 1, "recovered": 1}
        without_hash = {
            "artifacts": [_artifact(role) for role in ("call-truth-index", "data-elf-index", "data-reconciliation", "data-truth-index", "function-elf-index", "function-truth-index")],
            "baselines": {
                "calls": {"aggregate": _metric(), "artifact": _artifact("calls-baseline"), "reportSha256": SHA},
                "data": {"aggregate": {name: _metric() for name in ("abiObjects", "globals", "types")}, "artifact": _artifact("data-baseline"), "reportSha256": SHA},
                "functions": {"aggregate": function_metric, "artifact": _artifact("functions-baseline"), "reportSha256": SHA},
            },
            "complete": True,
            "inventory": {"compilationUnits": 1, "indexSha256": SHA, "shards": 1},
            "observations": {name: observation_stage for name in ("calls", "data", "functions")},
            "oracle": {"richArtifactSha256": SHA, "scopeSha256": SHA, "strippedArtifactSha256": SHA},
            "reconciliation": {"abiObjects": 1, "abiSlots": 1, "unexplainedEntities": 0},
            "schemaVersion": 1,
            "truth": {
                "calls": {**truth_stage, "counts": {"directInternal": 1, "edges": 1, "external": 0, "indirectUnresolved": 0}},
                "data": {**truth_stage, "counts": {"globals": 1, "types": 1}},
                "functions": {**truth_stage, "counts": {"inlineUnique": 1, "scoredRvas": 1}},
            },
        }
        return _hashed(without_hash, "reportSha256")

    def test_release_evidence_hashes_determinism_denominators_and_summary(self) -> None:
        report = self._report()
        validate_full_tree_release_evidence(report)
        summary = render_full_tree_release_summary(report)
        self.assertIn("zero unexplained entities", summary)
        self.assertIn(report["reportSha256"], summary)
        mutated = json.loads(json.dumps(report))
        mutated["reconciliation"]["unexplainedEntities"] = 1
        without_hash = {key: value for key, value in mutated.items() if key != "reportSha256"}
        mutated["reportSha256"] = hashlib.sha256(canonical_json_bytes(without_hash)).hexdigest()
        with self.assertRaisesRegex(FullTreeReleaseEvidenceError, "unexplained"):
            validate_full_tree_release_evidence(mutated)


if __name__ == "__main__":
    unittest.main()
