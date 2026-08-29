"""Transparent per-subsystem baseline for surviving stripped function evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from oracle.full_tree_function_truth import validate_full_tree_function_truth_index
from oracle.full_tree_scope import canonical_json_bytes


class FullTreeFunctionBaselineError(ValueError):
    """Raised when baseline inputs or regression comparisons are inconsistent."""


POLICY = {
    "id": "full-tree-function-baseline",
    "version": 1,
    "recovered": "truth-alias-has-authenticated-stripped-elf-symbol-evidence",
    "denominator": "scored-function-rvas",
    "excluded": "dwarf-only-owned-plus-elf-only-unowned-rvas",
}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _configuration_sha256() -> str:
    schema = Path(__file__).with_name("full-tree-function-baseline.schema.json").read_bytes()
    return _sha256(canonical_json_bytes(POLICY) + schema)


def _metric(recovered: int, missing: int, fabricated: int, excluded: int) -> dict[str, int]:
    return {
        "denominator": recovered + missing,
        "excluded": excluded,
        "fabricated": fabricated,
        "missing": missing,
        "recallDenominator": recovered + missing,
        "recallNumerator": recovered,
        "recovered": recovered,
    }


def _mismatch(kind: str, truth_id: str, shard_id: str | None) -> dict[str, Any]:
    identity = _sha256(canonical_json_bytes({"kind": kind, "truthId": truth_id}))[:32]
    return {
        "id": f"{kind}-function-{identity}",
        "kind": kind,
        "shardId": shard_id,
        "truthId": truth_id,
    }


def generate_full_tree_function_baseline(
    truth_index: dict[str, Any],
    *,
    truth_root: Path,
    scope: dict[str, Any],
    scope_sha256: str,
    inventory: dict[str, Any],
) -> dict[str, Any]:
    validate_full_tree_function_truth_index(
        truth_index,
        output_root=truth_root,
        scope=scope,
        scope_sha256=scope_sha256,
        inventory=inventory,
        observation_index_sha256=truth_index["oracle"]["observationIndexSha256"],
        elf_index_sha256=truth_index["oracle"]["elfIndexSha256"],
    )
    shard_reports = []
    mismatches = []
    aggregate = {"recovered": 0, "missing": 0, "fabricated": 0, "excluded": 0}
    for shard_record in truth_index["shards"]:
        document = json.loads((truth_root / shard_record["path"]).read_text(encoding="utf-8"))
        recovered = 0
        missing = 0
        excluded = 0
        for function in document["functions"]:
            if function["population"] != "scored":
                excluded += 1
                continue
            surviving = any(
                evidence["kind"] == "elf-symbol" and evidence["locator"].startswith("stripped:")
                for alias in function["aliases"]
                for evidence in alias["evidence"]
            )
            if surviving:
                recovered += 1
            else:
                missing += 1
                mismatches.append(_mismatch("missing", function["id"], shard_record["id"]))
        metric = _metric(recovered, missing, 0, excluded)
        shard_reports.append({"id": shard_record["id"], "metric": metric})
        for name in aggregate:
            aggregate[name] += metric[name]
    aggregate["excluded"] += truth_index["counts"]["elfOnlyRvas"]
    shard_reports.append(
        {
            "id": "elf-only-exclusions",
            "metric": _metric(0, 0, 0, truth_index["counts"]["elfOnlyRvas"]),
        }
    )
    shard_reports.sort(key=lambda item: item["id"])
    report_without_hash = {
        "aggregate": _metric(**aggregate),
        "configurationSha256": _configuration_sha256(),
        "mismatches": sorted(mismatches, key=lambda item: item["id"]),
        "schemaVersion": 1,
        "shards": shard_reports,
        "truthIndexSha256": _sha256((truth_root / "index.json").read_bytes()),
    }
    report = {
        **report_without_hash,
        "reportSha256": _sha256(canonical_json_bytes(report_without_hash)),
    }
    validate_full_tree_function_baseline(report)
    return report


def validate_full_tree_function_baseline(report: dict[str, Any]) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]
        schema = json.loads(Path(__file__).with_name("full-tree-function-baseline.schema.json").read_text(encoding="utf-8"))
        fastjsonschema.compile(schema)(report)
    except (ModuleNotFoundError, OSError, json.JSONDecodeError) as error:
        raise FullTreeFunctionBaselineError(f"cannot validate function baseline: {error}") from error
    except fastjsonschema.JsonSchemaException as error:
        raise FullTreeFunctionBaselineError(f"function baseline fails JSON Schema: {error}") from error
    if report["configurationSha256"] != _configuration_sha256():
        raise FullTreeFunctionBaselineError("function baseline configuration binding differs")
    without_hash = {key: value for key, value in report.items() if key != "reportSha256"}
    if report["reportSha256"] != _sha256(canonical_json_bytes(without_hash)):
        raise FullTreeFunctionBaselineError("function baseline report hash does not reconcile")
    if report["shards"] != sorted(report["shards"], key=lambda item: item["id"]):
        raise FullTreeFunctionBaselineError("function baseline shards are not ordered")
    if report["mismatches"] != sorted(report["mismatches"], key=lambda item: item["id"]):
        raise FullTreeFunctionBaselineError("function baseline mismatches are not ordered")
    if len({item["id"] for item in report["mismatches"]}) != len(report["mismatches"]):
        raise FullTreeFunctionBaselineError("function baseline mismatch IDs are duplicated")
    metrics = [item["metric"] for item in report["shards"]]
    expected = _metric(
        recovered=sum(item["recovered"] for item in metrics),
        missing=sum(item["missing"] for item in metrics),
        fabricated=sum(item["fabricated"] for item in metrics),
        excluded=sum(item["excluded"] for item in metrics),
    )
    if report["aggregate"] != expected:
        raise FullTreeFunctionBaselineError("function baseline aggregate does not reconcile")


def require_no_function_baseline_regression(current: dict[str, Any], accepted: dict[str, Any]) -> None:
    validate_full_tree_function_baseline(current)
    validate_full_tree_function_baseline(accepted)
    accepted_by_shard = {item["id"]: item["metric"] for item in accepted["shards"]}
    current_by_shard = {item["id"]: item["metric"] for item in current["shards"]}
    if current_by_shard.keys() != accepted_by_shard.keys():
        raise FullTreeFunctionBaselineError("function baseline shard population drifted")
    for shard_id, baseline in accepted_by_shard.items():
        observed = current_by_shard[shard_id]
        if observed["denominator"] != baseline["denominator"]:
            raise FullTreeFunctionBaselineError(f"function denominator drifted for {shard_id}")
        if observed["recovered"] < baseline["recovered"] or observed["fabricated"] > baseline["fabricated"]:
            raise FullTreeFunctionBaselineError(f"function baseline regressed for {shard_id}")
