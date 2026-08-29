"""Transparent per-shard baseline for authenticated full-tree call truth."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from oracle.full_tree_call_truth import validate_full_tree_call_truth_index
from oracle.full_tree_scope import canonical_json_bytes


class FullTreeCallBaselineError(ValueError):
    """Raised when a call baseline is malformed or regresses."""


POLICY = {
    "id": "full-tree-call-baseline",
    "version": 2,
    "exact": "resolved-direct-semantic-external-or-independently-proven-target-set",
    "partial": "observed-site-with-unresolved-indirect-or-thunk-semantic-target",
    "excluded": "unobservable-call-site",
}


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _configuration_sha256() -> str:
    schema = Path(__file__).with_name("full-tree-call-baseline.schema.json").read_bytes()
    return _sha(canonical_json_bytes(POLICY) + schema)


def _metric(exact: int, partial: int, missing: int, fabricated: int, excluded: int) -> dict[str, int]:
    return {
        "denominator": exact + partial + missing,
        "exact": exact,
        "excluded": excluded,
        "fabricated": fabricated,
        "missing": missing,
        "partial": partial,
    }


def generate_full_tree_call_baseline(
    truth_index: dict[str, Any],
    *,
    truth_root: Path,
    inventory: dict[str, Any],
) -> dict[str, Any]:
    validate_full_tree_call_truth_index(
        truth_index,
        output_root=truth_root,
        inventory=inventory,
    )
    shard_reports = []
    mismatches = []
    totals = {"exact": 0, "partial": 0, "missing": 0, "fabricated": 0, "excluded": 0}
    for shard_record in truth_index["shards"]:
        document = json.loads((truth_root / shard_record["path"]).read_bytes())
        counts = {"exact": 0, "partial": 0, "missing": 0, "fabricated": 0, "excluded": 0}
        for call in document["calls"]:
            if call["population"] == "unobservable":
                counts["excluded"] += 1
                continue
            if call["targetKind"] == "external" and call["externalTargetIds"]:
                kind = "exact"
            elif call["targetKind"] == "indirect-proven" and call["provenTargetIds"]:
                kind = "exact"
            elif call["targetKind"] == "direct-internal" and call["semanticTargetId"] is not None:
                kind = "exact"
            else:
                kind = "partial"
            counts[kind] += 1
            if kind != "exact":
                identity = _sha(canonical_json_bytes({"kind": kind, "truthId": call["id"]}))[:32]
                mismatches.append(
                    {
                        "id": f"{kind}-call-{identity}",
                        "kind": kind,
                        "reasonCode": call["reasonCode"],
                        "shardId": shard_record["id"],
                        "truthId": call["id"],
                    }
                )
        metric = _metric(**counts)
        shard_reports.append({"id": shard_record["id"], "metric": metric})
        for name in totals:
            totals[name] += counts[name]
    without_hash = {
        "aggregate": _metric(**totals),
        "configurationSha256": _configuration_sha256(),
        "mismatches": sorted(mismatches, key=lambda item: item["id"]),
        "schemaVersion": 1,
        "shards": shard_reports,
        "truthIndexSha256": _sha((truth_root / "index.json").read_bytes()),
    }
    report = {**without_hash, "reportSha256": _sha(canonical_json_bytes(without_hash))}
    validate_full_tree_call_baseline(report)
    return report


def validate_full_tree_call_baseline(report: dict[str, Any]) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]

        schema = json.loads(
            Path(__file__).with_name("full-tree-call-baseline.schema.json").read_text(encoding="utf-8")
        )
        fastjsonschema.compile(schema)(report)
    except Exception as error:
        raise FullTreeCallBaselineError(f"call baseline fails validation: {error}") from error
    if report["configurationSha256"] != _configuration_sha256():
        raise FullTreeCallBaselineError("call baseline configuration binding differs")
    without_hash = {key: value for key, value in report.items() if key != "reportSha256"}
    if report["reportSha256"] != _sha(canonical_json_bytes(without_hash)):
        raise FullTreeCallBaselineError("call baseline hash does not reconcile")
    if report["shards"] != sorted(report["shards"], key=lambda item: item["id"]):
        raise FullTreeCallBaselineError("call baseline shards are not ordered")
    if report["mismatches"] != sorted(report["mismatches"], key=lambda item: item["id"]):
        raise FullTreeCallBaselineError("call baseline mismatches are not ordered")
    if len({item["id"] for item in report["mismatches"]}) != len(report["mismatches"]):
        raise FullTreeCallBaselineError("call baseline mismatch identities are duplicated")
    totals = {"exact": 0, "partial": 0, "missing": 0, "fabricated": 0, "excluded": 0}
    for shard in report["shards"]:
        metric = shard["metric"]
        if metric["denominator"] != metric["exact"] + metric["partial"] + metric["missing"]:
            raise FullTreeCallBaselineError(f"call denominator differs for {shard['id']}")
        for name in totals:
            totals[name] += metric[name]
    if report["aggregate"] != _metric(**totals):
        raise FullTreeCallBaselineError("call baseline aggregate does not reconcile")


def require_no_call_baseline_regression(current: dict[str, Any], accepted: dict[str, Any]) -> None:
    validate_full_tree_call_baseline(current)
    validate_full_tree_call_baseline(accepted)
    current_shards = {item["id"]: item["metric"] for item in current["shards"]}
    accepted_shards = {item["id"]: item["metric"] for item in accepted["shards"]}
    if current_shards.keys() != accepted_shards.keys():
        raise FullTreeCallBaselineError("call baseline shard population drifted")
    for shard_id, baseline in accepted_shards.items():
        observed = current_shards[shard_id]
        if observed["denominator"] != baseline["denominator"]:
            raise FullTreeCallBaselineError(f"call denominator drifted for {shard_id}")
        if observed["exact"] < baseline["exact"] or observed["fabricated"] > baseline["fabricated"]:
            raise FullTreeCallBaselineError(f"call baseline regressed for {shard_id}")
