"""Byte-compare independently materialized bounded shard runs."""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any
from oracle.bounded_shards import load_complete_shard_index
from oracle.full_tree_scope import canonical_json_bytes

class FullTreeDeterminismError(ValueError):
    """Raised when runs are incompatible or a report is malformed."""

def _sha(payload: bytes) -> str: return hashlib.sha256(payload).hexdigest()


def _content_contract(root: Path) -> tuple[str, int]:
    run = json.loads((root / "run.json").read_bytes())
    bounds = dict(run["bounds"])
    workers = bounds.pop("maximumWorkers")
    contract = {**run, "bounds": bounds}
    return _sha(canonical_json_bytes(contract)), workers

def compare_full_tree_runs(first_root: Path, second_root: Path) -> dict[str, Any]:
    first = load_complete_shard_index(first_root); second = load_complete_shard_index(second_root)
    first_contract, first_workers = _content_contract(first_root)
    second_contract, second_workers = _content_contract(second_root)
    if first_contract != second_contract:
        raise FullTreeDeterminismError("bounded runs have different authenticated content contracts")
    first_by_id = {item["shardId"]: item for item in first["shards"]}; second_by_id = {item["shardId"]: item for item in second["shards"]}
    if first_by_id.keys() != second_by_id.keys():
        raise FullTreeDeterminismError("bounded runs have different shard populations")
    differing = []
    for identifier in sorted(first_by_id):
        first_payload = (first_root / "outputs" / f"{identifier}.json").read_bytes(); second_payload = (second_root / "outputs" / f"{identifier}.json").read_bytes()
        if first_payload != second_payload: differing.append(identifier)
    without_hash = {
        "contentContractSha256": first_contract,
        "differingShards": differing,
        "firstIndexSha256": _sha((first_root / "index.json").read_bytes()),
        "firstRun": {"maximumWorkers": first_workers, "runSha256": first["runSha256"]},
        "identical": not differing,
        "schemaVersion": 2,
        "secondIndexSha256": _sha((second_root / "index.json").read_bytes()),
        "secondRun": {"maximumWorkers": second_workers, "runSha256": second["runSha256"]},
        "shards": len(first_by_id),
    }
    report = {**without_hash, "reportSha256": _sha(canonical_json_bytes(without_hash))}; validate_full_tree_determinism_report(report); return report

def validate_full_tree_determinism_report(report: dict[str, Any]) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]
        schema = json.loads(Path(__file__).with_name("full-tree-determinism-report.schema.json").read_text(encoding="utf-8")); fastjsonschema.compile(schema)(report)
    except Exception as error: raise FullTreeDeterminismError(f"determinism report fails schema validation: {error}") from error
    without_hash = {key: value for key, value in report.items() if key != "reportSha256"}
    if report["reportSha256"] != _sha(canonical_json_bytes(without_hash)) or report["identical"] != (not report["differingShards"]):
        raise FullTreeDeterminismError("determinism report does not reconcile")
