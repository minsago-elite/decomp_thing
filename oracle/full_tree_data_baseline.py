"""Per-shard baselines for global, type-layout, and ABI-object truth."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from oracle.full_tree_data_reconciliation import validate_full_tree_data_reconciliation
from oracle.full_tree_data_truth import validate_full_tree_data_truth_index
from oracle.full_tree_scope import canonical_json_bytes


class FullTreeDataBaselineError(ValueError):
    """Raised when data baselines are malformed or regress."""


POLICY = {
    "id": "full-tree-data-baseline",
    "version": 1,
    "globalExact": "dwarf-elf-reconciled",
    "globalPartial": "authenticated-elf-only",
    "typeExact": "complete-dwarf-layout",
    "abiExact": "all-authenticated-slots-resolved-or-no-pointer-slots",
}
DIMENSIONS = ("abiObjects", "globals", "types")


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _configuration_sha256() -> str:
    schema = Path(__file__).with_name("full-tree-data-baseline.schema.json").read_bytes()
    return _sha(canonical_json_bytes(POLICY) + schema)


def _metric(
    *, exact: int = 0, partial: int = 0, missing: int = 0,
    fabricated: int = 0, excluded: int = 0,
) -> dict[str, int]:
    return {
        "denominator": exact + partial + missing,
        "exact": exact,
        "excluded": excluded,
        "fabricated": fabricated,
        "missing": missing,
        "partial": partial,
    }


def _empty_counts() -> dict[str, dict[str, int]]:
    return {
        dimension: {name: 0 for name in ("exact", "partial", "missing", "fabricated", "excluded")}
        for dimension in DIMENSIONS
    }


def _mismatch(
    *, dimension: str, kind: str, truth_id: str, shard_id: str, reason_code: str
) -> dict[str, str]:
    singular = "abi-object" if dimension == "abiObjects" else "global"
    identity = _sha(canonical_json_bytes({"dimension": dimension, "kind": kind, "truthId": truth_id}))[:32]
    return {
        "dimension": dimension,
        "id": f"{kind}-{singular}-{identity}",
        "kind": kind,
        "reasonCode": reason_code,
        "shardId": shard_id,
        "truthId": truth_id,
    }


def generate_full_tree_data_baseline(
    *,
    data_truth_root: Path,
    reconciliation_report_path: Path,
    inventory: dict[str, Any],
    scope_sha256: str,
) -> dict[str, Any]:
    data_payload = (data_truth_root / "index.json").read_bytes()
    data_index = json.loads(data_payload)
    validate_full_tree_data_truth_index(
        data_index,
        output_root=data_truth_root,
        scope_sha256=scope_sha256,
        inventory=inventory,
    )
    reconciliation_payload = reconciliation_report_path.read_bytes()
    reconciliation = json.loads(reconciliation_payload)
    validate_full_tree_data_reconciliation(
        reconciliation,
        data_truth_index_sha256=_sha(data_payload),
        elf_data_index_sha256=reconciliation["oracle"]["elfDataIndexSha256"],
        inventory=inventory,
        scope_sha256=scope_sha256,
    )

    counts_by_shard = {shard["id"]: _empty_counts() for shard in inventory["shards"]}
    counts_by_shard["elf-only"] = _empty_counts()
    mismatches = []
    matched_dwarf_global_ids = {
        truth_id
        for item in reconciliation["globals"]
        for truth_id in item["dwarfTruthIds"]
    }
    for shard_record in data_index["shards"]:
        document = json.loads((data_truth_root / shard_record["path"]).read_bytes())
        counts = counts_by_shard[shard_record["id"]]
        for item in document["globals"]:
            if item["population"] == "unobservable" and item["id"] not in matched_dwarf_global_ids:
                counts["globals"]["excluded"] += 1
        for item in document["types"]:
            outcome = "exact" if item["population"] == "scored" else "excluded"
            counts["types"][outcome] += 1

    for item in reconciliation["globals"]:
        owner = item["ownerShardIds"][0]
        if item["reconciliation"] == "elf-only":
            counts_by_shard[owner]["globals"]["partial"] += 1
            mismatches.append(
                _mismatch(
                    dimension="globals",
                    kind="partial",
                    truth_id=item["elfGlobalId"],
                    shard_id=owner,
                    reason_code="elf-object-without-dwarf-owner",
                )
            )
        else:
            counts_by_shard[owner]["globals"]["exact"] += 1
    for item in reconciliation["dwarfOnlyScoredGlobals"]:
        owner = item["shardId"]
        counts_by_shard[owner]["globals"]["missing"] += 1
        mismatches.append(
            _mismatch(
                dimension="globals",
                kind="missing",
                truth_id=item["truthId"],
                shard_id=owner,
                reason_code="dwarf-address-without-elf-object",
            )
        )
    for item in reconciliation["abiObjects"]:
        owner = item["ownerShardIds"][0]
        outcome = "exact" if item["resolvedSlots"] == item["slots"] else "partial"
        counts_by_shard[owner]["abiObjects"][outcome] += 1
        if outcome == "partial":
            truth_id = f"{item['elfGlobalId']}:{item['aliasName']}"
            mismatches.append(
                _mismatch(
                    dimension="abiObjects",
                    kind="partial",
                    truth_id=truth_id,
                    shard_id=owner,
                    reason_code="abi-object-has-unresolved-slot-words",
                )
            )

    shard_reports = []
    aggregate_counts = _empty_counts()
    for shard_id, dimension_counts in sorted(counts_by_shard.items()):
        report = {"id": shard_id}
        for dimension in DIMENSIONS:
            report[dimension] = _metric(**dimension_counts[dimension])
            for outcome, value in dimension_counts[dimension].items():
                aggregate_counts[dimension][outcome] += value
        shard_reports.append(report)
    aggregate = {
        dimension: _metric(**aggregate_counts[dimension]) for dimension in DIMENSIONS
    }
    without_hash = {
        "aggregate": aggregate,
        "configurationSha256": _configuration_sha256(),
        "dataTruthIndexSha256": _sha(data_payload),
        "mismatches": sorted(mismatches, key=lambda item: item["id"]),
        "reconciliationReportSha256": _sha(reconciliation_payload),
        "schemaVersion": 1,
        "shards": shard_reports,
    }
    report = {**without_hash, "reportSha256": _sha(canonical_json_bytes(without_hash))}
    validate_full_tree_data_baseline(report)
    return report


def validate_full_tree_data_baseline(report: dict[str, Any]) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]

        schema = json.loads(
            Path(__file__).with_name("full-tree-data-baseline.schema.json").read_text(encoding="utf-8")
        )
        fastjsonschema.compile(schema)(report)
    except Exception as error:
        raise FullTreeDataBaselineError(f"data baseline fails validation: {error}") from error
    if report["configurationSha256"] != _configuration_sha256():
        raise FullTreeDataBaselineError("data baseline configuration binding differs")
    without_hash = {key: value for key, value in report.items() if key != "reportSha256"}
    if report["reportSha256"] != _sha(canonical_json_bytes(without_hash)):
        raise FullTreeDataBaselineError("data baseline hash does not reconcile")
    if report["shards"] != sorted(report["shards"], key=lambda item: item["id"]):
        raise FullTreeDataBaselineError("data baseline shards are not ordered")
    if report["mismatches"] != sorted(report["mismatches"], key=lambda item: item["id"]):
        raise FullTreeDataBaselineError("data baseline mismatches are not ordered")
    if len({item["id"] for item in report["mismatches"]}) != len(report["mismatches"]):
        raise FullTreeDataBaselineError("data baseline mismatch identities are duplicated")
    aggregate_counts = _empty_counts()
    for shard in report["shards"]:
        for dimension in DIMENSIONS:
            metric = shard[dimension]
            if metric["denominator"] != metric["exact"] + metric["partial"] + metric["missing"]:
                raise FullTreeDataBaselineError(f"{dimension} denominator differs for {shard['id']}")
            for outcome in aggregate_counts[dimension]:
                aggregate_counts[dimension][outcome] += metric[outcome]
    expected = {
        dimension: _metric(**aggregate_counts[dimension]) for dimension in DIMENSIONS
    }
    if report["aggregate"] != expected:
        raise FullTreeDataBaselineError("data baseline aggregate does not reconcile")


def require_no_data_baseline_regression(current: dict[str, Any], accepted: dict[str, Any]) -> None:
    validate_full_tree_data_baseline(current)
    validate_full_tree_data_baseline(accepted)
    current_shards = {item["id"]: item for item in current["shards"]}
    accepted_shards = {item["id"]: item for item in accepted["shards"]}
    if current_shards.keys() != accepted_shards.keys():
        raise FullTreeDataBaselineError("data baseline shard population drifted")
    for shard_id, baseline in accepted_shards.items():
        for dimension in DIMENSIONS:
            observed = current_shards[shard_id][dimension]
            prior = baseline[dimension]
            if observed["denominator"] != prior["denominator"]:
                raise FullTreeDataBaselineError(f"{dimension} denominator drifted for {shard_id}")
            if observed["exact"] < prior["exact"] or observed["fabricated"] > prior["fabricated"]:
                raise FullTreeDataBaselineError(f"{dimension} baseline regressed for {shard_id}")
