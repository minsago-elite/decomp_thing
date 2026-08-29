"""Canonical A13 evidence manifest and concise human summary."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from oracle.bounded_shards import load_complete_shard_index
from oracle.full_tree_call_baseline import validate_full_tree_call_baseline
from oracle.full_tree_call_truth import validate_full_tree_call_truth_index
from oracle.full_tree_data_baseline import validate_full_tree_data_baseline
from oracle.full_tree_data_reconciliation import validate_full_tree_data_reconciliation
from oracle.full_tree_data_truth import validate_full_tree_data_truth_index
from oracle.full_tree_determinism import compare_full_tree_runs, validate_full_tree_determinism_report
from oracle.full_tree_elf_data import validate_full_tree_elf_data_index
from oracle.full_tree_elf_functions import validate_full_tree_elf_function_index
from oracle.full_tree_function_baseline import validate_full_tree_function_baseline
from oracle.full_tree_function_truth import validate_full_tree_function_truth_index
from oracle.full_tree_materialization_determinism import (
    compare_full_tree_materializations,
    validate_full_tree_materialization_determinism,
)
from oracle.full_tree_scope import canonical_json_bytes


class FullTreeReleaseEvidenceError(ValueError):
    """Raised when full-tree release evidence is incomplete or inconsistent."""


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _load(path: Path) -> tuple[dict[str, Any], bytes]:
    payload = path.read_bytes()
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise FullTreeReleaseEvidenceError(f"evidence input is invalid JSON: {path}") from error
    if not isinstance(value, dict) or payload != canonical_json_bytes(value):
        raise FullTreeReleaseEvidenceError(f"evidence input is not canonical: {path}")
    return value, payload


def _artifact(role: str, payload: bytes) -> dict[str, Any]:
    return {"bytes": len(payload), "role": role, "sha256": _sha(payload)}


def _execution(root: Path, index: dict[str, Any]) -> dict[str, Any]:
    evidence, payload = _load(root / "execution-evidence.json")
    without_hash = {key: value for key, value in evidence.items() if key != "evidenceSha256"}
    if evidence.get("evidenceSha256") != _sha(canonical_json_bytes(without_hash)):
        raise FullTreeReleaseEvidenceError("execution evidence hash does not reconcile")
    if evidence.get("indexSha256") != index["indexSha256"] or evidence.get("runSha256") != index["runSha256"]:
        raise FullTreeReleaseEvidenceError("execution evidence differs from its shard index")
    observed = evidence["observed"]
    bounds = evidence["bounds"]
    if (
        observed["entities"] != index["counts"]["entities"]
        or observed["serializedBytes"] != index["counts"]["serializedBytes"]
        or observed["maximumResidentBytes"] > bounds["perShard"]["maximumResidentBytes"]
        or observed["systemCpuSeconds"] + observed["userCpuSeconds"] > bounds["wholeRun"]["cpuSeconds"]
        or observed["wallClockSeconds"] > bounds["wholeRun"]["wallClockSeconds"]
    ):
        raise FullTreeReleaseEvidenceError("execution evidence exceeds or differs from bounds")
    return {
        "artifact": _artifact("execution-evidence", payload),
        "bounds": bounds,
        "evidenceSha256": evidence["evidenceSha256"],
        "observed": observed,
        "runSha256": evidence["runSha256"],
    }


def _observation_stage(role: str, first_root: Path, second_root: Path) -> dict[str, Any]:
    first = load_complete_shard_index(first_root)
    second = load_complete_shard_index(second_root)
    determinism = compare_full_tree_runs(first_root, second_root)
    if not determinism["identical"]:
        raise FullTreeReleaseEvidenceError(f"{role} observations are nondeterministic")
    first_payload = (first_root / "index.json").read_bytes()
    second_payload = (second_root / "index.json").read_bytes()
    return {
        "counts": first["counts"],
        "determinism": determinism,
        "executions": [_execution(first_root, first), _execution(second_root, second)],
        "indexes": [_artifact(f"{role}-observations-first", first_payload), _artifact(f"{role}-observations-second", second_payload)],
    }


def _truth_stage(role: str, first_root: Path, second_root: Path, counts: dict[str, Any]) -> dict[str, Any]:
    determinism = compare_full_tree_materializations(first_root, second_root)
    if not determinism["identical"]:
        raise FullTreeReleaseEvidenceError(f"{role} truth is nondeterministic")
    first_payload = (first_root / "index.json").read_bytes()
    second_payload = (second_root / "index.json").read_bytes()
    return {
        "counts": counts,
        "determinism": determinism,
        "indexes": [_artifact(f"{role}-truth-first", first_payload), _artifact(f"{role}-truth-second", second_payload)],
    }


def generate_full_tree_release_evidence(
    *,
    scope: dict[str, Any], scope_sha256: str, inventory: dict[str, Any],
    function_elf_path: Path, function_observation_roots: tuple[Path, Path], function_truth_roots: tuple[Path, Path], function_baseline_path: Path,
    call_observation_roots: tuple[Path, Path], call_truth_roots: tuple[Path, Path], call_baseline_path: Path,
    data_elf_path: Path, data_observation_roots: tuple[Path, Path], data_truth_roots: tuple[Path, Path], data_reconciliation_path: Path, data_baseline_path: Path,
) -> dict[str, Any]:
    function_elf, function_elf_payload = _load(function_elf_path)
    validate_full_tree_elf_function_index(function_elf, scope=scope, scope_sha256=scope_sha256, inventory=inventory)
    function_observations = _observation_stage("functions", *function_observation_roots)
    function_index, function_index_payload = _load(function_truth_roots[0] / "index.json")
    validate_full_tree_function_truth_index(
        function_index, output_root=function_truth_roots[0], scope=scope, scope_sha256=scope_sha256, inventory=inventory,
        observation_index_sha256=function_index["oracle"]["observationIndexSha256"], elf_index_sha256=function_index["oracle"]["elfIndexSha256"],
    )
    function_truth = _truth_stage("functions", *function_truth_roots, function_index["counts"])

    call_observations = _observation_stage("calls", *call_observation_roots)
    call_index, call_index_payload = _load(call_truth_roots[0] / "index.json")
    validate_full_tree_call_truth_index(call_index, output_root=call_truth_roots[0], inventory=inventory)
    call_truth = _truth_stage("calls", *call_truth_roots, call_index["counts"])

    data_elf, data_elf_payload = _load(data_elf_path)
    validate_full_tree_elf_data_index(data_elf, scope=scope, scope_sha256=scope_sha256, inventory=inventory)
    data_observations = _observation_stage("data", *data_observation_roots)
    data_index, data_index_payload = _load(data_truth_roots[0] / "index.json")
    validate_full_tree_data_truth_index(data_index, output_root=data_truth_roots[0], scope_sha256=scope_sha256, inventory=inventory)
    data_truth = _truth_stage("data", *data_truth_roots, data_index["counts"])
    reconciliation, reconciliation_payload = _load(data_reconciliation_path)
    validate_full_tree_data_reconciliation(
        reconciliation, data_truth_index_sha256=_sha(data_index_payload), elf_data_index_sha256=_sha(data_elf_payload),
        inventory=inventory, scope_sha256=scope_sha256,
    )
    if reconciliation["counts"]["unexplainedEntities"] != 0:
        raise FullTreeReleaseEvidenceError("data reconciliation has unexplained entities")

    baselines = {}
    for role, path, validator in (
        ("functions", function_baseline_path, validate_full_tree_function_baseline),
        ("calls", call_baseline_path, validate_full_tree_call_baseline),
        ("data", data_baseline_path, validate_full_tree_data_baseline),
    ):
        baseline, payload = _load(path)
        validator(baseline)
        baselines[role] = {"aggregate": baseline["aggregate"], "artifact": _artifact(f"{role}-baseline", payload), "reportSha256": baseline["reportSha256"]}

    without_hash = {
        "artifacts": sorted([
            _artifact("function-elf-index", function_elf_payload),
            _artifact("function-truth-index", function_index_payload),
            _artifact("call-truth-index", call_index_payload),
            _artifact("data-elf-index", data_elf_payload),
            _artifact("data-truth-index", data_index_payload),
            _artifact("data-reconciliation", reconciliation_payload),
        ], key=lambda item: item["role"]),
        "baselines": baselines,
        "complete": True,
        "inventory": {"compilationUnits": len(inventory["units"]), "indexSha256": inventory["indexSha256"], "shards": len(inventory["shards"])},
        "observations": {"calls": call_observations, "data": data_observations, "functions": function_observations},
        "oracle": {"richArtifactSha256": scope["oracle"]["richArtifactSha256"], "scopeSha256": scope_sha256, "strippedArtifactSha256": scope["oracle"]["strippedArtifactSha256"]},
        "reconciliation": reconciliation["counts"],
        "schemaVersion": 1,
        "truth": {"calls": call_truth, "data": data_truth, "functions": function_truth},
    }
    report = {**without_hash, "reportSha256": _sha(canonical_json_bytes(without_hash))}
    validate_full_tree_release_evidence(report)
    return report


def validate_full_tree_release_evidence(report: dict[str, Any]) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]
        schema = json.loads(Path(__file__).with_name("full-tree-release-evidence.schema.json").read_text(encoding="utf-8"))
        fastjsonschema.compile(schema)(report)
    except Exception as error:
        raise FullTreeReleaseEvidenceError(f"release evidence fails validation: {error}") from error
    without_hash = {key: value for key, value in report.items() if key != "reportSha256"}
    if report["reportSha256"] != _sha(canonical_json_bytes(without_hash)):
        raise FullTreeReleaseEvidenceError("release evidence hash does not reconcile")
    roles = [item["role"] for item in report["artifacts"]]
    if roles != sorted(roles) or len(roles) != len(set(roles)):
        raise FullTreeReleaseEvidenceError("release evidence artifacts are not ordered and unique")
    for stage in report["observations"].values():
        validate_full_tree_determinism_report(stage["determinism"])
        if not stage["determinism"]["identical"]:
            raise FullTreeReleaseEvidenceError("release evidence admits nondeterministic observations")
    for stage in report["truth"].values():
        validate_full_tree_materialization_determinism(stage["determinism"])
        if not stage["determinism"]["identical"]:
            raise FullTreeReleaseEvidenceError("release evidence admits nondeterministic truth")
    if report["reconciliation"]["unexplainedEntities"] != 0:
        raise FullTreeReleaseEvidenceError("release evidence has unexplained entities")
    function = report["baselines"]["functions"]["aggregate"]
    if function["denominator"] != function["recovered"] + function["missing"]:
        raise FullTreeReleaseEvidenceError("function baseline denominator does not reconcile")
    call = report["baselines"]["calls"]["aggregate"]
    if call["denominator"] != call["exact"] + call["partial"] + call["missing"]:
        raise FullTreeReleaseEvidenceError("call baseline denominator does not reconcile")
    for metric in report["baselines"]["data"]["aggregate"].values():
        if metric["denominator"] != metric["exact"] + metric["partial"] + metric["missing"]:
            raise FullTreeReleaseEvidenceError("data baseline denominator does not reconcile")


def render_full_tree_release_summary(report: dict[str, Any]) -> str:
    validate_full_tree_release_evidence(report)
    function = report["truth"]["functions"]["counts"]
    calls = report["truth"]["calls"]["counts"]
    data = report["truth"]["data"]["counts"]
    lines = [
        "# LLVM 22.1.6 A13 full-tree evidence",
        "",
        f"Scope `{report['oracle']['scopeSha256']}` covers {report['inventory']['compilationUnits']:,} compilation units in {report['inventory']['shards']} shards. All observation and truth pairs are byte-deterministic, and data reconciliation reports zero unexplained entities.",
        "",
        "| Dimension | Authenticated result |",
        "| --- | ---: |",
        f"| Scored function RVAs | {function['scoredRvas']:,} |",
        f"| Unique inline-only functions | {function['inlineUnique']:,} |",
        f"| Call edges | {calls['edges']:,} |",
        f"| Direct internal calls | {calls['directInternal']:,} |",
        f"| External calls | {calls['external']:,} |",
        f"| Unresolved indirect calls | {calls['indirectUnresolved']:,} |",
        f"| Canonical globals | {data['globals']:,} |",
        f"| Canonical aggregate types | {data['types']:,} |",
        f"| ABI objects | {report['reconciliation']['abiObjects']:,} |",
        f"| ABI slots | {report['reconciliation']['abiSlots']:,} |",
        "",
        "| Baseline | Exact/recovered | Partial | Missing | Excluded | Fabricated |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    functions = report["baselines"]["functions"]["aggregate"]
    call_baseline = report["baselines"]["calls"]["aggregate"]
    data_baseline = report["baselines"]["data"]["aggregate"]
    lines.append(f"| Functions | {functions['recovered']:,} | — | {functions['missing']:,} | {functions['excluded']:,} | {functions['fabricated']:,} |")
    lines.append(f"| Calls | {call_baseline['exact']:,} | {call_baseline['partial']:,} | {call_baseline['missing']:,} | {call_baseline['excluded']:,} | {call_baseline['fabricated']:,} |")
    for dimension in ("globals", "types", "abiObjects"):
        metric = data_baseline[dimension]
        lines.append(f"| Data: {dimension} | {metric['exact']:,} | {metric['partial']:,} | {metric['missing']:,} | {metric['excluded']:,} | {metric['fabricated']:,} |")
    lines.extend(["", f"Machine report SHA-256: `{report['reportSha256']}`", ""])
    return "\n".join(lines)
