"""Byte-compare two independently materialized full-tree truth directories."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from oracle.full_tree_scope import canonical_json_bytes


class FullTreeMaterializationDeterminismError(ValueError):
    """Raised when a truth tree or its determinism report is malformed."""


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _paths(root: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    index_payload = (root / "index.json").read_bytes()
    try:
        index = json.loads(index_payload)
    except json.JSONDecodeError as error:
        raise FullTreeMaterializationDeterminismError("truth index is invalid JSON") from error
    if not isinstance(index, dict) or canonical_json_bytes(index) != index_payload:
        raise FullTreeMaterializationDeterminismError("truth index is not canonical")
    relative_paths = {"index.json"}
    for record in index.get("shards", []):
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise FullTreeMaterializationDeterminismError("truth shard has no path")
        relative_paths.add(record["path"])
    exclusion = index.get("exclusions")
    if exclusion is not None:
        if not isinstance(exclusion, dict) or not isinstance(exclusion.get("path"), str):
            raise FullTreeMaterializationDeterminismError("truth exclusions have no path")
        relative_paths.add(exclusion["path"])
    payloads = {}
    for relative in sorted(relative_paths):
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or str(path) != relative:
            raise FullTreeMaterializationDeterminismError("truth path escapes its root")
        payloads[relative] = (root / relative).read_bytes()
    return index, payloads


def compare_full_tree_materializations(first_root: Path, second_root: Path) -> dict[str, Any]:
    _, first = _paths(first_root)
    _, second = _paths(second_root)
    differing = sorted(
        relative
        for relative in first.keys() | second.keys()
        if first.get(relative) != second.get(relative)
    )
    without_hash = {
        "differingFiles": differing,
        "files": len(first.keys() | second.keys()),
        "firstIndexSha256": _sha(first["index.json"]),
        "identical": not differing,
        "schemaVersion": 1,
        "secondIndexSha256": _sha(second["index.json"]),
    }
    report = {**without_hash, "reportSha256": _sha(canonical_json_bytes(without_hash))}
    validate_full_tree_materialization_determinism(report)
    return report


def validate_full_tree_materialization_determinism(report: dict[str, Any]) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]

        schema = json.loads(
            Path(__file__).with_name("full-tree-materialization-determinism.schema.json").read_text(encoding="utf-8")
        )
        fastjsonschema.compile(schema)(report)
    except Exception as error:
        raise FullTreeMaterializationDeterminismError(
            f"materialization determinism report fails validation: {error}"
        ) from error
    without_hash = {key: value for key, value in report.items() if key != "reportSha256"}
    if report["reportSha256"] != _sha(canonical_json_bytes(without_hash)):
        raise FullTreeMaterializationDeterminismError("materialization report hash does not reconcile")
    if report["differingFiles"] != sorted(set(report["differingFiles"])):
        raise FullTreeMaterializationDeterminismError("materialization differences are not ordered and unique")
    if report["identical"] != (not report["differingFiles"]):
        raise FullTreeMaterializationDeterminismError("materialization result does not reconcile")
