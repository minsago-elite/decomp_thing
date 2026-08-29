"""Persist and reconcile bounded per-shard resource observations."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import tempfile
import time
from typing import Any

from oracle.bounded_shards import ShardInput
from oracle.full_tree_scope import canonical_json_bytes


class FullTreeExecutionEvidenceError(ValueError):
    """Raised when resource evidence is missing, malformed, or exceeds policy."""


def persist_shard_execution_usage(
    *,
    usage_directory: Path,
    shard: ShardInput,
    output: Path,
    entities: int,
    maximum_resident_bytes: int,
    user_cpu_seconds: float,
    system_cpu_seconds: float,
    wall_clock_seconds: float,
) -> None:
    output_payload = output.read_bytes()
    payload = canonical_json_bytes(
        {
            "entities": entities,
            "id": shard.identifier,
            "inputSha256": shard.input_sha256,
            "maximumResidentBytes": maximum_resident_bytes,
            "outputSha256": hashlib.sha256(output_payload).hexdigest(),
            "serializedBytes": len(output_payload),
            "systemCpuSeconds": system_cpu_seconds,
            "userCpuSeconds": user_cpu_seconds,
            "wallClockSeconds": wall_clock_seconds,
        }
    )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{shard.identifier}.", suffix=".usage", dir=usage_directory
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, usage_directory / f"{shard.identifier}.json")
    finally:
        try:
            Path(temporary_name).unlink()
        except FileNotFoundError:
            pass


def write_full_tree_execution_evidence(
    *,
    output_root: Path,
    index: dict[str, Any],
    per_shard_bounds: dict[str, Any],
    whole_run_bounds: dict[str, Any],
    run_started: float,
) -> dict[str, Any]:
    usage_records = []
    for checkpoint in index["shards"]:
        path = output_root / "usage" / f"{checkpoint['shardId']}.json"
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise FullTreeExecutionEvidenceError(
                f"missing or malformed execution evidence for {checkpoint['shardId']}"
            ) from error
        if record["id"] != checkpoint["shardId"] or any(
            record[field] != checkpoint[checkpoint_field]
            for field, checkpoint_field in (
                ("inputSha256", "inputSha256"),
                ("outputSha256", "outputSha256"),
                ("serializedBytes", "outputBytes"),
                ("entities", "entities"),
            )
        ):
            raise FullTreeExecutionEvidenceError(
                f"execution evidence differs from checkpoint {checkpoint['shardId']}"
            )
        usage_records.append(record)
    evidence_without_hash = {
        "bounds": {"perShard": per_shard_bounds, "wholeRun": whole_run_bounds},
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "indexSha256": index["indexSha256"],
        "observed": {
            "entities": sum(item["entities"] for item in usage_records),
            "maximumResidentBytes": max(item["maximumResidentBytes"] for item in usage_records),
            "serializedBytes": sum(item["serializedBytes"] for item in usage_records),
            "systemCpuSeconds": sum(item["systemCpuSeconds"] for item in usage_records),
            "userCpuSeconds": sum(item["userCpuSeconds"] for item in usage_records),
            "wallClockSeconds": time.monotonic() - run_started,
        },
        "runSha256": index["runSha256"],
        "schemaVersion": 1,
        "shards": usage_records,
    }
    evidence = {
        **evidence_without_hash,
        "evidenceSha256": hashlib.sha256(canonical_json_bytes(evidence_without_hash)).hexdigest(),
    }
    observed = evidence["observed"]
    if (
        observed["entities"] != index["counts"]["entities"]
        or observed["serializedBytes"] != index["counts"]["serializedBytes"]
        or observed["maximumResidentBytes"] > per_shard_bounds["maximumResidentBytes"]
        or observed["userCpuSeconds"] + observed["systemCpuSeconds"] > whole_run_bounds["cpuSeconds"]
        or observed["wallClockSeconds"] > whole_run_bounds["wallClockSeconds"]
    ):
        raise FullTreeExecutionEvidenceError("execution evidence exceeds or differs from run bounds")
    try:
        import fastjsonschema  # type: ignore[import-untyped]

        schema = json.loads(
            Path(__file__).with_name("full-tree-execution-evidence.schema.json").read_text(encoding="utf-8")
        )
        fastjsonschema.compile(schema)(evidence)
    except Exception as error:
        raise FullTreeExecutionEvidenceError(
            f"execution evidence fails validation: {error}"
        ) from error
    (output_root / "execution-evidence.json").write_bytes(canonical_json_bytes(evidence))
    return evidence
