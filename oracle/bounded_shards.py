"""Program-neutral bounded, resumable, byte-deterministic shard execution."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import tempfile
import threading
import time
from typing import Any, Callable, Iterable

from oracle.full_tree_scope import canonical_json_bytes


_IDENTIFIER = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class BoundedShardError(ValueError):
    """Raised when shard work or its durable evidence violates the run contract."""


@dataclass(frozen=True)
class ShardInput:
    identifier: str
    input_sha256: str


@dataclass(frozen=True)
class ShardBounds:
    maximum_shards: int
    per_shard_entities: int
    whole_run_entities: int
    per_shard_bytes: int
    whole_run_bytes: int
    per_shard_seconds: float
    whole_run_seconds: float
    per_shard_cpu_seconds: float
    whole_run_cpu_seconds: float
    maximum_resident_bytes: int
    maximum_workers: int


ShardProducer = Callable[[ShardInput, Path, threading.Event], int]


def _sha256_file(path: Path, maximum: int) -> tuple[str, int]:
    if path.is_symlink() or not path.is_file():
        raise BoundedShardError(f"shard output is not a regular file: {path}")
    size = path.stat().st_size
    if not 0 < size <= maximum:
        raise BoundedShardError(f"shard output size {size} is outside 1..{maximum}")
    digest = hashlib.sha256()
    observed = 0
    with path.open("rb") as stream:
        while block := stream.read(min(1024 * 1024, maximum + 1 - observed)):
            observed += len(block)
            if observed > maximum:
                raise BoundedShardError("shard output exceeded its byte bound")
            digest.update(block)
    if observed != size:
        raise BoundedShardError("shard output changed while it was hashed")
    return digest.hexdigest(), size


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".partial", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _document(path: Path, label: str, maximum: int = 16 * 1024 * 1024) -> tuple[dict[str, Any], bytes]:
    digest, size = _sha256_file(path, maximum)
    del digest, size
    payload = path.read_bytes()
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BoundedShardError(f"{label} is invalid JSON: {error}") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != payload:
        raise BoundedShardError(f"{label} is not a canonical JSON object")
    return value, payload


def _validate_inputs(inputs: Iterable[ShardInput], bounds: ShardBounds) -> list[ShardInput]:
    result = sorted(inputs, key=lambda item: item.identifier)
    if not result or len(result) > bounds.maximum_shards:
        raise BoundedShardError("shard count is outside the run bound")
    identifiers = [item.identifier for item in result]
    if len(set(identifiers)) != len(identifiers):
        raise BoundedShardError("shard identifiers are not unique")
    for item in result:
        if _IDENTIFIER.fullmatch(item.identifier) is None:
            raise BoundedShardError(f"invalid shard identifier: {item.identifier}")
        if _SHA256.fullmatch(item.input_sha256) is None:
            raise BoundedShardError(f"invalid shard input digest: {item.identifier}")
    integer_bounds = (
        bounds.maximum_shards,
        bounds.per_shard_entities,
        bounds.whole_run_entities,
        bounds.per_shard_bytes,
        bounds.whole_run_bytes,
        bounds.maximum_resident_bytes,
        bounds.maximum_workers,
    )
    if any(isinstance(value, bool) or value <= 0 for value in integer_bounds):
        raise BoundedShardError("integer shard bounds must be positive")
    if not 0 < bounds.maximum_workers <= min(32, bounds.maximum_shards):
        raise BoundedShardError("maximum workers exceeds the deterministic bound")
    if bounds.per_shard_entities > bounds.whole_run_entities:
        raise BoundedShardError("per-shard entity bound exceeds whole-run bound")
    if bounds.per_shard_bytes > bounds.whole_run_bytes:
        raise BoundedShardError("per-shard byte bound exceeds whole-run bound")
    if not 0 < bounds.per_shard_seconds <= bounds.whole_run_seconds:
        raise BoundedShardError("wall-clock bounds are invalid")
    if not 0 < bounds.per_shard_cpu_seconds <= bounds.whole_run_cpu_seconds:
        raise BoundedShardError("CPU-time bounds are invalid")
    return result


def _run_document(run_id: str, inputs: list[ShardInput], bounds: ShardBounds) -> dict[str, Any]:
    if _IDENTIFIER.fullmatch(run_id) is None:
        raise BoundedShardError("run ID must be lowercase kebab-case")
    return {
        "bounds": {
            "maximumResidentBytes": bounds.maximum_resident_bytes,
            "maximumShards": bounds.maximum_shards,
            "maximumWorkers": bounds.maximum_workers,
            "perShardBytes": bounds.per_shard_bytes,
            "perShardEntities": bounds.per_shard_entities,
            "perShardSeconds": bounds.per_shard_seconds,
            "perShardCpuSeconds": bounds.per_shard_cpu_seconds,
            "wholeRunBytes": bounds.whole_run_bytes,
            "wholeRunEntities": bounds.whole_run_entities,
            "wholeRunSeconds": bounds.whole_run_seconds,
            "wholeRunCpuSeconds": bounds.whole_run_cpu_seconds,
        },
        "id": run_id,
        "schemaVersion": 1,
        "shards": [
            {"id": item.identifier, "inputSha256": item.input_sha256}
            for item in inputs
        ],
    }


def _maximum_resident_bytes() -> int:
    own = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    children = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    # Linux reports KiB. This repository's production runners are Linux-only.
    return max(int(own), int(children)) * 1024


def _cpu_seconds() -> float:
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime + own.ru_stime + children.ru_utime + children.ru_stime


def _checkpoint(
    checkpoint_path: Path,
    output_path: Path,
    *,
    run_sha256: str,
    shard: ShardInput,
    maximum_bytes: int,
    maximum_entities: int,
) -> dict[str, Any] | None:
    if not checkpoint_path.exists():
        return None
    record, _ = _document(checkpoint_path, f"checkpoint {shard.identifier}")
    expected_fields = {
        "entities",
        "inputSha256",
        "outputBytes",
        "outputSha256",
        "runSha256",
        "schemaVersion",
        "shardId",
        "status",
    }
    if set(record) != expected_fields:
        raise BoundedShardError(f"checkpoint {shard.identifier} has unknown fields")
    if (
        record["schemaVersion"] != 1
        or record["status"] not in {"prepared", "complete"}
        or record["shardId"] != shard.identifier
        or record["inputSha256"] != shard.input_sha256
        or record["runSha256"] != run_sha256
    ):
        raise BoundedShardError(f"checkpoint {shard.identifier} identity does not match")
    if record["status"] == "prepared" and not output_path.exists():
        return None
    digest, size = _sha256_file(output_path, maximum_bytes)
    if record["outputSha256"] != digest or record["outputBytes"] != size:
        raise BoundedShardError(f"checkpoint {shard.identifier} output does not match")
    if (
        isinstance(record["entities"], bool)
        or not isinstance(record["entities"], int)
        or not 0 <= record["entities"] <= maximum_entities
    ):
        raise BoundedShardError(f"checkpoint {shard.identifier} entity count is invalid")
    if record["status"] == "prepared":
        record = {**record, "status": "complete"}
        _atomic_write(checkpoint_path, canonical_json_bytes(record))
    return record


def run_bounded_shards(
    root: Path,
    *,
    run_id: str,
    inputs: Iterable[ShardInput],
    bounds: ShardBounds,
    producer: ShardProducer,
) -> dict[str, Any]:
    """Run missing shards and publish an index only after all evidence reconciles."""

    shards = _validate_inputs(inputs, bounds)
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise BoundedShardError("shard run root must be a non-symlink directory")
    run = _run_document(run_id, shards, bounds)
    run_payload = canonical_json_bytes(run)
    run_sha256 = hashlib.sha256(run_payload).hexdigest()
    run_path = root / "run.json"
    if run_path.exists():
        _, existing = _document(run_path, "shard run contract")
        if existing != run_payload:
            raise BoundedShardError("existing shard run contract differs")
    else:
        _atomic_write(run_path, run_payload)

    outputs = root / "outputs"
    checkpoints = root / "checkpoints"
    outputs.mkdir(exist_ok=True)
    checkpoints.mkdir(exist_ok=True)
    if outputs.is_symlink() or not outputs.is_dir():
        raise BoundedShardError("shard output directory must not be a symlink")
    if checkpoints.is_symlink() or not checkpoints.is_dir():
        raise BoundedShardError("shard checkpoint directory must not be a symlink")
    records: dict[str, dict[str, Any]] = {}
    pending: list[ShardInput] = []
    for shard in shards:
        record = _checkpoint(
            checkpoints / f"{shard.identifier}.json",
            outputs / f"{shard.identifier}.json",
            run_sha256=run_sha256,
            shard=shard,
            maximum_bytes=bounds.per_shard_bytes,
            maximum_entities=bounds.per_shard_entities,
        )
        if record is None:
            pending.append(shard)
        else:
            records[shard.identifier] = record

    started = time.monotonic()
    cpu_started = _cpu_seconds()
    lock = threading.Lock()
    cancelled = threading.Event()

    def execute(shard: ShardInput) -> dict[str, Any]:
        shard_started = time.monotonic()
        shard_cpu_started = _cpu_seconds()
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{shard.identifier}.", suffix=".partial", dir=outputs
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            entities = producer(shard, temporary, cancelled)
            elapsed = time.monotonic() - shard_started
            if isinstance(entities, bool) or not isinstance(entities, int) or not 0 <= entities <= bounds.per_shard_entities:
                raise BoundedShardError(f"shard {shard.identifier} exceeded its entity bound")
            if elapsed > bounds.per_shard_seconds:
                raise BoundedShardError(f"shard {shard.identifier} exceeded its wall-clock bound")
            if _cpu_seconds() - shard_cpu_started > bounds.per_shard_cpu_seconds:
                raise BoundedShardError(f"shard {shard.identifier} exceeded its CPU-time bound")
            digest, size = _sha256_file(temporary, bounds.per_shard_bytes)
            if _maximum_resident_bytes() > bounds.maximum_resident_bytes:
                raise BoundedShardError("shard run exceeded its maximum resident-byte bound")
            output_path = outputs / f"{shard.identifier}.json"
            if output_path.exists() or output_path.is_symlink():
                raise BoundedShardError(f"uncheckpointed output already exists for {shard.identifier}")
            record = {
                "entities": entities,
                "inputSha256": shard.input_sha256,
                "outputBytes": size,
                "outputSha256": digest,
                "runSha256": run_sha256,
                "schemaVersion": 1,
                "shardId": shard.identifier,
                "status": "prepared",
            }
            _atomic_write(
                checkpoints / f"{shard.identifier}.json",
                canonical_json_bytes(record),
            )
            os.replace(temporary, output_path)
            record["status"] = "complete"
            _atomic_write(
                checkpoints / f"{shard.identifier}.json",
                canonical_json_bytes(record),
            )
            with lock:
                records[shard.identifier] = record
            return record
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    with ThreadPoolExecutor(max_workers=bounds.maximum_workers) as executor:
        futures: dict[Future[dict[str, Any]], ShardInput] = {
            executor.submit(execute, shard): shard for shard in pending
        }
        try:
            for future in as_completed(futures):
                future.result()
                if time.monotonic() - started > bounds.whole_run_seconds:
                    raise BoundedShardError("shard run exceeded its whole-run wall-clock bound")
                if _cpu_seconds() - cpu_started > bounds.whole_run_cpu_seconds:
                    raise BoundedShardError("shard run exceeded its whole-run CPU-time bound")
        except BaseException:
            cancelled.set()
            for future in futures:
                future.cancel()
            raise

    ordered = [records[shard.identifier] for shard in shards]
    total_entities = sum(record["entities"] for record in ordered)
    total_bytes = sum(record["outputBytes"] for record in ordered)
    if total_entities > bounds.whole_run_entities:
        raise BoundedShardError("completed shards exceed the whole-run entity bound")
    if total_bytes > bounds.whole_run_bytes:
        raise BoundedShardError("completed shards exceed the whole-run byte bound")
    leaves = [hashlib.sha256(canonical_json_bytes(record)).digest() for record in ordered]
    index = {
        "complete": True,
        "counts": {
            "entities": total_entities,
            "serializedBytes": total_bytes,
            "shards": len(ordered),
        },
        "indexSha256": hashlib.sha256(b"bounded-shards-v1\0" + b"".join(leaves)).hexdigest(),
        "runSha256": run_sha256,
        "schemaVersion": 1,
        "shards": ordered,
    }
    _atomic_write(root / "index.json", canonical_json_bytes(index))
    return index


def load_complete_shard_index(root: Path) -> dict[str, Any]:
    """Load an index only when every bound output/checkpoint is still intact."""

    run, run_payload = _document(root / "run.json", "shard run contract")
    index, index_payload = _document(root / "index.json", "shard run index")
    del index_payload
    try:
        import fastjsonschema  # type: ignore[import-untyped]
    except ModuleNotFoundError as error:
        raise BoundedShardError("shard index validation requires pinned oracle dependencies") from error
    schema_path = Path(__file__).with_name("bounded-shard-index.schema.json")
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        fastjsonschema.compile(schema)(index)
    except (OSError, json.JSONDecodeError, fastjsonschema.JsonSchemaException) as error:
        raise BoundedShardError(f"shard run index fails JSON Schema: {error}") from error
    if index.get("schemaVersion") != 1 or index.get("complete") is not True:
        raise BoundedShardError("shard run index is not complete")
    run_sha256 = hashlib.sha256(run_payload).hexdigest()
    if index.get("runSha256") != run_sha256:
        raise BoundedShardError("shard run index does not match its run contract")
    inputs = {
        item["id"]: ShardInput(item["id"], item["inputSha256"])
        for item in run["shards"]
    }
    records = index.get("shards")
    if not isinstance(records, list) or [item.get("shardId") for item in records] != sorted(inputs):
        raise BoundedShardError("shard run index membership is incomplete or unordered")
    for record in records:
        identifier = record["shardId"]
        actual = _checkpoint(
            root / "checkpoints" / f"{identifier}.json",
            root / "outputs" / f"{identifier}.json",
            run_sha256=run_sha256,
            shard=inputs[identifier],
            maximum_bytes=run["bounds"]["perShardBytes"],
            maximum_entities=run["bounds"]["perShardEntities"],
        )
        if actual != record:
            raise BoundedShardError(f"index checkpoint differs for {identifier}")
    leaves = [hashlib.sha256(canonical_json_bytes(record)).digest() for record in records]
    if index.get("indexSha256") != hashlib.sha256(b"bounded-shards-v1\0" + b"".join(leaves)).hexdigest():
        raise BoundedShardError("shard run index hash does not reconcile")
    counts = {
        "entities": sum(item["entities"] for item in records),
        "serializedBytes": sum(item["outputBytes"] for item in records),
        "shards": len(records),
    }
    if index.get("counts") != counts:
        raise BoundedShardError("shard run index counts do not reconcile")
    return index
