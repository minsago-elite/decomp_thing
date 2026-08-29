"""Deterministic, bounded DWARF compilation-unit inventory and shard index."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

from oracle.full_tree_scope import (
    FullTreeScopeError,
    canonical_json_bytes,
    normalize_source_path,
    shard_for_source_path,
)


class FullTreeInventoryError(ValueError):
    """Raised when a compilation-unit inventory is incomplete or inconsistent."""


def _decode(value: Any, label: str) -> str:
    if isinstance(value, bytes):
        try:
            result = value.decode("utf-8")
        except UnicodeDecodeError as error:
            raise FullTreeInventoryError(f"{label} is not UTF-8") from error
    elif isinstance(value, str):
        result = value
    else:
        raise FullTreeInventoryError(f"{label} is not a DWARF string")
    if not result or "\x00" in result or len(result) > 4096:
        raise FullTreeInventoryError(f"{label} is empty, contains NUL, or exceeds 4096 characters")
    return result


def _sha256_file(stream: Any) -> str:
    stream.seek(0)
    digest = hashlib.sha256()
    while block := stream.read(1024 * 1024):
        digest.update(block)
    stream.seek(0)
    return digest.hexdigest()


def _artifact_stream(path: Path) -> tuple[Any, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FullTreeInventoryError(f"cannot open rich artifact {path}: {error}") from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > 1024 * 1024 * 1024:
        os.close(descriptor)
        raise FullTreeInventoryError("rich artifact must be a regular file of 1 byte..1 GiB")
    return os.fdopen(descriptor, "rb", closefd=True), metadata


def _stable(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def _attribute(top: Any, name: str, label: str, *, required: bool = False) -> Any:
    attribute = top.attributes.get(name)
    if attribute is None:
        if required:
            raise FullTreeInventoryError(f"{label} lacks {name}")
        return None
    return attribute.value


def _raw_unit_path(top: Any, label: str) -> str:
    name = _decode(_attribute(top, "DW_AT_name", label, required=True), f"{label} name")
    if name.startswith("/"):
        return name
    directory_value = _attribute(top, "DW_AT_comp_dir", label, required=True)
    directory = _decode(directory_value, f"{label} compilation directory").rstrip("/")
    return f"{directory}/{name}"


def _unit_id(source_path: str) -> str:
    return "cu-" + hashlib.sha256(source_path.encode("utf-8")).hexdigest()[:32]


def _index_hash(units: list[dict[str, Any]]) -> str:
    leaves = [hashlib.sha256(canonical_json_bytes(unit)).digest() for unit in units]
    return hashlib.sha256(b"full-tree-index-v1\0" + b"".join(leaves)).hexdigest()


def generate_inventory(rich_artifact: Path, scope: dict[str, Any], scope_sha256: str) -> dict[str, Any]:
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]
        import elftools  # type: ignore[import-untyped]
    except ModuleNotFoundError as error:
        raise FullTreeInventoryError("inventory generation requires pinned pyelftools") from error
    if getattr(elftools, "__version__", None) != "0.33":
        raise FullTreeInventoryError("inventory generation requires exactly pyelftools 0.33")
    stream, before = _artifact_stream(rich_artifact)
    try:
        observed_sha256 = _sha256_file(stream)
        if observed_sha256 != scope["oracle"]["richArtifactSha256"]:
            raise FullTreeInventoryError("rich artifact does not match the full-tree scope")
        try:
            elf = ELFFile(stream)
            if not elf.has_dwarf_info():
                raise FullTreeInventoryError("rich artifact has no DWARF information")
            dwarf = elf.get_dwarf_info(follow_links=False)
        except FullTreeInventoryError:
            raise
        except Exception as error:
            raise FullTreeInventoryError(f"cannot load rich ELF/DWARF: {error}") from error
        units: list[dict[str, Any]] = []
        limit = scope["bounds"]["wholeRun"]["compilationUnits"]
        for compilation_unit in dwarf.iter_CUs():
            if len(units) >= limit:
                raise FullTreeInventoryError(f"compilation-unit count exceeds scope bound {limit}")
            top = compilation_unit.get_top_DIE()
            label = f"DWARF compilation unit {hex(top.offset)}"
            raw_path = _raw_unit_path(top, label)
            try:
                source_path = normalize_source_path(scope, raw_path)
                shard_id = shard_for_source_path(scope, source_path)
            except FullTreeScopeError as error:
                raise FullTreeInventoryError(str(error)) from error
            producer = _attribute(top, "DW_AT_producer", label)
            producer_sha256 = None if producer is None else hashlib.sha256(
                _decode(producer, f"{label} producer").encode("utf-8"),
            ).hexdigest()
            language = _attribute(top, "DW_AT_language", label)
            if language is not None and (isinstance(language, bool) or not isinstance(language, int) or language < 0):
                raise FullTreeInventoryError(f"{label} language is invalid")
            units.append(
                {
                    "addressSize": int(compilation_unit["address_size"]),
                    "dwarfOffset": hex(int(compilation_unit.cu_offset)),
                    "dwarfVersion": int(compilation_unit["version"]),
                    "id": _unit_id(source_path),
                    "language": language,
                    "producerSha256": producer_sha256,
                    "rawPathSha256": hashlib.sha256(raw_path.encode("utf-8")).hexdigest(),
                    "shardId": shard_id,
                    "sourceKind": "generated" if source_path.startswith("generated/") else "handwritten",
                    "sourcePath": source_path,
                },
            )
        after = os.fstat(stream.fileno())
        if _stable(before) != _stable(after):
            raise FullTreeInventoryError("rich artifact changed while its inventory was generated")
    finally:
        stream.close()

    units.sort(key=lambda item: (item["sourcePath"], item["id"]))
    ids = [item["id"] for item in units]
    paths = [item["sourcePath"] for item in units]
    if len(set(ids)) != len(ids) or len(set(paths)) != len(paths):
        raise FullTreeInventoryError("compilation-unit source identities are not unique")
    by_shard: dict[str, list[str]] = defaultdict(list)
    for unit in units:
        by_shard[unit["shardId"]].append(unit["id"])
    per_shard_limit = scope["bounds"]["perShard"]["compilationUnits"]
    if any(len(unit_ids) > per_shard_limit for unit_ids in by_shard.values()):
        raise FullTreeInventoryError("a shard exceeds its compilation-unit bound")
    document = {
        "counts": {
            "compilationUnits": len(units),
            "generatedUnits": sum(item["sourceKind"] == "generated" for item in units),
            "handwrittenUnits": sum(item["sourceKind"] == "handwritten" for item in units),
            "shards": len(by_shard),
        },
        "indexSha256": _index_hash(units),
        "oracle": {
            "artifactManifestSha256": scope["oracle"]["artifactManifestSha256"],
            "id": scope["oracle"]["id"],
            "richArtifactSha256": scope["oracle"]["richArtifactSha256"],
            "scopeSha256": scope_sha256,
            "sourceLockSha256": scope["oracle"]["sourceLockSha256"],
        },
        "schemaVersion": 1,
        "shards": [{"id": shard_id, "unitIds": sorted(unit_ids)} for shard_id, unit_ids in sorted(by_shard.items())],
        "units": units,
    }
    encoded = canonical_json_bytes(document)
    if len(encoded) > scope["bounds"]["wholeRun"]["serializedBytes"]:
        raise FullTreeInventoryError("inventory exceeds whole-run serialized-byte bound")
    return document


def validate_inventory(document: dict[str, Any], scope: dict[str, Any], scope_sha256: str) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]
    except ModuleNotFoundError as error:
        raise FullTreeInventoryError("inventory validation requires pinned oracle dependencies") from error
    schema = json.loads(Path(__file__).with_name("full-tree-inventory.schema.json").read_text(encoding="utf-8"))
    try:
        fastjsonschema.compile(schema)(document)
    except fastjsonschema.JsonSchemaException as error:
        raise FullTreeInventoryError(f"inventory fails JSON Schema: {error}") from error
    units = document["units"]
    if units != sorted(units, key=lambda item: (item["sourcePath"], item["id"])):
        raise FullTreeInventoryError("inventory units are not canonically ordered")
    if document["indexSha256"] != _index_hash(units):
        raise FullTreeInventoryError("inventory index hash does not reconcile")
    if document["oracle"] != {
        "artifactManifestSha256": scope["oracle"]["artifactManifestSha256"],
        "id": scope["oracle"]["id"],
        "richArtifactSha256": scope["oracle"]["richArtifactSha256"],
        "scopeSha256": scope_sha256,
        "sourceLockSha256": scope["oracle"]["sourceLockSha256"],
    }:
        raise FullTreeInventoryError("inventory oracle bindings do not match scope")
    ids = [unit["id"] for unit in units]
    if len(set(ids)) != len(ids):
        raise FullTreeInventoryError("inventory unit IDs are not unique")
    expected_shards: dict[str, list[str]] = defaultdict(list)
    for unit in units:
        expected_shards[unit["shardId"]].append(unit["id"])
    shards = [{"id": key, "unitIds": sorted(value)} for key, value in sorted(expected_shards.items())]
    if document["shards"] != shards:
        raise FullTreeInventoryError("inventory shard ownership does not reconcile")
    expected_counts = {
        "compilationUnits": len(units),
        "generatedUnits": sum(item["sourceKind"] == "generated" for item in units),
        "handwrittenUnits": sum(item["sourceKind"] == "handwritten" for item in units),
        "shards": len(shards),
    }
    if document["counts"] != expected_counts:
        raise FullTreeInventoryError("inventory counts do not reconcile")
