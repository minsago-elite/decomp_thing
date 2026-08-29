"""Bounded DWARF function observations for every full-tree inventory shard."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import stat
import threading
from typing import Any

from oracle.bounded_shards import ShardBounds, ShardInput, run_bounded_shards
from oracle.full_tree_scope import canonical_json_bytes
from oracle.function_recovery_oracle import (
    OracleGenerationError,
    _dwarf_names,
    _dwarf_starts,
    _in_executable_range,
)


class FullTreeFunctionObservationError(ValueError):
    """Raised when the complete DWARF inventory cannot be observed safely."""


def validate_function_observation_shard(
    document: dict[str, Any],
    *,
    scope: dict[str, Any],
    scope_sha256: str,
    inventory: dict[str, Any],
    shard: ShardInput,
    units: list[dict[str, Any]],
) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]
    except ModuleNotFoundError as error:
        raise FullTreeFunctionObservationError("observation validation requires pinned dependencies") from error
    schema_path = Path(__file__).with_name("full-tree-function-observations.schema.json")
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        fastjsonschema.compile(schema)(document)
    except (OSError, json.JSONDecodeError, fastjsonschema.JsonSchemaException) as error:
        raise FullTreeFunctionObservationError(f"function observation shard fails JSON Schema: {error}") from error
    if document["oracle"] != {
        "inventoryIndexSha256": inventory["indexSha256"],
        "richArtifactSha256": scope["oracle"]["richArtifactSha256"],
        "scopeSha256": scope_sha256,
    } or document["shard"] != {"id": shard.identifier, "inputSha256": shard.input_sha256}:
        raise FullTreeFunctionObservationError("function observation shard bindings do not match")
    unit_ids = {unit["id"] for unit in units}
    emitted = document["emitted"]
    inline_only = document["inlineOnly"]
    if emitted != sorted(emitted, key=lambda item: int(item["rva"], 16)):
        raise FullTreeFunctionObservationError("emitted observations are not ordered by RVA")
    if len({item["rva"] for item in emitted}) != len(emitted):
        raise FullTreeFunctionObservationError("emitted observations contain duplicate RVAs")
    for item in emitted:
        if item["id"] != f"function-rva-{item['rva']}":
            raise FullTreeFunctionObservationError("emitted observation identity does not match RVA")
        if item["ownerUnitIds"] != sorted(item["ownerUnitIds"]) or not set(item["ownerUnitIds"]) <= unit_ids:
            raise FullTreeFunctionObservationError("emitted observation ownership is invalid")
        if item["aliases"] != sorted(item["aliases"], key=lambda alias: alias["name"]):
            raise FullTreeFunctionObservationError("emitted aliases are not canonically ordered")
        for alias in item["aliases"]:
            if any(evidence["unitId"] not in item["ownerUnitIds"] for evidence in alias["evidence"]):
                raise FullTreeFunctionObservationError("alias evidence is outside emitted ownership")
    if inline_only != sorted(
        inline_only,
        key=lambda item: (item["unitId"], int(item["dieOffset"], 16), item["id"]),
    ):
        raise FullTreeFunctionObservationError("inline observations are not canonically ordered")
    if any(item["unitId"] not in unit_ids for item in inline_only):
        raise FullTreeFunctionObservationError("inline observation ownership is invalid")
    expected_counts = {
        "emittedRvas": len(emitted),
        "inlineOnly": len(inline_only),
        "scannedDies": document["counts"]["scannedDies"],
        "units": len(units),
    }
    if document["counts"] != expected_counts:
        raise FullTreeFunctionObservationError("function observation counts do not reconcile")
    if len(emitted) + len(inline_only) > scope["bounds"]["perShard"]["entities"]:
        raise FullTreeFunctionObservationError("function observation shard exceeds its entity bound")


def _artifact_identity(path: Path, expected_sha256: str) -> tuple[str, tuple[int, ...]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FullTreeFunctionObservationError(f"cannot open rich artifact: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 1024 * 1024 * 1024:
            raise FullTreeFunctionObservationError("rich artifact must be a regular file of 1 byte..1 GiB")
        digest = hashlib.sha256()
        while block := os.read(descriptor, 1024 * 1024):
            digest.update(block)
        observed = digest.hexdigest()
        after = os.fstat(descriptor)
        identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise FullTreeFunctionObservationError("rich artifact changed while it was authenticated")
        if observed != expected_sha256:
            raise FullTreeFunctionObservationError("rich artifact does not match the full-tree scope")
        return observed, identity
    finally:
        os.close(descriptor)


def _shard_inputs(
    inventory: dict[str, Any],
    *,
    scope_sha256: str,
    rich_sha256: str,
) -> tuple[list[ShardInput], dict[str, list[dict[str, Any]]]]:
    units = {unit["id"]: unit for unit in inventory["units"]}
    by_shard: dict[str, list[dict[str, Any]]] = {}
    inputs: list[ShardInput] = []
    for shard in inventory["shards"]:
        records = [units[identifier] for identifier in shard["unitIds"]]
        if any(record["shardId"] != shard["id"] for record in records):
            raise FullTreeFunctionObservationError("inventory shard ownership does not reconcile")
        payload = canonical_json_bytes(
            {
                "inventoryIndexSha256": inventory["indexSha256"],
                "richArtifactSha256": rich_sha256,
                "scopeSha256": scope_sha256,
                "shardId": shard["id"],
                "units": records,
            }
        )
        inputs.append(ShardInput(shard["id"], hashlib.sha256(payload).hexdigest()))
        by_shard[shard["id"]] = records
    return inputs, by_shard


def _produce_shard(
    rich_artifact: Path,
    *,
    scope: dict[str, Any],
    scope_sha256: str,
    inventory: dict[str, Any],
    shard: ShardInput,
    units: list[dict[str, Any]],
    output: Path,
    cancelled: threading.Event,
) -> int:
    try:
        from elftools.dwarf.descriptions import describe_form_class  # type: ignore[import-untyped]
        from elftools.dwarf.ranges import BaseAddressEntry, RangeEntry  # type: ignore[import-untyped]
        from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]
        import elftools  # type: ignore[import-untyped]
    except ModuleNotFoundError as error:
        raise FullTreeFunctionObservationError("function observations require pinned pyelftools") from error
    if getattr(elftools, "__version__", None) != "0.33":
        raise FullTreeFunctionObservationError("function observations require exactly pyelftools 0.33")

    try:
        stream = rich_artifact.open("rb")
        elf = ELFFile(stream)
        dwarf = elf.get_dwarf_info(follow_links=False)
        loads = [
            segment
            for segment in elf.iter_segments()
            if segment["p_type"] == "PT_LOAD" and int(segment["p_memsz"]) > 0
        ]
        image_base = min(int(segment["p_vaddr"]) for segment in loads)
        executable_ranges = tuple(
            sorted(
                (
                    int(segment["p_vaddr"]) - image_base,
                    int(segment["p_vaddr"]) + int(segment["p_memsz"]) - image_base,
                )
                for segment in loads
                if int(segment["p_flags"]) & 1
            )
        )
        by_rva: dict[int, dict[str, Any]] = {}
        inline_only: list[dict[str, Any]] = []
        scanned_dies = 0
        for unit in units:
            offset = int(unit["dwarfOffset"], 16)
            compilation_unit = dwarf.get_CU_at(offset)
            if compilation_unit is None or int(compilation_unit.cu_offset) != offset:
                raise FullTreeFunctionObservationError(f"inventory CU offset is absent: {unit['id']}")
            for die in compilation_unit.iter_DIEs():
                if cancelled.is_set():
                    raise FullTreeFunctionObservationError(
                        f"function observation shard {shard.identifier} was cancelled"
                    )
                scanned_dies += 1
                if die.tag != "DW_TAG_subprogram":
                    continue
                declaration = die.attributes.get("DW_AT_declaration")
                if declaration is not None and bool(declaration.value):
                    continue
                try:
                    starts = _dwarf_starts(
                        die,
                        dwarf,
                        BaseAddressEntry,
                        RangeEntry,
                        describe_form_class,
                    )
                    names = _dwarf_names(die, "rich")
                except OracleGenerationError as error:
                    raise FullTreeFunctionObservationError(str(error)) from error
                observed_starts = [
                    address
                    for address in starts
                    if _in_executable_range(address, image_base, executable_ranges)
                ]
                if observed_starts:
                    for address in observed_starts:
                        rva = address - image_base
                        record = by_rva.setdefault(
                            rva,
                            {"aliases": defaultdict(set), "ownerUnitIds": set()},
                        )
                        record["ownerUnitIds"].add(unit["id"])
                        for name, evidence in names.items():
                            for item in evidence:
                                record["aliases"][name].add((item.kind, item.locator, unit["id"]))
                else:
                    inline = die.attributes.get("DW_AT_inline")
                    if inline is not None and int(inline.value) in {1, 3}:
                        inline_only.append(
                            {
                                "aliases": [
                                    {
                                        "evidence": [
                                            {
                                                "kind": item.kind,
                                                "locator": item.locator,
                                                "unitId": unit["id"],
                                            }
                                            for item in evidence
                                        ],
                                        "name": name,
                                    }
                                    for name, evidence in names.items()
                                ],
                                "dieOffset": hex(int(die.offset)),
                                "id": f"inline-{unit['id']}-{hex(int(die.offset) - offset)}",
                                "reasonCode": "inline-no-emitted-range",
                                "unitId": unit["id"],
                            }
                        )
        emitted = []
        for rva, record in sorted(by_rva.items()):
            emitted.append(
                {
                    "aliases": [
                        {
                            "evidence": [
                                {"kind": kind, "locator": locator, "unitId": unit_id}
                                for kind, locator, unit_id in sorted(evidence)
                            ],
                            "name": name,
                        }
                        for name, evidence in sorted(record["aliases"].items())
                    ],
                    "id": f"function-rva-{hex(rva)}",
                    "ownerUnitIds": sorted(record["ownerUnitIds"]),
                    "rva": hex(rva),
                }
            )
        inline_only.sort(
            key=lambda item: (item["unitId"], int(item["dieOffset"], 16), item["id"])
        )
        document = {
            "counts": {
                "emittedRvas": len(emitted),
                "inlineOnly": len(inline_only),
                "scannedDies": scanned_dies,
                "units": len(units),
            },
            "emitted": emitted,
            "inlineOnly": inline_only,
            "oracle": {
                "inventoryIndexSha256": inventory["indexSha256"],
                "richArtifactSha256": scope["oracle"]["richArtifactSha256"],
                "scopeSha256": scope_sha256,
            },
            "schemaVersion": 1,
            "shard": {"id": shard.identifier, "inputSha256": shard.input_sha256},
        }
        validate_function_observation_shard(
            document,
            scope=scope,
            scope_sha256=scope_sha256,
            inventory=inventory,
            shard=shard,
            units=units,
        )
        output.write_bytes(canonical_json_bytes(document))
        return len(emitted) + len(inline_only)
    except FullTreeFunctionObservationError:
        raise
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise FullTreeFunctionObservationError(
            f"cannot observe function shard {shard.identifier}: {error}"
        ) from error
    finally:
        try:
            stream.close()
        except UnboundLocalError:
            pass


def run_full_tree_function_observations(
    rich_artifact: Path,
    *,
    scope: dict[str, Any],
    scope_sha256: str,
    inventory: dict[str, Any],
    output_root: Path,
    maximum_workers: int,
) -> dict[str, Any]:
    """Produce or resume all inventory shards without loading a monolithic model."""

    rich_sha256, before = _artifact_identity(
        rich_artifact, scope["oracle"]["richArtifactSha256"]
    )
    inputs, units = _shard_inputs(
        inventory,
        scope_sha256=scope_sha256,
        rich_sha256=rich_sha256,
    )
    per_shard = scope["bounds"]["perShard"]
    whole_run = scope["bounds"]["wholeRun"]
    bounds = ShardBounds(
        maximum_shards=len(inputs),
        per_shard_entities=per_shard["entities"],
        whole_run_entities=whole_run["entities"],
        per_shard_bytes=per_shard["serializedBytes"],
        whole_run_bytes=whole_run["serializedBytes"],
        per_shard_seconds=per_shard["wallClockSeconds"],
        whole_run_seconds=whole_run["wallClockSeconds"],
        per_shard_cpu_seconds=per_shard["cpuSeconds"],
        whole_run_cpu_seconds=whole_run["cpuSeconds"],
        maximum_resident_bytes=whole_run["maximumResidentBytes"],
        maximum_workers=min(maximum_workers, len(inputs)),
    )

    def producer(shard: ShardInput, output: Path, cancelled: threading.Event) -> int:
        return _produce_shard(
            rich_artifact,
            scope=scope,
            scope_sha256=scope_sha256,
            inventory=inventory,
            shard=shard,
            units=units[shard.identifier],
            output=output,
            cancelled=cancelled,
        )

    index = run_bounded_shards(
        output_root,
        run_id="full-tree-functions-" + scope_sha256[:16],
        inputs=inputs,
        bounds=bounds,
        producer=producer,
    )
    _, after = _artifact_identity(rich_artifact, rich_sha256)
    if before != after:
        raise FullTreeFunctionObservationError("rich artifact changed during the shard run")
    return index
