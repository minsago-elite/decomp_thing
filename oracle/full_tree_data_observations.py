"""Extract bounded DWARF globals and aggregate-layout observations."""

from __future__ import annotations

import gc
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from typing import Any

from oracle.bounded_shards import ShardBounds, ShardInput, run_bounded_shards
from oracle.full_tree_function_observations import _artifact_identity, _declaration, _process_resident_bytes
from oracle.full_tree_execution_evidence import (
    FullTreeExecutionEvidenceError,
    persist_shard_execution_usage,
    write_full_tree_execution_evidence,
)
from oracle.full_tree_scope import canonical_json_bytes
from oracle.function_recovery_oracle import _attribute_chain, _decode_dwarf_string


class FullTreeDataObservationError(ValueError):
    """Raised when global/type evidence cannot be represented exactly."""


POLICY = {
    "id": "full-tree-data-observations",
    "version": 4,
    "globals": "static-storage-or-linkage-bearing-dwarf-variables",
    "types": "class-struct-union-enum-definitions-and-declarations",
    "typeReferences": "compact-immediate-and-aggregate-dwarf-offsets-with-modifier-chain-or-closed-reason",
}

TYPE_TAGS = {
    "DW_TAG_class_type": "class",
    "DW_TAG_structure_type": "struct",
    "DW_TAG_union_type": "union",
    "DW_TAG_enumeration_type": "enum",
}


def _configuration_sha256() -> str:
    schema = Path(__file__).with_name("full-tree-data-observations.schema.json").read_bytes()
    return hashlib.sha256(canonical_json_bytes(POLICY) + schema).hexdigest()


def data_shard_inputs(inventory: dict[str, Any], *, scope_sha256: str, rich_sha256: str) -> tuple[list[ShardInput], dict[str, list[dict[str, Any]]]]:
    units = {unit["id"]: unit for unit in inventory["units"]}
    inputs = []
    grouped = {}
    for shard in inventory["shards"]:
        records = [units[item] for item in shard["unitIds"]]
        payload = canonical_json_bytes(
            {"configurationSha256": _configuration_sha256(), "inventoryIndexSha256": inventory["indexSha256"], "richArtifactSha256": rich_sha256, "scopeSha256": scope_sha256, "shardId": shard["id"], "units": records}
        )
        inputs.append(ShardInput(shard["id"], hashlib.sha256(payload).hexdigest()))
        grouped[shard["id"]] = records
    return inputs, grouped


def _integer_attribute(die: Any, name: str) -> int | None:
    for source in _attribute_chain(die):
        attribute = source.attributes.get(name)
        if attribute is not None and isinstance(attribute.value, int) and not isinstance(attribute.value, bool):
            return int(attribute.value)
    return None


def _name(die: Any) -> str | None:
    attribute = die.attributes.get("DW_AT_name")
    return _decode_dwarf_string(attribute.value, f"DIE {hex(int(die.offset))} name", 16_384) if attribute else None


def _names(die: Any) -> list[str]:
    result = set()
    for source in _attribute_chain(die):
        for key in ("DW_AT_linkage_name", "DW_AT_MIPS_linkage_name", "DW_AT_name"):
            attribute = source.attributes.get(key)
            if attribute is not None:
                result.add(_decode_dwarf_string(attribute.value, f"DIE {hex(int(die.offset))} {key}", 16_384))
    return sorted(result)


def _type_context(die: Any) -> list[str]:
    components = []
    current = die.get_parent()
    context_tags = {
        "DW_TAG_class_type",
        "DW_TAG_enumeration_type",
        "DW_TAG_namespace",
        "DW_TAG_structure_type",
        "DW_TAG_subprogram",
        "DW_TAG_union_type",
    }
    while current is not None and current.tag != "DW_TAG_compile_unit":
        if current.tag in context_tags:
            name = _name(current)
            if current.tag == "DW_TAG_namespace" and name is None:
                name = "(anonymous namespace)"
            components.append(f"{current.tag}:{name or '(anonymous)'}")
        current = current.get_parent()
    return list(reversed(components))


def _type_reference(die: Any) -> tuple[list[Any], Any | None]:
    if "DW_AT_type" not in die.attributes:
        return [None, None, [], "no-type-attribute"], None
    target = die.get_DIE_from_attribute("DW_AT_type")
    immediate = target
    offsets: list[str] = []
    modifiers: list[str] = []
    seen: set[int] = set()
    for _ in range(64):
        offset = int(target.offset)
        if offset in seen:
            raise FullTreeDataObservationError(
                f"cyclic DWARF type reference at {hex(offset)}"
            )
        seen.add(offset)
        offsets.append(hex(offset))
        if target.tag in TYPE_TAGS:
            return [offsets[0], hex(offset), modifiers, None], immediate
        modifiers.append(target.tag)
        if "DW_AT_type" not in target.attributes:
            return [offsets[0], None, modifiers, "non-aggregate-terminal-type"], immediate
        target = target.get_DIE_from_attribute("DW_AT_type")
    raise FullTreeDataObservationError("DWARF type reference exceeds 64 links")


def _location(die: Any, dwarf: Any, image_base: int) -> tuple[int | None, bool]:
    attribute = die.attributes.get("DW_AT_location")
    if attribute is None or not isinstance(attribute.value, (bytes, bytearray, list, tuple)):
        return None, False
    from elftools.dwarf.dwarf_expr import DWARFExprParser  # type: ignore[import-untyped]
    try:
        expression = bytes(attribute.value)
    except (TypeError, ValueError):
        return None, False
    operations = DWARFExprParser(die.cu.structs).parse_expr(expression)
    tls = any(operation.op_name in {"DW_OP_form_tls_address", "DW_OP_GNU_push_tls_address"} for operation in operations)
    if tls and len(operations) == 2 and operations[1].op_name in {"DW_OP_form_tls_address", "DW_OP_GNU_push_tls_address"} and operations[0].op_name in {"DW_OP_const1u", "DW_OP_const2u", "DW_OP_const4u", "DW_OP_const8u", "DW_OP_constu"}:
        return int(operations[0].args[0]), True
    if len(operations) == 1 and operations[0].op_name == "DW_OP_addr":
        address = int(operations[0].args[0])
        return address - image_base if address >= image_base else None, tls
    return None, tls


def _member(child: Any) -> dict[str, Any]:
    kind = {"DW_TAG_member": "field", "DW_TAG_inheritance": "base", "DW_TAG_enumerator": "enumerator"}[child.tag]
    reference, _ = _type_reference(child)
    byte_offset = _integer_attribute(child, "DW_AT_data_member_location")
    return {
        "bitOffset": _integer_attribute(child, "DW_AT_data_bit_offset") or _integer_attribute(child, "DW_AT_bit_offset"),
        "bitSize": _integer_attribute(child, "DW_AT_bit_size"),
        "byteOffset": byte_offset,
        "kind": kind,
        "name": _name(child),
        "typeReference": reference,
        "value": _integer_attribute(child, "DW_AT_const_value") if kind == "enumerator" else None,
        "virtuality": _integer_attribute(child, "DW_AT_virtuality") if kind == "base" else None,
    }


def validate_data_observation_shard(document: dict[str, Any], *, scope: dict[str, Any], scope_sha256: str, inventory: dict[str, Any], shard: ShardInput, units: list[dict[str, Any]]) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]
        schema = json.loads(Path(__file__).with_name("full-tree-data-observations.schema.json").read_text(encoding="utf-8"))
        fastjsonschema.compile(schema)(document)
    except Exception as error:
        raise FullTreeDataObservationError(f"data observations fail validation: {error}") from error
    expected_oracle = {"configurationSha256": _configuration_sha256(), "inventoryIndexSha256": inventory["indexSha256"], "richArtifactSha256": scope["oracle"]["richArtifactSha256"], "scopeSha256": scope_sha256}
    if document["oracle"] != expected_oracle or document["shard"] != {"id": shard.identifier, "inputSha256": shard.input_sha256}:
        raise FullTreeDataObservationError("data observation bindings do not match")
    if document["globals"] != sorted(document["globals"], key=lambda item: item["id"]) or document["types"] != sorted(document["types"], key=lambda item: item["id"]):
        raise FullTreeDataObservationError("data observations are not ordered")
    unit_ids = {unit["id"] for unit in units}
    if any(item["unitId"] not in unit_ids for item in document["globals"] + document["types"]):
        raise FullTreeDataObservationError("data observation owner is outside its shard")
    expected = {
        "bases": sum(member["kind"] == "base" for item in document["types"] for member in item["members"]),
        "enumerators": sum(member["kind"] == "enumerator" for item in document["types"] for member in item["members"]),
        "fields": sum(member["kind"] == "field" for item in document["types"] for member in item["members"]),
        "globals": len(document["globals"]), "scannedDies": document["counts"]["scannedDies"],
        "types": len(document["types"]), "units": len(units),
    }
    if document["counts"] != expected:
        raise FullTreeDataObservationError("data observation counts do not reconcile")


def produce_data_observation_shard(rich_artifact: Path, *, scope: dict[str, Any], scope_sha256: str, inventory: dict[str, Any], shard: ShardInput, units: list[dict[str, Any]], output: Path, cancelled: threading.Event) -> int:
    from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]
    stream = rich_artifact.open("rb")
    try:
        elf = ELFFile(stream)
        dwarf = elf.get_dwarf_info(follow_links=False)
        loads = [segment for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD" and int(segment["p_memsz"]) > 0]
        image_base = min(int(segment["p_vaddr"]) for segment in loads)
        globals_ = []
        types = []
        scanned = 0
        for unit in units:
            cu = dwarf.get_CU_at(int(unit["dwarfOffset"], 16))
            for die in cu.iter_DIEs():
                if cancelled.is_set():
                    raise FullTreeDataObservationError(f"data shard {shard.identifier} was cancelled")
                scanned += 1
                if die.tag in TYPE_TAGS:
                    members = [_member(child) for child in die.iter_children() if child.tag in {"DW_TAG_member", "DW_TAG_inheritance", "DW_TAG_enumerator"}]
                    identity = hashlib.sha256(f"{unit['id']}:{hex(int(die.offset))}".encode()).hexdigest()[:32]
                    types.append({"alignment": _integer_attribute(die, "DW_AT_alignment"), "byteSize": _integer_attribute(die, "DW_AT_byte_size"), "context": _type_context(die), "declaration": _declaration(die, dwarf, scope, unit), "declarationOnly": bool(_integer_attribute(die, "DW_AT_declaration") or 0), "dieOffset": hex(int(die.offset)), "id": f"type-observation-{identity}", "members": members, "name": _name(die), "tag": TYPE_TAGS[die.tag], "unitId": unit["id"]})
                elif die.tag == "DW_TAG_variable":
                    names = _names(die)
                    parent = die.get_parent()
                    external = bool(_integer_attribute(die, "DW_AT_external") or 0)
                    address, tls = _location(die, dwarf, image_base)
                    if not names or not (
                        external
                        or parent is None
                        or parent.tag in {"DW_TAG_compile_unit", "DW_TAG_namespace"}
                        or any(name.startswith("_Z") for name in names)
                        or address is not None
                        or tls
                    ):
                        continue
                    type_reference, type_die = _type_reference(die)
                    identity = hashlib.sha256(f"{unit['id']}:{hex(int(die.offset))}".encode()).hexdigest()[:32]
                    visibility = {1: "local", 2: "exported", 3: "qualified"}.get(_integer_attribute(die, "DW_AT_visibility"), "default" if external else "unknown")
                    globals_.append({"addressRva": hex(address) if address is not None else None, "alignment": _integer_attribute(type_die, "DW_AT_alignment") if type_die else None, "declaration": _declaration(die, dwarf, scope, unit), "dieOffset": hex(int(die.offset)), "external": external, "id": f"global-observation-{identity}", "mutability": "constant" if "DW_AT_const_value" in die.attributes else "mutable" if address is not None or tls else "unknown", "names": names, "reasonCode": None if address is not None else "tls-no-image-rva" if tls else "optimized-out-or-nonaddress-location", "size": _integer_attribute(type_die, "DW_AT_byte_size") if type_die else None, "tls": tls, "typeReference": type_reference, "unitId": unit["id"], "visibility": visibility})
            del die
            del cu
            dwarf._cu_cache.clear()
            dwarf._cu_offsets_map.clear()
            dwarf._linetable_cache.clear()
            gc.collect()
        globals_.sort(key=lambda item: item["id"]); types.sort(key=lambda item: item["id"])
        counts = {"bases": sum(member["kind"] == "base" for item in types for member in item["members"]), "enumerators": sum(member["kind"] == "enumerator" for item in types for member in item["members"]), "fields": sum(member["kind"] == "field" for item in types for member in item["members"]), "globals": len(globals_), "scannedDies": scanned, "types": len(types), "units": len(units)}
        document = {"counts": counts, "globals": globals_, "oracle": {"configurationSha256": _configuration_sha256(), "inventoryIndexSha256": inventory["indexSha256"], "richArtifactSha256": scope["oracle"]["richArtifactSha256"], "scopeSha256": scope_sha256}, "schemaVersion": 1, "shard": {"id": shard.identifier, "inputSha256": shard.input_sha256}, "types": types}
        validate_data_observation_shard(document, scope=scope, scope_sha256=scope_sha256, inventory=inventory, shard=shard, units=units)
        output.write_bytes(canonical_json_bytes(document))
        return len(globals_) + len(types)
    finally:
        stream.close()


def run_full_tree_data_observations(rich_artifact: Path, *, scope: dict[str, Any], scope_sha256: str, inventory: dict[str, Any], output_root: Path, maximum_workers: int) -> dict[str, Any]:
    run_started = time.monotonic()
    rich_sha256, before = _artifact_identity(rich_artifact, scope["oracle"]["richArtifactSha256"])
    inputs, _ = data_shard_inputs(inventory, scope_sha256=scope_sha256, rich_sha256=rich_sha256)
    per_shard = scope["bounds"]["perShard"]
    whole = scope["bounds"]["wholeRun"]
    bounds = ShardBounds(
        maximum_shards=len(inputs), per_shard_entities=per_shard["entities"], whole_run_entities=whole["entities"],
        per_shard_bytes=per_shard["serializedBytes"], whole_run_bytes=whole["serializedBytes"],
        per_shard_seconds=per_shard["wallClockSeconds"], whole_run_seconds=whole["wallClockSeconds"],
        per_shard_cpu_seconds=per_shard["cpuSeconds"], whole_run_cpu_seconds=whole["cpuSeconds"],
        maximum_resident_bytes=whole["maximumResidentBytes"], maximum_workers=min(maximum_workers, len(inputs)),
    )
    control = output_root / "control"
    control.mkdir(parents=True, exist_ok=True)
    scope_path = control / "scope.json"
    inventory_path = control / "inventory.json"
    usage_directory = output_root / "usage"
    usage_directory.mkdir(parents=True, exist_ok=True)
    for path, payload, label in ((scope_path, canonical_json_bytes(scope), "scope"), (inventory_path, canonical_json_bytes(inventory), "inventory")):
        if path.exists() and (path.is_symlink() or not path.is_file() or path.read_bytes() != payload):
            raise FullTreeDataObservationError(f"isolated data worker {label} changed")
        if not path.exists():
            path.write_bytes(payload)

    def producer(shard: ShardInput, output: Path, cancelled: threading.Event) -> int:
        worker_started = time.monotonic()
        process = subprocess.Popen(
            [sys.executable, os.fspath(Path(__file__).resolve().parents[1] / "scripts/full-tree-data-shard-worker.py"),
             "--rich-artifact", os.fspath(rich_artifact.absolute()), "--scope", os.fspath(scope_path.absolute()),
             "--scope-sha256", scope_sha256, "--inventory", os.fspath(inventory_path.absolute()),
             "--shard", shard.identifier, "--input-sha256", shard.input_sha256, "--output", os.fspath(output.absolute())],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        deadline = time.monotonic() + per_shard["wallClockSeconds"]
        while True:
            resident = _process_resident_bytes(process) if process.poll() is None else 0
            over_memory = resident > per_shard["maximumResidentBytes"]
            if cancelled.is_set() or time.monotonic() >= deadline or over_memory:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); process.wait()
                raise FullTreeDataObservationError(f"isolated data shard {shard.identifier} exceeded a runtime bound")
            try:
                stdout, stderr = process.communicate(timeout=0.25); break
            except subprocess.TimeoutExpired:
                continue
        if process.returncode != 0:
            raise FullTreeDataObservationError(f"isolated data shard {shard.identifier} failed: {stderr[:65536].decode('utf-8', 'replace').strip()}")
        if len(stdout) > 4096 or len(stderr) > 65536:
            raise FullTreeDataObservationError(f"isolated data shard {shard.identifier} exceeded control output bounds")
        try:
            usage = json.loads(stdout); entities = usage["entities"]; resident = usage["maximumResidentBytes"]; system_cpu = usage["systemCpuSeconds"]; user_cpu = usage["userCpuSeconds"]
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise FullTreeDataObservationError(f"isolated data shard {shard.identifier} returned malformed usage") from error
        if isinstance(entities, bool) or not isinstance(entities, int) or entities < 0:
            raise FullTreeDataObservationError(f"isolated data shard {shard.identifier} returned invalid entities")
        if isinstance(resident, bool) or not isinstance(resident, int) or resident > per_shard["maximumResidentBytes"]:
            raise FullTreeDataObservationError(f"isolated data shard {shard.identifier} exceeded its resident-byte bound")
        for value, label in ((system_cpu, "system CPU"), (user_cpu, "user CPU")):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                raise FullTreeDataObservationError(f"isolated data shard {shard.identifier} returned invalid {label} usage")
        persist_shard_execution_usage(
            usage_directory=usage_directory,
            shard=shard,
            output=output,
            entities=entities,
            maximum_resident_bytes=resident,
            user_cpu_seconds=user_cpu,
            system_cpu_seconds=system_cpu,
            wall_clock_seconds=time.monotonic() - worker_started,
        )
        return entities

    index = run_bounded_shards(output_root, run_id="full-tree-data-" + scope_sha256[:16], inputs=inputs, bounds=bounds, producer=producer)
    _, after = _artifact_identity(rich_artifact, rich_sha256)
    if before != after:
        raise FullTreeDataObservationError("rich artifact changed during the data run")
    try:
        write_full_tree_execution_evidence(
            output_root=output_root,
            index=index,
            per_shard_bounds=per_shard,
            whole_run_bounds=whole,
            run_started=run_started,
        )
    except FullTreeExecutionEvidenceError as error:
        raise FullTreeDataObservationError(str(error)) from error
    return index
