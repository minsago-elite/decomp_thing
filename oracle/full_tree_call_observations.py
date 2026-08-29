"""Extract source-owned DWARF call sites with closed target classifications."""

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
from oracle.full_tree_function_observations import (
    MAX_FULL_TREE_NAME_CHARACTERS,
    _artifact_identity,
    _process_resident_bytes,
)
from oracle.full_tree_execution_evidence import (
    FullTreeExecutionEvidenceError,
    persist_shard_execution_usage,
    write_full_tree_execution_evidence,
)
from oracle.full_tree_scope import canonical_json_bytes
from oracle.function_recovery_oracle import (
    OracleGenerationError,
    _dwarf_names,
    _dwarf_starts,
    _in_executable_range,
)


class FullTreeCallObservationError(ValueError):
    """Raised when DWARF call evidence is malformed or exceeds policy."""


PRODUCER_POLICY = {
    "id": "full-tree-call-observations",
    "version": 1,
    "siteIdentity": "caller-id-return-pc-rva-or-unit-die-offset",
    "siteLocator": "dwarf-call-return-pc",
    "targetPolicy": "call-origin-address-or-closed-unresolved-classification",
}


def _configuration_sha256() -> str:
    schema = Path(__file__).with_name("full-tree-call-observations.schema.json").read_bytes()
    return hashlib.sha256(canonical_json_bytes(PRODUCER_POLICY) + schema).hexdigest()


def call_shard_inputs(
    inventory: dict[str, Any],
    *,
    scope_sha256: str,
    rich_sha256: str,
) -> tuple[list[ShardInput], dict[str, list[dict[str, Any]]]]:
    units = {unit["id"]: unit for unit in inventory["units"]}
    inputs = []
    by_shard = {}
    for shard in inventory["shards"]:
        records = [units[identifier] for identifier in shard["unitIds"]]
        payload = canonical_json_bytes(
            {
                "inventoryIndexSha256": inventory["indexSha256"],
                "producerConfigurationSha256": _configuration_sha256(),
                "richArtifactSha256": rich_sha256,
                "scopeSha256": scope_sha256,
                "shardId": shard["id"],
                "units": records,
            }
        )
        inputs.append(ShardInput(shard["id"], hashlib.sha256(payload).hexdigest()))
        by_shard[shard["id"]] = records
    return inputs, by_shard


def _address(attribute: Any, dwarf: Any, cu: Any) -> int:
    # pyelftools resolves DW_FORM_addrx* through .debug_addr while decoding the
    # DIE and retains the encoded index separately as ``raw_value``.  Resolving
    # ``value`` a second time treats the address as an index and can read beyond
    # .debug_addr on large DWARF 5 artifacts.
    value = int(attribute.value)
    if value < 0 or value >= 1 << 64:
        raise FullTreeCallObservationError("call-site address is outside unsigned 64-bit range")
    return value


def _parent_subprogram(die: Any) -> Any | None:
    current = die.get_parent()
    while current is not None:
        if current.tag == "DW_TAG_subprogram":
            return current
        current = current.get_parent()
    return None


def _target(die: Any, dwarf: Any, image_base: int, executable_ranges: tuple[tuple[int, int], ...], helpers: tuple[Any, Any, Any]) -> dict[str, Any]:
    BaseAddressEntry, RangeEntry, describe_form_class = helpers
    origin_attribute = die.attributes.get("DW_AT_call_origin")
    if origin_attribute is None:
        return {
            "aliases": [],
            "functionId": None,
            "kind": "indirect-unresolved",
            "originDieOffset": None,
        }
    try:
        origin = die.get_DIE_from_attribute("DW_AT_call_origin")
        names = sorted(
            _dwarf_names(
                origin,
                "rich",
                maximum_name_characters=MAX_FULL_TREE_NAME_CHARACTERS,
            )
        )
        starts = _dwarf_starts(
            origin,
            dwarf,
            BaseAddressEntry,
            RangeEntry,
            describe_form_class,
        )
    except (KeyError, IndexError, ValueError, OracleGenerationError) as error:
        raise FullTreeCallObservationError(
            f"cannot resolve call origin at {hex(int(die.offset))}: {error}"
        ) from error
    internal = sorted(
        address - image_base
        for address in starts
        if _in_executable_range(address, image_base, executable_ranges)
    )
    if len(internal) > 1:
        raise FullTreeCallObservationError(
            f"call origin at {hex(int(die.offset))} has ambiguous emitted starts"
        )
    return {
        "aliases": names,
        "functionId": f"function-rva-{hex(internal[0])}" if internal else None,
        "kind": "direct-internal" if internal else "external-unresolved",
        "originDieOffset": hex(int(origin.offset)),
    }


def validate_call_observation_shard(
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
        schema = json.loads(Path(__file__).with_name("full-tree-call-observations.schema.json").read_text(encoding="utf-8"))
        fastjsonschema.compile(schema)(document)
    except (ModuleNotFoundError, OSError, json.JSONDecodeError) as error:
        raise FullTreeCallObservationError(f"cannot validate call observations: {error}") from error
    except fastjsonschema.JsonSchemaException as error:
        raise FullTreeCallObservationError(f"call observations fail JSON Schema: {error}") from error
    if document["oracle"] != {
        "configurationSha256": _configuration_sha256(),
        "inventoryIndexSha256": inventory["indexSha256"],
        "richArtifactSha256": scope["oracle"]["richArtifactSha256"],
        "scopeSha256": scope_sha256,
    } or document["shard"] != {"id": shard.identifier, "inputSha256": shard.input_sha256}:
        raise FullTreeCallObservationError("call observation bindings do not match")
    calls = document["calls"]
    if calls != sorted(calls, key=lambda item: item["id"]):
        raise FullTreeCallObservationError("call observations are not identity ordered")
    if len({item["id"] for item in calls}) != len(calls):
        raise FullTreeCallObservationError("call observations contain duplicate identities")
    unit_ids = {unit["id"] for unit in units}
    if any(item["unitId"] not in unit_ids for item in calls):
        raise FullTreeCallObservationError("call observation owner is outside its shard")
    expected = {
        "observedCallSites": len(calls),
        "scannedDies": document["counts"]["scannedDies"],
        "scored": sum(item["population"] == "scored" for item in calls),
        "units": len(units),
        "unobservable": sum(item["population"] == "unobservable" for item in calls),
    }
    if document["counts"] != expected:
        raise FullTreeCallObservationError("call observation counts do not reconcile")


def produce_call_observation_shard(
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
        raise FullTreeCallObservationError("call observations require pinned pyelftools") from error
    if getattr(elftools, "__version__", None) != "0.33":
        raise FullTreeCallObservationError("call observations require exactly pyelftools 0.33")
    stream = rich_artifact.open("rb")
    try:
        elf = ELFFile(stream)
        dwarf = elf.get_dwarf_info(follow_links=False)
        loads = [segment for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD" and int(segment["p_memsz"]) > 0]
        image_base = min(int(segment["p_vaddr"]) for segment in loads)
        executable_ranges = tuple(
            sorted(
                (int(segment["p_vaddr"]) - image_base, int(segment["p_vaddr"]) + int(segment["p_memsz"]) - image_base)
                for segment in loads if int(segment["p_flags"]) & 1
            )
        )
        calls = []
        scanned_dies = 0
        helpers = (BaseAddressEntry, RangeEntry, describe_form_class)
        for unit in units:
            cu = dwarf.get_CU_at(int(unit["dwarfOffset"], 16))
            for die in cu.iter_DIEs():
                if cancelled.is_set():
                    raise FullTreeCallObservationError(f"call shard {shard.identifier} was cancelled")
                scanned_dies += 1
                if die.tag != "DW_TAG_call_site":
                    continue
                return_attribute = die.attributes.get("DW_AT_call_return_pc") or die.attributes.get("DW_AT_call_pc")
                return_address = _address(return_attribute, dwarf, cu) if return_attribute is not None else None
                return_rva = (
                    return_address - image_base
                    if return_address is not None and _in_executable_range(return_address, image_base, executable_ranges)
                    else None
                )
                caller = _parent_subprogram(die)
                caller_starts = [] if caller is None else [
                    address - image_base
                    for address in _dwarf_starts(caller, dwarf, *helpers)
                    if _in_executable_range(address, image_base, executable_ranges)
                ]
                caller_start = max((start for start in caller_starts if return_rva is not None and start <= return_rva), default=None)
                reason = "call-site-no-address" if return_rva is None else "caller-no-emitted-range" if caller_start is None else None
                identity_payload = canonical_json_bytes(
                    {"caller": hex(caller_start) if caller_start is not None else None, "die": hex(int(die.offset)), "return": hex(return_rva) if return_rva is not None else None, "unit": unit["id"]}
                )
                calls.append(
                    {
                        "callerId": f"function-rva-{hex(caller_start)}" if caller_start is not None else None,
                        "callerLocalReturnOffset": hex(return_rva - caller_start) if caller_start is not None and return_rva is not None else None,
                        "dieOffset": hex(int(die.offset)),
                        "id": "call-" + hashlib.sha256(identity_payload).hexdigest()[:32],
                        "population": "scored" if reason is None else "unobservable",
                        "reasonCode": reason,
                        "returnPcRva": hex(return_rva) if return_rva is not None else None,
                        "target": _target(die, dwarf, image_base, executable_ranges, helpers),
                        "unitId": unit["id"],
                    }
                )
            del die
            del cu
            dwarf._cu_cache.clear()
            dwarf._cu_offsets_map.clear()
            dwarf._linetable_cache.clear()
            gc.collect()
        calls.sort(key=lambda item: item["id"])
        document = {
            "calls": calls,
            "counts": {
                "observedCallSites": len(calls),
                "scannedDies": scanned_dies,
                "scored": sum(item["population"] == "scored" for item in calls),
                "units": len(units),
                "unobservable": sum(item["population"] == "unobservable" for item in calls),
            },
            "oracle": {
                "configurationSha256": _configuration_sha256(),
                "inventoryIndexSha256": inventory["indexSha256"],
                "richArtifactSha256": scope["oracle"]["richArtifactSha256"],
                "scopeSha256": scope_sha256,
            },
            "schemaVersion": 1,
            "shard": {"id": shard.identifier, "inputSha256": shard.input_sha256},
        }
        validate_call_observation_shard(document, scope=scope, scope_sha256=scope_sha256, inventory=inventory, shard=shard, units=units)
        output.write_bytes(canonical_json_bytes(document))
        return len(calls)
    except (KeyError, TypeError, ValueError, OSError, OracleGenerationError) as error:
        if isinstance(error, FullTreeCallObservationError):
            raise
        raise FullTreeCallObservationError(f"cannot observe call shard {shard.identifier}: {error}") from error
    finally:
        stream.close()


def run_full_tree_call_observations(
    rich_artifact: Path,
    *,
    scope: dict[str, Any],
    scope_sha256: str,
    inventory: dict[str, Any],
    output_root: Path,
    maximum_workers: int,
) -> dict[str, Any]:
    run_started = time.monotonic()
    rich_sha256, before = _artifact_identity(rich_artifact, scope["oracle"]["richArtifactSha256"])
    inputs, _ = call_shard_inputs(inventory, scope_sha256=scope_sha256, rich_sha256=rich_sha256)
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
    control = output_root / "control"
    control.mkdir(parents=True, exist_ok=True)
    scope_path = control / "scope.json"
    inventory_path = control / "inventory.json"
    usage_directory = output_root / "usage"
    usage_directory.mkdir(parents=True, exist_ok=True)
    for path, payload, label in (
        (scope_path, canonical_json_bytes(scope), "scope"),
        (inventory_path, canonical_json_bytes(inventory), "inventory"),
    ):
        if path.exists() and (path.is_symlink() or not path.is_file() or path.read_bytes() != payload):
            raise FullTreeCallObservationError(f"isolated call worker {label} changed")
        if not path.exists():
            path.write_bytes(payload)

    def producer(shard: ShardInput, output: Path, cancelled: threading.Event) -> int:
        worker_started = time.monotonic()
        command = [
            sys.executable,
            os.fspath(Path(__file__).resolve().parents[1] / "scripts/full-tree-call-shard-worker.py"),
            "--rich-artifact", os.fspath(rich_artifact.absolute()),
            "--scope", os.fspath(scope_path.absolute()),
            "--scope-sha256", scope_sha256,
            "--inventory", os.fspath(inventory_path.absolute()),
            "--shard", shard.identifier,
            "--input-sha256", shard.input_sha256,
            "--output", os.fspath(output.absolute()),
        ]
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        deadline = time.monotonic() + per_shard["wallClockSeconds"]
        while True:
            resident = _process_resident_bytes(process) if process.poll() is None else 0
            memory_exceeded = resident > per_shard["maximumResidentBytes"]
            if cancelled.is_set() or time.monotonic() >= deadline or memory_exceeded:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                reason = "cancelled" if cancelled.is_set() else "resident-byte bound" if memory_exceeded else "timeout"
                raise FullTreeCallObservationError(f"isolated call shard {shard.identifier} exceeded {reason}")
            try:
                stdout, stderr = process.communicate(timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                continue
        if process.returncode != 0:
            raise FullTreeCallObservationError(
                f"isolated call shard {shard.identifier} failed: {stderr[:65536].decode('utf-8', 'replace').strip()}"
            )
        if len(stdout) > 4096 or len(stderr) > 65536:
            raise FullTreeCallObservationError(f"isolated call shard {shard.identifier} exceeded control output bounds")
        try:
            usage = json.loads(stdout)
            entities = usage["entities"]
            resident = usage["maximumResidentBytes"]
            system_cpu = usage["systemCpuSeconds"]
            user_cpu = usage["userCpuSeconds"]
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise FullTreeCallObservationError(f"isolated call shard {shard.identifier} returned malformed usage") from error
        if isinstance(entities, bool) or not isinstance(entities, int) or entities < 0:
            raise FullTreeCallObservationError(f"isolated call shard {shard.identifier} returned invalid entities")
        if isinstance(resident, bool) or not isinstance(resident, int) or resident > per_shard["maximumResidentBytes"]:
            raise FullTreeCallObservationError(f"isolated call shard {shard.identifier} exceeded its resident-byte bound")
        for value, label in ((system_cpu, "system CPU"), (user_cpu, "user CPU")):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                raise FullTreeCallObservationError(
                    f"isolated call shard {shard.identifier} returned invalid {label} usage"
                )
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

    index = run_bounded_shards(
        output_root,
        run_id="full-tree-calls-" + scope_sha256[:16],
        inputs=inputs,
        bounds=bounds,
        producer=producer,
    )
    _, after = _artifact_identity(rich_artifact, rich_sha256)
    if before != after:
        raise FullTreeCallObservationError("rich artifact changed during the call run")
    try:
        write_full_tree_execution_evidence(
            output_root=output_root,
            index=index,
            per_shard_bounds=per_shard,
            whole_run_bounds=whole_run,
            run_started=run_started,
        )
    except FullTreeExecutionEvidenceError as error:
        raise FullTreeCallObservationError(str(error)) from error
    return index
