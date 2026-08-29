"""Bounded DWARF function observations for every full-tree inventory shard."""

from __future__ import annotations

from collections import defaultdict
import gc
import hashlib
import json
import os
from pathlib import Path
import posixpath
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import platform
from typing import Any

from oracle.bounded_shards import ShardBounds, ShardInput, run_bounded_shards
from oracle.full_tree_scope import (
    FullTreeScopeError,
    canonical_json_bytes,
    normalize_source_path,
)
from oracle.function_recovery_oracle import (
    OracleGenerationError,
    _attribute_chain,
    _dwarf_names,
    _dwarf_starts,
    _in_executable_range,
)


class FullTreeFunctionObservationError(ValueError):
    """Raised when the complete DWARF inventory cannot be observed safely."""


PRODUCER_POLICY = {
    "id": "full-tree-function-observations",
    "version": 3,
    "emittedIdentity": "image-relative-start-rva",
    "ownershipCandidates": "all-source-aligned-dwarf-compilation-units",
    "declarationPaths": "explicit-scope-map-or-external-path-sha256",
    "nonEmittedIdentity": "unit-id-and-die-relative-offset",
    "nonEmissionReasons": "dwarf-inline-attribute-or-definition-without-emitted-range",
    "nonEmittedCanonicalization": "declaration-and-alias-names-with-all-unit-die-locators-retained",
}
MAX_FULL_TREE_NAME_CHARACTERS = 16_384


def _configuration_sha256() -> str:
    schema = Path(__file__).with_name("full-tree-function-observations.schema.json").read_bytes()
    return hashlib.sha256(canonical_json_bytes(PRODUCER_POLICY) + schema).hexdigest()


def _accumulate_non_emitted(
    groups: dict[str, dict[str, Any]],
    item: dict[str, Any],
    *,
    shard_id: str,
) -> None:
    declaration_identity = dict(item["declaration"])
    declaration_identity.pop("unitSourcePath", None)
    identity = hashlib.sha256(
        canonical_json_bytes(
            {
                "aliasNames": sorted(alias["name"] for alias in item["aliases"]),
                "declaration": declaration_identity,
            }
        )
    ).hexdigest()[:32]
    grouped = groups.setdefault(
        identity,
        {
            "aliases": {},
            "declaration": item["declaration"],
            "dieOffsets": [],
            "id": "non-emitted-observation-"
            + hashlib.sha256(f"{shard_id}:{identity}".encode()).hexdigest()[:32],
            "reasonCodes": set(),
            "unitIds": set(),
        },
    )
    if canonical_json_bytes(grouped["declaration"]) != canonical_json_bytes(item["declaration"]):
        grouped["declaration"] = min(
            (grouped["declaration"], item["declaration"]), key=canonical_json_bytes
        )
    grouped["dieOffsets"].append(
        {"dieOffset": item["dieOffset"], "unitId": item["unitId"]}
    )
    grouped["reasonCodes"].add(item["reasonCode"])
    grouped["unitIds"].add(item["unitId"])
    for alias in item["aliases"]:
        evidence = grouped["aliases"].setdefault(alias["name"], {})
        for raw in alias["evidence"]:
            evidence[canonical_json_bytes(raw)] = raw


def _freeze_non_emitted(groups: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for identity in sorted(groups):
        item = groups.pop(identity)
        result.append(
            {
            **{key: value for key, value in item.items() if key not in {"aliases", "reasonCodes", "unitIds"}},
            "aliases": [
                {"evidence": [value for _, value in sorted(evidence.items())], "name": name}
                for name, evidence in sorted(item["aliases"].items())
            ],
            "dieOffsets": sorted(
                item["dieOffsets"],
                key=lambda value: (value["unitId"], int(value["dieOffset"], 16)),
            ),
            "reasonCodes": sorted(item["reasonCodes"]),
            "unitIds": sorted(item["unitIds"]),
            }
        )
    result.sort(key=lambda item: item["id"])
    return result


def _dwarf_text(value: Any, label: str) -> str:
    if not isinstance(value, bytes):
        raise FullTreeFunctionObservationError(f"{label} is not a DWARF byte string")
    try:
        result = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FullTreeFunctionObservationError(f"{label} is not UTF-8") from error
    if not result or "\x00" in result or len(result) > 16384:
        raise FullTreeFunctionObservationError(f"{label} is invalid")
    return result


def _declaration(die: Any, dwarf: Any, scope: dict[str, Any], unit: dict[str, Any]) -> dict[str, Any]:
    attributes: dict[str, Any] = {}
    for source in _attribute_chain(die):
        for name in ("DW_AT_decl_file", "DW_AT_decl_line", "DW_AT_decl_column"):
            if name not in attributes and name in source.attributes:
                attributes[name] = source.attributes[name].value
    file_index = attributes.get("DW_AT_decl_file")
    line = attributes.get("DW_AT_decl_line")
    column = attributes.get("DW_AT_decl_column")
    for value, label in ((file_index, "file"), (line, "line"), (column, "column")):
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise FullTreeFunctionObservationError(f"DWARF declaration {label} is invalid")
    raw_path: str | None = None
    if file_index is not None:
        line_program = dwarf.line_program_for_CU(die.cu)
        if line_program is not None:
            entries = list(line_program.header["file_entry"])
            entry_index = file_index if int(die.cu["version"]) >= 5 else file_index - 1
            if 0 <= entry_index < len(entries):
                entry = entries[entry_index]
                name = _dwarf_text(entry.name, "DWARF declaration file")
                if name.startswith("/"):
                    raw_path = name
                else:
                    directory_index = int(entry.dir_index)
                    directories = list(line_program.header["include_directory"])
                    if int(die.cu["version"]) >= 5:
                        directory = (
                            _dwarf_text(directories[directory_index], "DWARF declaration directory")
                            if 0 <= directory_index < len(directories)
                            else None
                        )
                    elif directory_index == 0:
                        directory = None
                        top_directory = die.cu.get_top_DIE().attributes.get("DW_AT_comp_dir")
                        if top_directory is not None:
                            directory = _dwarf_text(top_directory.value, "DWARF compilation directory")
                    else:
                        adjusted = directory_index - 1
                        directory = (
                            _dwarf_text(directories[adjusted], "DWARF declaration directory")
                            if 0 <= adjusted < len(directories)
                            else None
                        )
                    if directory is not None:
                        raw_path = posixpath.normpath(posixpath.join(directory, name))
    source_path: str | None = None
    external_sha256: str | None = None
    if raw_path is not None and raw_path.startswith("/"):
        try:
            source_path = normalize_source_path(scope, raw_path)
        except FullTreeScopeError:
            external_sha256 = hashlib.sha256(raw_path.encode("utf-8")).hexdigest()
    return {
        "column": column,
        "externalPathSha256": external_sha256,
        "fileIndex": file_index,
        "line": line,
        "sourcePath": source_path,
        "unitSourcePath": unit["sourcePath"],
    }


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
        "configurationSha256": _configuration_sha256(),
        "inventoryIndexSha256": inventory["indexSha256"],
        "richArtifactSha256": scope["oracle"]["richArtifactSha256"],
        "scopeSha256": scope_sha256,
    } or document["shard"] != {"id": shard.identifier, "inputSha256": shard.input_sha256}:
        raise FullTreeFunctionObservationError("function observation shard bindings do not match")
    unit_ids = {unit["id"] for unit in units}
    emitted = document["emitted"]
    non_emitted = document["nonEmitted"]
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
        if item["declarations"] != sorted(
            item["declarations"],
            key=lambda declaration: canonical_json_bytes(declaration),
        ):
            raise FullTreeFunctionObservationError("emitted declarations are not canonically ordered")
        for alias in item["aliases"]:
            if any(evidence["unitId"] not in item["ownerUnitIds"] for evidence in alias["evidence"]):
                raise FullTreeFunctionObservationError("alias evidence is outside emitted ownership")
    if non_emitted != sorted(non_emitted, key=lambda item: item["id"]):
        raise FullTreeFunctionObservationError("non-emitted observations are not canonically ordered")
    if any(not set(item["unitIds"]) <= unit_ids for item in non_emitted):
        raise FullTreeFunctionObservationError("non-emitted observation ownership is invalid")
    if len({item["id"] for item in non_emitted}) != len(non_emitted):
        raise FullTreeFunctionObservationError("non-emitted observation identities are duplicated")
    for item in non_emitted:
        if item["unitIds"] != sorted(item["unitIds"]) or item["reasonCodes"] != sorted(item["reasonCodes"]):
            raise FullTreeFunctionObservationError("non-emitted observation sets are not ordered")
        if item["dieOffsets"] != sorted(
            item["dieOffsets"], key=lambda value: (value["unitId"], int(value["dieOffset"], 16))
        ) or any(value["unitId"] not in item["unitIds"] for value in item["dieOffsets"]):
            raise FullTreeFunctionObservationError("non-emitted DIE evidence is invalid")
    expected_counts = {
        "emittedRvas": len(emitted),
        "nonEmitted": len(non_emitted),
        "nonEmittedDies": sum(len(item["dieOffsets"]) for item in non_emitted),
        "scannedDies": document["counts"]["scannedDies"],
        "units": len(units),
    }
    if document["counts"] != expected_counts:
        raise FullTreeFunctionObservationError("function observation counts do not reconcile")
    if len(emitted) + len(non_emitted) > scope["bounds"]["perShard"]["entities"]:
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


def _process_resident_bytes(process: subprocess.Popen[bytes]) -> int:
    try:
        status = Path(f"/proc/{process.pid}/status").read_text(encoding="ascii")
    except (FileNotFoundError, ProcessLookupError):
        return 0
    except OSError as error:
        raise FullTreeFunctionObservationError(
            f"cannot measure isolated shard worker {process.pid}: {error}"
        ) from error
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            fields = line.split()
            if len(fields) != 3 or fields[2] != "kB" or not fields[1].isdigit():
                break
            return int(fields[1]) * 1024
    # A freshly forked task and an exiting zombie can have a readable status
    # record before the kernel exposes an address-space RSS field. The next
    # 250 ms sample measures it once an mm exists; malformed present fields
    # still fail above.
    return 0


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
        stream_before = os.fstat(stream.fileno())
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
        non_emitted_groups: dict[str, dict[str, Any]] = {}
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
                    names = _dwarf_names(
                        die,
                        "rich",
                        maximum_name_characters=MAX_FULL_TREE_NAME_CHARACTERS,
                    )
                    declaration = _declaration(die, dwarf, scope, unit)
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
                            {
                                "aliases": defaultdict(set),
                                "declarations": {},
                                "ownerUnitIds": set(),
                            },
                        )
                        record["ownerUnitIds"].add(unit["id"])
                        declaration_payload = canonical_json_bytes(declaration)
                        record["declarations"][declaration_payload] = declaration
                        for name, evidence in names.items():
                            for item in evidence:
                                record["aliases"][name].add((item.kind, item.locator, unit["id"]))
                else:
                    inline = die.attributes.get("DW_AT_inline")
                    if names:
                        _accumulate_non_emitted(
                            non_emitted_groups,
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
                                "declaration": declaration,
                                "id": f"non-emitted-{unit['id']}-{hex(int(die.offset) - offset)}",
                                "reasonCode": (
                                    "inline-no-emitted-range"
                                    if inline is not None and int(inline.value) in {1, 3}
                                    else "definition-no-emitted-range"
                                ),
                                "unitId": unit["id"],
                            },
                            shard_id=shard.identifier,
                        )
            # pyelftools intentionally caches CUs and line tables. Keeping those
            # caches across a production subsystem makes RSS proportional to every
            # previously scanned DIE even though the emitted facts are detached.
            # The dependency is version-pinned, so clear its documented internal
            # cache pairs after each independently addressed inventory CU.
            del die
            del compilation_unit
            dwarf._cu_cache.clear()
            dwarf._cu_offsets_map.clear()
            dwarf._linetable_cache.clear()
            gc.collect()
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
                    "declarations": [
                        declaration
                        for _, declaration in sorted(record["declarations"].items())
                    ],
                    "ownerUnitIds": sorted(record["ownerUnitIds"]),
                    "rva": hex(rva),
                }
            )
        non_emitted = _freeze_non_emitted(non_emitted_groups)
        document = {
            "counts": {
                "emittedRvas": len(emitted),
                "nonEmitted": len(non_emitted),
                "nonEmittedDies": sum(len(item["dieOffsets"]) for item in non_emitted),
                "scannedDies": scanned_dies,
                "units": len(units),
            },
            "emitted": emitted,
            "nonEmitted": non_emitted,
            "oracle": {
                "configurationSha256": _configuration_sha256(),
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
        stream_after = os.fstat(stream.fileno())
        if (
            stream_before.st_dev,
            stream_before.st_ino,
            stream_before.st_size,
            stream_before.st_mtime_ns,
            stream_before.st_ctime_ns,
        ) != (
            stream_after.st_dev,
            stream_after.st_ino,
            stream_after.st_size,
            stream_after.st_mtime_ns,
            stream_after.st_ctime_ns,
        ):
            raise FullTreeFunctionObservationError("rich artifact changed during shard observation")
        output.write_bytes(canonical_json_bytes(document))
        return len(emitted) + len(non_emitted)
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
    isolate_workers: bool = False,
) -> dict[str, Any]:
    """Produce or resume all inventory shards without loading a monolithic model."""

    run_started = time.monotonic()
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

    if isolate_workers:
        control = output_root / "control"
        control.mkdir(parents=True, exist_ok=True)
        if control.is_symlink() or not control.is_dir():
            raise FullTreeFunctionObservationError("worker control directory must not be a symlink")
        scope_path = control / "scope.json"
        inventory_path = control / "inventory.json"
        usage_directory = output_root / "usage"
        usage_directory.mkdir(parents=True, exist_ok=True)
        for path, payload, label in (
            (scope_path, canonical_json_bytes(scope), "scope"),
            (inventory_path, canonical_json_bytes(inventory), "inventory"),
        ):
            if path.exists():
                if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
                    raise FullTreeFunctionObservationError(f"isolated worker {label} changed")
            else:
                path.write_bytes(payload)

        def producer(shard: ShardInput, output: Path, cancelled: threading.Event) -> int:
            worker_started = time.monotonic()
            command = [
                sys.executable,
                os.fspath(Path(__file__).resolve().parents[1] / "scripts/full-tree-function-shard-worker.py"),
                "--rich-artifact",
                os.fspath(rich_artifact.absolute()),
                "--scope",
                os.fspath(scope_path.absolute()),
                "--scope-sha256",
                scope_sha256,
                "--inventory",
                os.fspath(inventory_path.absolute()),
                "--shard",
                shard.identifier,
                "--input-sha256",
                shard.input_sha256,
                "--output",
                os.fspath(output.absolute()),
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
                    reason = (
                        "cancelled"
                        if cancelled.is_set()
                        else "exceeded its resident-byte bound"
                        if memory_exceeded
                        else "timed out"
                    )
                    raise FullTreeFunctionObservationError(
                        f"isolated function shard {shard.identifier} {reason}"
                    )
                try:
                    stdout, stderr = process.communicate(timeout=0.25)
                    break
                except subprocess.TimeoutExpired:
                    continue
            if len(stdout) > 4096 or len(stderr) > 65536:
                raise FullTreeFunctionObservationError(
                    f"isolated function shard {shard.identifier} exceeded control capture bounds"
                )
            if process.returncode != 0:
                detail = stderr.decode("utf-8", "replace").strip()
                raise FullTreeFunctionObservationError(
                    f"isolated function shard {shard.identifier} failed: {detail}"
                )
            try:
                result = json.loads(stdout.decode("utf-8"))
                entities = result["entities"]
                resident = result["maximumResidentBytes"]
                user_cpu = result["userCpuSeconds"]
                system_cpu = result["systemCpuSeconds"]
            except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
                raise FullTreeFunctionObservationError(
                    f"isolated function shard {shard.identifier} returned malformed usage"
                ) from error
            if isinstance(entities, bool) or not isinstance(entities, int) or entities < 0:
                raise FullTreeFunctionObservationError(
                    f"isolated function shard {shard.identifier} returned an invalid entity count"
                )
            if (
                isinstance(resident, bool)
                or not isinstance(resident, int)
                or resident < 0
                or resident > per_shard["maximumResidentBytes"]
            ):
                raise FullTreeFunctionObservationError(
                    f"isolated function shard {shard.identifier} exceeded its resident-byte bound"
                )
            for value, label in ((user_cpu, "user CPU"), (system_cpu, "system CPU")):
                if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                    raise FullTreeFunctionObservationError(
                        f"isolated function shard {shard.identifier} returned invalid {label} usage"
                    )
            output_payload = output.read_bytes()
            usage = canonical_json_bytes(
                {
                    "entities": entities,
                    "id": shard.identifier,
                    "inputSha256": shard.input_sha256,
                    "maximumResidentBytes": resident,
                    "outputSha256": hashlib.sha256(output_payload).hexdigest(),
                    "serializedBytes": len(output_payload),
                    "systemCpuSeconds": system_cpu,
                    "userCpuSeconds": user_cpu,
                    "wallClockSeconds": time.monotonic() - worker_started,
                }
            )
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{shard.identifier}.", suffix=".usage", dir=usage_directory
            )
            try:
                with os.fdopen(descriptor, "wb") as usage_output:
                    usage_output.write(usage)
                    usage_output.flush()
                    os.fsync(usage_output.fileno())
                os.replace(temporary_name, usage_directory / f"{shard.identifier}.json")
            finally:
                try:
                    Path(temporary_name).unlink()
                except FileNotFoundError:
                    pass
            return entities

    else:
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
    if isolate_workers:
        usage_records = []
        for checkpoint in index["shards"]:
            path = output_root / "usage" / f"{checkpoint['shardId']}.json"
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise FullTreeFunctionObservationError(
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
                raise FullTreeFunctionObservationError(
                    f"execution evidence differs from checkpoint {checkpoint['shardId']}"
                )
            usage_records.append(record)
        evidence_without_hash = {
            "bounds": {
                "perShard": per_shard,
                "wholeRun": whole_run,
            },
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
            or observed["maximumResidentBytes"] > per_shard["maximumResidentBytes"]
            or observed["userCpuSeconds"] + observed["systemCpuSeconds"] > whole_run["cpuSeconds"]
            or observed["wallClockSeconds"] > whole_run["wallClockSeconds"]
        ):
            raise FullTreeFunctionObservationError("execution evidence exceeds or differs from run bounds")
        try:
            import fastjsonschema  # type: ignore[import-untyped]
            schema = json.loads(
                Path(__file__).with_name("full-tree-execution-evidence.schema.json").read_text(encoding="utf-8")
            )
            fastjsonschema.compile(schema)(evidence)
        except ModuleNotFoundError as error:
            raise FullTreeFunctionObservationError("execution evidence validation requires pinned dependencies") from error
        except (OSError, json.JSONDecodeError, fastjsonschema.JsonSchemaException) as error:
            raise FullTreeFunctionObservationError(f"execution evidence fails validation: {error}") from error
        (output_root / "execution-evidence.json").write_bytes(canonical_json_bytes(evidence))
    return index
