"""Deterministically reconcile full-tree DWARF observations with ELF functions."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import itertools
import json
from pathlib import Path
import resource
import sqlite3
import tempfile
import time
from typing import Any, Iterable

from oracle.bounded_shards import load_complete_shard_index
from oracle.full_tree_elf_functions import validate_full_tree_elf_function_index
from oracle.full_tree_function_observations import (
    _shard_inputs,
    validate_function_observation_shard,
)
from oracle.full_tree_scope import canonical_json_bytes


class FullTreeFunctionTruthError(ValueError):
    """Raised when function populations cannot be reconciled exactly."""


PRODUCER_POLICY = {
    "id": "full-tree-function-truth",
    "version": 2,
    "emittedIdentity": "one-record-per-rva",
    "ownerSelection": "lowest-source-aligned-unit-id",
    "nonEmittedIdentity": "declaration-and-alias-name-sha256-prefix-128",
    "nonEmissionPolicy": "inline-or-definition-without-range-and-emitted-alias-reconciliation",
    "elfOnlyPopulation": "excluded-elf-no-source-aligned-dwarf",
}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _configuration_sha256() -> str:
    schemas = b"".join(
        Path(__file__).with_name(name).read_bytes()
        for name in (
            "full-tree-function-exclusions.schema.json",
            "full-tree-function-truth.schema.json",
            "full-tree-function-truth-index.schema.json",
        )
    )
    return _sha256(canonical_json_bytes(PRODUCER_POLICY) + schemas)


def _compile_schema(name: str) -> Any:
    try:
        import fastjsonschema  # type: ignore[import-untyped]
    except ModuleNotFoundError as error:
        raise FullTreeFunctionTruthError("function truth validation requires pinned dependencies") from error
    try:
        schema = json.loads(Path(__file__).with_name(name).read_text(encoding="utf-8"))
        return fastjsonschema.compile(schema)
    except (OSError, json.JSONDecodeError, fastjsonschema.JsonSchemaException) as error:
        raise FullTreeFunctionTruthError(f"cannot compile {name}: {error}") from error


def _alias_records(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence_by_name: dict[str, dict[bytes, dict[str, Any]]] = defaultdict(dict)
    for record in records:
        for alias in record["aliases"]:
            for raw in alias["evidence"]:
                evidence = {
                    "kind": raw["kind"],
                    "locator": raw["locator"],
                    "unitId": raw.get("unitId"),
                }
                evidence_by_name[alias["name"]][canonical_json_bytes(evidence)] = evidence
    return [
        {
            "name": name,
            "evidence": [item for _, item in sorted(evidence.items())],
        }
        for name, evidence in sorted(evidence_by_name.items())
    ]


def _declarations(records: Iterable[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    unique: dict[bytes, dict[str, Any]] = {}
    for record in records:
        values = record[field] if isinstance(record[field], list) else [record[field]]
        for declaration in values:
            unique[canonical_json_bytes(declaration)] = declaration
    return [item for _, item in sorted(unique.items())]


def _is_thunk(aliases: list[dict[str, Any]]) -> bool:
    return any(alias["name"].startswith(("_ZTh", "_ZTv", "_ZTc")) for alias in aliases)


def _non_emitted_identity(record: dict[str, Any]) -> str:
    declaration = dict(record["declaration"])
    declaration.pop("unitSourcePath", None)
    payload = canonical_json_bytes(
        {
            "aliasNames": sorted(alias["name"] for alias in record["aliases"]),
            "declaration": declaration,
        }
    )
    return "non-emitted-function-" + _sha256(payload)[:32]


def _write(path: Path, document: dict[str, Any]) -> dict[str, Any]:
    payload = canonical_json_bytes(document)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)
    return {"bytes": len(payload), "sha256": _sha256(payload)}


def _validate_shard(document: dict[str, Any]) -> None:
    try:
        _compile_schema("full-tree-function-truth.schema.json")(document)
    except Exception as error:
        if error.__class__.__module__.startswith("fastjsonschema"):
            raise FullTreeFunctionTruthError(f"function truth shard fails JSON Schema: {error}") from error
        raise
    functions = document["functions"]
    non_emitted = document["nonEmitted"]
    if functions != sorted(functions, key=lambda item: int(item["rva"], 16)):
        raise FullTreeFunctionTruthError("function truth records are not RVA ordered")
    if len({item["rva"] for item in functions}) != len(functions):
        raise FullTreeFunctionTruthError("function truth shard duplicates an RVA")
    if non_emitted != sorted(non_emitted, key=lambda item: item["id"]):
        raise FullTreeFunctionTruthError("non-emitted truth records are not identity ordered")
    for item in functions + non_emitted:
        if item["aliases"] != sorted(item["aliases"], key=lambda alias: alias["name"]):
            raise FullTreeFunctionTruthError("function truth aliases are not ordered")
        if item["ownerUnitId"] not in document["shard"]["unitIds"]:
            raise FullTreeFunctionTruthError("function truth owner is outside its shard")
    for item in functions:
        if item["entityKind"] != ("thunk" if _is_thunk(item["aliases"]) else "function"):
            raise FullTreeFunctionTruthError("function/thunk classification contradicts authenticated aliases")
        expected_emission = (
            "coalesced-odr-or-comdat"
            if len(item["ownershipCandidates"]) > 1
            else "single-definition"
        )
        if item["emissionKind"] != expected_emission:
            raise FullTreeFunctionTruthError("COMDAT/ODR emission classification contradicts ownership evidence")
    if document["counts"] != {"functions": len(functions), "nonEmitted": len(non_emitted)}:
        raise FullTreeFunctionTruthError("function truth shard counts do not reconcile")


def _database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        PRAGMA journal_mode=DELETE;
        PRAGMA synchronous=FULL;
        CREATE TABLE elf (rva INTEGER PRIMARY KEY, payload BLOB NOT NULL);
        CREATE TABLE emitted (rva INTEGER NOT NULL, shard_id TEXT NOT NULL, payload BLOB NOT NULL,
                              PRIMARY KEY (rva, shard_id));
        CREATE TABLE non_emitted (identity TEXT NOT NULL, shard_id TEXT NOT NULL, unit_id TEXT NOT NULL,
                             observation_id TEXT NOT NULL UNIQUE, payload BLOB NOT NULL);
        CREATE INDEX emitted_rva ON emitted(rva);
        CREATE INDEX non_emitted_identity ON non_emitted(identity);
        """
    )
    return connection


def _check_runtime_bounds(
    scope: dict[str, Any],
    *,
    started: float,
    cpu_started: float,
    database_path: Path,
) -> None:
    bounds = scope["bounds"]["wholeRun"]
    if time.monotonic() - started > bounds["wallClockSeconds"]:
        raise FullTreeFunctionTruthError("function truth merge exceeded its wall-clock bound")
    if time.process_time() - cpu_started > bounds["cpuSeconds"]:
        raise FullTreeFunctionTruthError("function truth merge exceeded its CPU-time bound")
    if int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024 > bounds["maximumResidentBytes"]:
        raise FullTreeFunctionTruthError("function truth merge exceeded its resident-byte bound")
    try:
        database_bytes = database_path.stat().st_size
    except FileNotFoundError:
        database_bytes = 0
    if database_bytes > bounds["serializedBytes"]:
        raise FullTreeFunctionTruthError("function truth merge database exceeded its byte bound")


def validate_full_tree_function_truth_index(
    index: dict[str, Any],
    *,
    output_root: Path,
    scope: dict[str, Any],
    scope_sha256: str,
    inventory: dict[str, Any],
    observation_index_sha256: str,
    elf_index_sha256: str,
) -> None:
    """Validate bindings, file hashes, ownership, and every population equation."""

    try:
        _compile_schema("full-tree-function-truth-index.schema.json")(index)
    except Exception as error:
        raise FullTreeFunctionTruthError(f"function truth index fails JSON Schema: {error}") from error
    expected_oracle = {
        "configurationSha256": _configuration_sha256(),
        "elfIndexSha256": elf_index_sha256,
        "inventoryIndexSha256": inventory["indexSha256"],
        "observationIndexSha256": observation_index_sha256,
        "scopeSha256": scope_sha256,
    }
    if index["oracle"] != expected_oracle:
        raise FullTreeFunctionTruthError("function truth index bindings do not match")
    if index["indexSha256"] != _sha256(
        canonical_json_bytes({key: value for key, value in index.items() if key != "indexSha256"})
    ):
        raise FullTreeFunctionTruthError("function truth index hash does not reconcile")
    expected_shards = {item["id"]: item for item in inventory["shards"]}
    if [item["id"] for item in index["shards"]] != sorted(expected_shards):
        raise FullTreeFunctionTruthError("function truth index does not cover every inventory shard")
    seen_rvas: set[str] = set()
    seen_non_emitted: set[str] = set()
    scored = 0
    dwarf_only = 0
    coalesced_emitted = 0
    non_emitted_observations = 0
    reason_counts: dict[str, int] = defaultdict(int)
    emitted_alias_names: set[str] = set()
    non_emitted_records: list[dict[str, Any]] = []
    for record in index["shards"]:
        path = output_root / record["path"]
        payload = path.read_bytes()
        if record["bytes"] != len(payload) or record["sha256"] != _sha256(payload):
            raise FullTreeFunctionTruthError(f"function truth shard {record['id']} changed")
        document = json.loads(payload.decode("utf-8"))
        if payload != canonical_json_bytes(document):
            raise FullTreeFunctionTruthError(f"function truth shard {record['id']} is not canonical")
        if document["oracle"] != expected_oracle or document["shard"] != expected_shards[record["id"]]:
            raise FullTreeFunctionTruthError(f"function truth shard {record['id']} bindings do not match")
        _validate_shard(document)
        if record["functions"] != len(document["functions"]) or record["nonEmitted"] != len(document["nonEmitted"]):
            raise FullTreeFunctionTruthError(f"function truth shard {record['id']} index counts differ")
        for function in document["functions"]:
            if function["rva"] in seen_rvas:
                raise FullTreeFunctionTruthError(f"function RVA {function['rva']} has duplicate ownership")
            seen_rvas.add(function["rva"])
            emitted_alias_names.update(alias["name"] for alias in function["aliases"])
            if function["emissionKind"] == "coalesced-odr-or-comdat":
                coalesced_emitted += 1
            if function["population"] == "scored":
                scored += 1
            else:
                dwarf_only += 1
        for item in document["nonEmitted"]:
            non_emitted_records.append(item)
            if item["id"] in seen_non_emitted:
                raise FullTreeFunctionTruthError(f"non-emitted identity {item['id']} has duplicate ownership")
            seen_non_emitted.add(item["id"])
            non_emitted_observations += len(item["observationDieOffsets"])
            reason_counts[item["reasonCode"]] += 1
    for item in non_emitted_records:
        overlaps_emitted = any(alias["name"] in emitted_alias_names for alias in item["aliases"])
        if item["reasonCode"] == "comdat-or-odr-selected-elsewhere" and not overlaps_emitted:
            raise FullTreeFunctionTruthError("selected-elsewhere reason lacks emitted alias evidence")
    exclusion_record = index["exclusions"]
    exclusion_path = output_root / exclusion_record["path"]
    exclusion_payload = exclusion_path.read_bytes()
    if (
        exclusion_record["bytes"] != len(exclusion_payload)
        or exclusion_record["sha256"] != _sha256(exclusion_payload)
    ):
        raise FullTreeFunctionTruthError("function truth exclusions changed")
    exclusions = json.loads(exclusion_payload.decode("utf-8"))
    _compile_schema("full-tree-function-exclusions.schema.json")(exclusions)
    if exclusion_payload != canonical_json_bytes(exclusions) or exclusions["oracle"] != expected_oracle:
        raise FullTreeFunctionTruthError("function truth exclusions are noncanonical or misbound")
    exclusion_rvas = [item["rva"] for item in exclusions["functions"]]
    if exclusion_rvas != sorted(exclusion_rvas, key=lambda value: int(value, 16)):
        raise FullTreeFunctionTruthError("ELF-only exclusions are not RVA ordered")
    if len(set(exclusion_rvas)) != len(exclusion_rvas) or seen_rvas.intersection(exclusion_rvas):
        raise FullTreeFunctionTruthError("ELF-only exclusions duplicate a function RVA")
    if exclusion_record["functions"] != len(exclusion_rvas) or exclusion_record["nonEmitted"] != 0:
        raise FullTreeFunctionTruthError("ELF-only exclusion index counts differ")
    expected_counts = {
        "dwarfOnlyRvas": dwarf_only,
        "dwarfRvas": len(seen_rvas),
        "elfOnlyRvas": len(exclusion_rvas),
        "elfRvas": scored + len(exclusion_rvas),
        "nonEmittedObservations": non_emitted_observations,
        "nonEmittedUnique": len(seen_non_emitted),
        "inlineOnlyUnique": reason_counts["inline-no-emitted-range"],
        "selectedElsewhereUnique": reason_counts["comdat-or-odr-selected-elsewhere"],
        "definitionNoRangeUnique": reason_counts["definition-no-emitted-range"],
        "coalescedEmittedRvas": coalesced_emitted,
        "scoredRvas": scored,
    }
    if index["counts"] != expected_counts:
        raise FullTreeFunctionTruthError("function truth aggregate counts do not reconcile")
    if expected_counts["elfRvas"] > scope["bounds"]["wholeRun"]["entities"]:
        raise FullTreeFunctionTruthError("function truth exceeds the whole-run entity bound")


def reconcile_full_tree_function_truth(
    *,
    scope: dict[str, Any],
    scope_sha256: str,
    inventory: dict[str, Any],
    elf_index_path: Path,
    observation_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Merge bounded inputs through disk-backed state and publish only complete truth."""

    started = time.monotonic()
    cpu_started = time.process_time()
    observation_index = load_complete_shard_index(observation_root)
    observation_index_payload = (observation_root / "index.json").read_bytes()
    elf_payload = elf_index_path.read_bytes()
    try:
        elf_index = json.loads(elf_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FullTreeFunctionTruthError(f"ELF function index is not valid UTF-8 JSON: {error}") from error
    if elf_payload != canonical_json_bytes(elf_index):
        raise FullTreeFunctionTruthError("ELF function index is not canonical")
    validate_full_tree_elf_function_index(
        elf_index,
        scope=scope,
        scope_sha256=scope_sha256,
        inventory=inventory,
    )
    inputs, units_by_shard = _shard_inputs(
        inventory,
        scope_sha256=scope_sha256,
        rich_sha256=scope["oracle"]["richArtifactSha256"],
    )
    expected = {item.identifier: item for item in inputs}
    if [item["shardId"] for item in observation_index["shards"]] != sorted(expected):
        raise FullTreeFunctionTruthError("observation index does not cover the inventory shards")
    unit_to_shard = {unit["id"]: unit["shardId"] for unit in inventory["units"]}
    oracle = {
        "configurationSha256": _configuration_sha256(),
        "elfIndexSha256": _sha256(elf_payload),
        "inventoryIndexSha256": inventory["indexSha256"],
        "observationIndexSha256": _sha256(observation_index_payload),
        "scopeSha256": scope_sha256,
    }
    output_root.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=".function-truth-", suffix=".sqlite", dir=output_root) as database_file:
        connection = _database(Path(database_file.name))
        database_path = Path(database_file.name)
        try:
            connection.executemany(
                "INSERT INTO elf VALUES (?, ?)",
                ((int(item["rva"], 16), canonical_json_bytes(item)) for item in elf_index["functions"]),
            )
            for record in observation_index["shards"]:
                shard_id = record["shardId"]
                path = observation_root / "outputs" / f"{shard_id}.json"
                payload = path.read_bytes()
                if _sha256(payload) != record["outputSha256"]:
                    raise FullTreeFunctionTruthError(f"observation shard {shard_id} changed")
                document = json.loads(payload.decode("utf-8"))
                validate_function_observation_shard(
                    document,
                    scope=scope,
                    scope_sha256=scope_sha256,
                    inventory=inventory,
                    shard=expected[shard_id],
                    units=units_by_shard[shard_id],
                )
                connection.executemany(
                    "INSERT INTO emitted VALUES (?, ?, ?)",
                    ((int(item["rva"], 16), shard_id, canonical_json_bytes(item)) for item in document["emitted"]),
                )
                connection.executemany(
                    "INSERT INTO non_emitted VALUES (?, ?, ?, ?, ?)",
                    (
                        (_non_emitted_identity(item), shard_id, min(item["unitIds"]), item["id"], canonical_json_bytes(item))
                        for item in document["nonEmitted"]
                    ),
                )
                connection.commit()
                _check_runtime_bounds(
                    scope,
                    started=started,
                    cpu_started=cpu_started,
                    database_path=database_path,
                )

            functions_by_shard: dict[str, list[dict[str, Any]]] = defaultdict(list)
            exclusions: list[dict[str, Any]] = []
            dwarf_rvas = 0
            scored_rvas = 0
            dwarf_only = 0
            coalesced_emitted = 0
            emitted_cursor = connection.execute(
                "SELECT r.rva, e.payload, d.payload "
                "FROM (SELECT rva FROM elf UNION SELECT rva FROM emitted) r "
                "LEFT JOIN elf e ON e.rva=r.rva "
                "LEFT JOIN emitted d ON d.rva=r.rva "
                "ORDER BY r.rva,d.shard_id"
            )
            for rva_index, (rva, rows) in enumerate(
                itertools.groupby(emitted_cursor, key=lambda row: row[0])
            ):
                if rva_index % 4096 == 0:
                    _check_runtime_bounds(
                        scope,
                        started=started,
                        cpu_started=cpu_started,
                        database_path=database_path,
                    )
                joined = list(rows)
                elf_raw = joined[0][1]
                dwarf_records = [json.loads(row[2]) for row in joined if row[2] is not None]
                if not dwarf_records:
                    elf_record = json.loads(elf_raw)
                    exclusions.append(
                        {
                            "aliases": _alias_records([elf_record]),
                            "id": elf_record["id"],
                            "reasonCode": "elf-no-source-aligned-dwarf",
                            "rva": elf_record["rva"],
                        }
                    )
                    continue
                dwarf_rvas += 1
                candidates = sorted({unit for record in dwarf_records for unit in record["ownerUnitIds"]})
                owner = candidates[0]
                elf_record = json.loads(elf_raw) if elf_raw is not None else None
                aliases = _alias_records(dwarf_records + ([elf_record] if elf_record else []))
                item = {
                    "aliases": aliases,
                    "declarations": _declarations(dwarf_records, "declarations"),
                    "entityKind": "thunk" if _is_thunk(aliases) else "function",
                    "emissionKind": (
                        "coalesced-odr-or-comdat" if len(candidates) > 1 else "single-definition"
                    ),
                    "id": f"function-rva-{hex(rva)}",
                    "ownerUnitId": owner,
                    "ownershipCandidates": candidates,
                    "population": "scored" if elf_record else "excluded",
                    "reasonCode": None if elf_record else "dwarf-rva-without-elf-function",
                    "rva": hex(rva),
                }
                functions_by_shard[unit_to_shard[owner]].append(item)
                if elf_record:
                    scored_rvas += 1
                    if len(candidates) > 1:
                        coalesced_emitted += 1
                else:
                    dwarf_only += 1

            emitted_alias_names = {
                alias["name"]
                for functions in functions_by_shard.values()
                for function in functions
                for alias in function["aliases"]
            }
            non_emitted_by_shard: dict[str, list[dict[str, Any]]] = defaultdict(list)
            non_emitted_observations = 0
            non_emitted_cursor = connection.execute(
                "SELECT identity,payload FROM non_emitted ORDER BY identity,observation_id"
            )
            for non_emitted_index, (identity, rows) in enumerate(
                itertools.groupby(non_emitted_cursor, key=lambda row: row[0])
            ):
                if non_emitted_index % 4096 == 0:
                    _check_runtime_bounds(
                        scope,
                        started=started,
                        cpu_started=cpu_started,
                        database_path=database_path,
                    )
                records = [json.loads(row[1]) for row in rows]
                owner = min(unit for item in records for unit in item["unitIds"])
                alias_names = {alias["name"] for item in records for alias in item["aliases"]}
                observed_reasons = {reason for item in records for reason in item["reasonCodes"]}
                observation_die_offsets = sorted(
                    {
                        canonical_json_bytes(locator): locator
                        for item in records for locator in item["dieOffsets"]
                    }.values(),
                    key=lambda value: (value["unitId"], int(value["dieOffset"], 16)),
                )
                non_emitted_observations += len(observation_die_offsets)
                if "definition-no-emitted-range" in observed_reasons:
                    reason_code = (
                        "comdat-or-odr-selected-elsewhere"
                        if alias_names.intersection(emitted_alias_names)
                        else "definition-no-emitted-range"
                    )
                else:
                    reason_code = "inline-no-emitted-range"
                non_emitted_by_shard[unit_to_shard[owner]].append(
                    {
                        "aliases": _alias_records(records),
                        "declarations": _declarations(records, "declaration"),
                        "id": identity,
                        "observationIds": sorted(item["id"] for item in records),
                        "observationDieOffsets": observation_die_offsets,
                        "ownerUnitId": owner,
                        "population": "unobservable",
                        "reasonCode": reason_code,
                    }
                )

            shard_files = []
            shard_validator = _compile_schema("full-tree-function-truth.schema.json")
            for shard in inventory["shards"]:
                shard_id = shard["id"]
                document = {
                    "counts": {
                        "functions": len(functions_by_shard[shard_id]),
                        "nonEmitted": len(non_emitted_by_shard[shard_id]),
                    },
                    "functions": functions_by_shard[shard_id],
                    "nonEmitted": sorted(non_emitted_by_shard[shard_id], key=lambda item: item["id"]),
                    "oracle": oracle,
                    "schemaVersion": 1,
                    "shard": {"id": shard_id, "unitIds": shard["unitIds"]},
                }
                shard_validator(document)
                _validate_shard(document)
                relative = f"shards/{shard_id}.json"
                written = _write(output_root / relative, document)
                shard_files.append(
                    {"id": shard_id, "path": relative, **written, **document["counts"]}
                )

            exclusions_document = {
                "functions": exclusions,
                "oracle": oracle,
                "reasonCode": "elf-no-source-aligned-dwarf",
                "schemaVersion": 1,
            }
            _compile_schema("full-tree-function-exclusions.schema.json")(exclusions_document)
            exclusion_written = _write(output_root / "exclusions.json", exclusions_document)
            exclusion_file = {
                "id": "elf-only-exclusions",
                "path": "exclusions.json",
                **exclusion_written,
                "functions": len(exclusions),
                "nonEmitted": 0,
            }
            counts = {
                "dwarfOnlyRvas": dwarf_only,
                "dwarfRvas": dwarf_rvas,
                "elfOnlyRvas": len(exclusions),
                "elfRvas": len(elf_index["functions"]),
                "nonEmittedObservations": non_emitted_observations,
                "nonEmittedUnique": sum(len(items) for items in non_emitted_by_shard.values()),
                "inlineOnlyUnique": sum(item["reasonCode"] == "inline-no-emitted-range" for items in non_emitted_by_shard.values() for item in items),
                "selectedElsewhereUnique": sum(item["reasonCode"] == "comdat-or-odr-selected-elsewhere" for items in non_emitted_by_shard.values() for item in items),
                "definitionNoRangeUnique": sum(item["reasonCode"] == "definition-no-emitted-range" for items in non_emitted_by_shard.values() for item in items),
                "coalescedEmittedRvas": coalesced_emitted,
                "scoredRvas": scored_rvas,
            }
            if counts["elfRvas"] != counts["scoredRvas"] + counts["elfOnlyRvas"]:
                raise FullTreeFunctionTruthError("ELF function denominator does not reconcile")
            if counts["dwarfRvas"] != counts["scoredRvas"] + counts["dwarfOnlyRvas"]:
                raise FullTreeFunctionTruthError("DWARF function denominator does not reconcile")
            total_entities = counts["elfRvas"] + counts["dwarfOnlyRvas"] + counts["nonEmittedUnique"]
            if total_entities > scope["bounds"]["wholeRun"]["entities"]:
                raise FullTreeFunctionTruthError("function truth exceeds its whole-run entity bound")
            index_without_hash = {
                "complete": True,
                "counts": counts,
                "exclusions": exclusion_file,
                "oracle": oracle,
                "schemaVersion": 1,
                "shards": shard_files,
            }
            index = {
                **index_without_hash,
                "indexSha256": _sha256(canonical_json_bytes(index_without_hash)),
            }
            validate_full_tree_function_truth_index(
                index,
                output_root=output_root,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                observation_index_sha256=oracle["observationIndexSha256"],
                elf_index_sha256=oracle["elfIndexSha256"],
            )
            total_output_bytes = sum(item["bytes"] for item in shard_files) + exclusion_file["bytes"]
            if total_output_bytes > scope["bounds"]["wholeRun"]["serializedBytes"]:
                raise FullTreeFunctionTruthError("function truth exceeds its whole-run output bound")
            _check_runtime_bounds(
                scope,
                started=started,
                cpu_started=cpu_started,
                database_path=database_path,
            )
            _write(output_root / "index.json", index)
            return index
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as error:
            if isinstance(error, FullTreeFunctionTruthError):
                raise
            raise FullTreeFunctionTruthError(f"cannot reconcile full-tree function truth: {error}") from error
        finally:
            connection.close()
