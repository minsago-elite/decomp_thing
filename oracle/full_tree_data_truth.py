"""ODR-aware reconciliation for full-tree globals and aggregate layouts."""

from __future__ import annotations
import hashlib, itertools, json, resource, sqlite3, tempfile, time
from pathlib import Path
from typing import Any, Iterable

from oracle.bounded_shards import load_complete_shard_index
from oracle.full_tree_data_observations import data_shard_inputs, validate_data_observation_shard
from oracle.full_tree_scope import canonical_json_bytes


class FullTreeDataTruthError(ValueError):
    """Raised when ODR-equivalent data evidence is incompatible or incomplete."""


POLICY = {"id": "full-tree-data-truth", "version": 11, "typeIdentity": "tag-qualified-lexical-context-name-or-anonymous-declaration-with-observation-owned-lambda-and-lossy-local-contexts", "globalIdentity": "rva-or-source-aligned-name-declaration-or-producer-observation", "owner": "lowest-unit-id", "typeReferences": "exact-dwarf-offset-chain-with-bounded-authenticated-candidate-commitments-and-no-ambiguous-target-substitution", "maximumDatabaseBytes": 8 * 1024 * 1024 * 1024}

REFERENCE_SAMPLE_LIMIT = 16


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _configuration_sha256() -> str:
    return _sha(canonical_json_bytes(POLICY) + Path(__file__).with_name("full-tree-data-truth.schema.json").read_bytes())


def _check_runtime_bounds(
    scope: dict[str, Any], *, started: float, cpu_started: float, database_path: Path
) -> None:
    bounds = scope["bounds"]["wholeRun"]
    if time.monotonic() - started > bounds["wallClockSeconds"]:
        raise FullTreeDataTruthError("data truth merge exceeded its wall-clock bound")
    if time.process_time() - cpu_started > bounds["cpuSeconds"]:
        raise FullTreeDataTruthError("data truth merge exceeded its CPU-time bound")
    if int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024 > bounds["maximumResidentBytes"]:
        raise FullTreeDataTruthError("data truth merge exceeded its resident-byte bound")
    if database_path.exists() and database_path.stat().st_size > POLICY["maximumDatabaseBytes"]:
        raise FullTreeDataTruthError("data truth merge database exceeded its byte bound")


def _declaration_key(declaration: dict[str, Any]) -> dict[str, Any]:
    return {key: declaration[key] for key in ("sourcePath", "externalPathSha256", "line", "column")}


def _type_key(item: dict[str, Any]) -> str:
    declaration = _declaration_key(item["declaration"])
    observable_location = declaration["sourcePath"] is not None or declaration["externalPathSha256"] is not None
    if observable_location:
        identity = {"tag": item["tag"], "context": item["context"], "name": item["name"], "declaration": declaration}
        if (item["name"] is not None and "lambda at " in item["name"]) or "DW_TAG_subprogram:(anonymous)" in item["context"]:
            identity["producerObservationId"] = item["id"]
        elif (item["name"] is not None and "anonymous namespace" in item["name"]) or any("anonymous namespace" in component for component in item["context"]):
            identity["producerUnitId"] = item["unitId"]
    else:
        identity = {"observationId": item["id"]}
    return _sha(canonical_json_bytes(identity))


def _global_key(item: dict[str, Any]) -> str:
    declaration = _declaration_key(item["declaration"])
    observable_location = declaration["sourcePath"] is not None or declaration["externalPathSha256"] is not None
    if item["addressRva"] is not None:
        identity = {"rva": item["addressRva"]}
    elif observable_location:
        identity = {"names": item["names"], "declaration": declaration}
    else:
        identity = {"observationId": item["id"]}
    return _sha(canonical_json_bytes(identity))


def _unique(records: Iterable[dict[str, Any]], field: str) -> list[Any]:
    values = {canonical_json_bytes(item[field]): item[field] for item in records}
    return [value for _, value in sorted(values.items())]


def _one_compatible(records: list[dict[str, Any]], field: str, identity: str) -> Any:
    known = {canonical_json_bytes(item[field]): item[field] for item in records if item[field] is not None and item[field] != "unknown"}
    if len(known) > 1:
        raise FullTreeDataTruthError(f"incompatible {field} definitions for {identity}")
    return next(iter(known.values()), None)


def _type_layout(item: dict[str, Any]) -> bytes:
    members = [
        {
            **{key: member[key] for key in ("kind", "name", "byteOffset", "bitOffset", "bitSize", "value", "virtuality")},
            "typeReference": {
                key: member["typeReference"][key]
                for key in ("modifierTags", "reasonCode")
            },
        }
        for member in item["members"]
    ]
    return canonical_json_bytes({"alignment": item["alignment"], "byteSize": item["byteSize"], "members": members})


def _resolve_type_reference(
    reference: dict[str, Any],
    database: sqlite3.Connection,
    unit_to_shard: dict[str, str],
) -> dict[str, Any]:
    immediate_offset, aggregate_offset, modifier_tags, reason_code = reference
    if aggregate_offset is None:
        return {
            "evidenceDieOffsets": [] if immediate_offset is None else [immediate_offset],
            "modifierTags": modifier_tags,
            "reasonCode": reason_code,
            "resolutionCode": "unresolved",
            "targetOwnerShardId": None,
            "targetTypeId": None,
            "_targetQuality": None,
        }
    row = database.execute(
        "SELECT target.identity,MIN(owner.unit_id),target.quality "
        "FROM type_targets target JOIN type_targets owner ON owner.identity=target.identity "
        "WHERE target.die_offset=? GROUP BY target.identity",
        (aggregate_offset,),
    ).fetchone()
    if row is None:
        raise FullTreeDataTruthError(
            f"aggregate reference {aggregate_offset} is outside the authenticated type index"
        )
    return {
        "evidenceDieOffsets": sorted({immediate_offset, aggregate_offset}, key=lambda value: int(value, 16)),
        "modifierTags": modifier_tags,
        "reasonCode": None,
        "resolutionCode": "exact-dwarf-offset",
        "targetOwnerShardId": unit_to_shard[row[1]],
        "targetTypeId": f"type-{row[0][:32]}",
        "_targetQuality": row[2],
    }


def _merge_type_references(references: Iterable[dict[str, Any]], identity: str) -> dict[str, Any]:
    records = list(references)
    modifiers = {canonical_json_bytes(item["modifierTags"]) for item in records}
    reasons = {item["reasonCode"] for item in records}
    if len(modifiers) != 1 or len(reasons) != 1:
        raise FullTreeDataTruthError(f"incompatible type references for {identity}")
    candidates = {
        canonical_json_bytes(
            {
                "targetOwnerShardId": item["targetOwnerShardId"],
                "targetTypeId": item["targetTypeId"],
            }
        ): {
            "targetOwnerShardId": item["targetOwnerShardId"],
            "targetTypeId": item["targetTypeId"],
        }
        for item in records
        if item["targetTypeId"] is not None
    }
    ordered_candidates = [value for _, value in sorted(candidates.items())]
    targets = {item["targetTypeId"] for item in ordered_candidates}
    if not targets:
        selected = records[0]
        resolution_code = "unresolved"
    elif len(targets) == 1:
        selected = next(item for item in records if item["targetTypeId"] is not None)
        resolution_code = "exact-dwarf-offset"
    else:
        source_aligned = {
            item["targetTypeId"]
            for item in records
            if item["_targetQuality"] == "source-aligned"
        }
        other_qualities = {
            item["_targetQuality"]
            for item in records
            if item["targetTypeId"] not in source_aligned
        }
        if len(source_aligned) == 1 and other_qualities <= {"producer-declaration"}:
            selected_id = next(iter(source_aligned))
            selected = next(item for item in records if item["targetTypeId"] == selected_id)
            resolution_code = "odr-member-sole-source-aligned-target"
        elif not source_aligned and other_qualities <= {"producer-declaration", "producer-definition"}:
            selected = {**records[0], "reasonCode": "ambiguous-producer-only-targets", "targetOwnerShardId": None, "targetTypeId": None}
            resolution_code = "unresolved-authenticated-target-set"
        else:
            raise FullTreeDataTruthError(f"incompatible type references for {identity}")
    evidence_offsets = sorted(
        {offset for item in records for offset in item["evidenceDieOffsets"]},
        key=lambda value: int(value, 16),
    )
    if selected["targetTypeId"] is not None:
        ordered_candidates.sort(
            key=lambda item: (
                item["targetTypeId"] != selected["targetTypeId"],
                canonical_json_bytes(item),
            )
        )
    return {
        "candidateTargetCount": len(ordered_candidates),
        "candidateTargets": ordered_candidates[:REFERENCE_SAMPLE_LIMIT],
        "candidateTargetsSha256": _sha(canonical_json_bytes(ordered_candidates)),
        "evidenceDieOffsetCount": len(evidence_offsets),
        "evidenceDieOffsets": evidence_offsets[:REFERENCE_SAMPLE_LIMIT],
        "evidenceDieOffsetsSha256": _sha(canonical_json_bytes(evidence_offsets)),
        "modifierTags": selected["modifierTags"],
        "reasonCode": selected["reasonCode"],
        "resolutionCode": resolution_code,
        "targetOwnerShardId": selected["targetOwnerShardId"],
        "targetTypeId": selected["targetTypeId"],
    }


def _validate_document(document: dict[str, Any]) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]
        schema = json.loads(Path(__file__).with_name("full-tree-data-truth.schema.json").read_text(encoding="utf-8"))
        fastjsonschema.compile(schema)(document)
    except Exception as error:
        raise FullTreeDataTruthError(f"data truth fails schema validation: {error}") from error
    if document["types"] != sorted(document["types"], key=lambda item: item["id"]) or document["globals"] != sorted(document["globals"], key=lambda item: item["id"]):
        raise FullTreeDataTruthError("data truth records are not ordered")
    expected = {
        "ambiguousTypeReferences": sum(
            reference["resolutionCode"] == "unresolved-authenticated-target-set"
            for item in document["globals"]
            for reference in [item["typeReference"]]
        ) + sum(
            member["typeReference"]["resolutionCode"] == "unresolved-authenticated-target-set"
            for item in document["types"] for member in item["members"]
        ),
        "bases": sum(member["kind"] == "base" for item in document["types"] for member in item["members"]),
        "enumerators": sum(member["kind"] == "enumerator" for item in document["types"] for member in item["members"]),
        "fields": sum(member["kind"] == "field" for item in document["types"] for member in item["members"]),
        "globals": len(document["globals"]), "types": len(document["types"]),
        "unobservableGlobals": sum(item["population"] == "unobservable" for item in document["globals"]),
        "unobservableTypes": sum(item["population"] == "unobservable" for item in document["types"]),
        "resolvedTypeReferences": sum(
            reference["targetTypeId"] is not None
            for item in document["globals"]
            for reference in [item["typeReference"]]
        ) + sum(
            member["typeReference"]["targetTypeId"] is not None
            for item in document["types"] for member in item["members"]
        ),
        "unresolvedTypeReferences": sum(
            reference["targetTypeId"] is None
            for item in document["globals"]
            for reference in [item["typeReference"]]
        ) + sum(
            member["typeReference"]["targetTypeId"] is None
            for item in document["types"] for member in item["members"]
        ),
        "crossShardTypeReferences": sum(
            reference["targetOwnerShardId"] is not None and reference["targetOwnerShardId"] != document["shard"]["id"]
            for item in document["globals"]
            for reference in [item["typeReference"]]
        ) + sum(
            member["typeReference"]["targetOwnerShardId"] is not None and member["typeReference"]["targetOwnerShardId"] != document["shard"]["id"]
            for item in document["types"] for member in item["members"]
        ),
    }
    if document["counts"] != expected:
        raise FullTreeDataTruthError("data truth counts do not reconcile")


def validate_full_tree_data_truth_index(
    index: dict[str, Any],
    *,
    output_root: Path,
    scope_sha256: str,
    inventory: dict[str, Any],
) -> None:
    """Validate every data-truth shard and its independently hashed index."""

    try:
        import fastjsonschema  # type: ignore[import-untyped]

        schema = json.loads(
            Path(__file__).with_name("full-tree-data-truth-index.schema.json").read_text(encoding="utf-8")
        )
        fastjsonschema.compile(schema)(index)
    except Exception as error:
        raise FullTreeDataTruthError(f"data truth index fails schema validation: {error}") from error
    without_hash = {key: value for key, value in index.items() if key != "indexSha256"}
    if index.get("indexSha256") != _sha(canonical_json_bytes(without_hash)):
        raise FullTreeDataTruthError("data truth index hash does not reconcile")
    oracle = index.get("oracle")
    if not isinstance(oracle, dict):
        raise FullTreeDataTruthError("data truth index has no oracle bindings")
    if oracle.get("scopeSha256") != scope_sha256 or oracle.get("inventoryIndexSha256") != inventory["indexSha256"]:
        raise FullTreeDataTruthError("data truth index scope or inventory binding differs")
    expected_ids = [shard["id"] for shard in inventory["shards"]]
    records = index.get("shards")
    if not isinstance(records, list) or [record.get("id") for record in records] != expected_ids:
        raise FullTreeDataTruthError("data truth shard population or ordering differs")
    aggregate: dict[str, int] = {}
    documents: list[dict[str, Any]] = []
    type_owners: dict[str, str] = {}
    for record, inventory_shard in zip(records, inventory["shards"], strict=True):
        path = output_root / record["path"]
        payload = path.read_bytes()
        if len(payload) != record["bytes"] or _sha(payload) != record["sha256"]:
            raise FullTreeDataTruthError(f"data truth shard {record['id']} changed")
        document = json.loads(payload)
        documents.append(document)
        _validate_document(document)
        if document["oracle"] != oracle or document["shard"] != {
            "id": record["id"],
            "unitIds": inventory_shard["unitIds"],
        }:
            raise FullTreeDataTruthError(f"data truth shard {record['id']} bindings differ")
        for name, value in document["counts"].items():
            if record.get(name) != value:
                raise FullTreeDataTruthError(f"data truth shard {record['id']} count differs")
            aggregate[name] = aggregate.get(name, 0) + value
        for item in document["types"]:
            if item["id"] in type_owners:
                raise FullTreeDataTruthError(f"duplicate canonical type identity {item['id']}")
            type_owners[item["id"]] = record["id"]
    if index.get("counts") != dict(sorted(aggregate.items())):
        raise FullTreeDataTruthError("data truth aggregate counts do not reconcile")
    for document in documents:
        references = [item["typeReference"] for item in document["globals"]] + [
            member["typeReference"]
            for item in document["types"]
            for member in item["members"]
        ]
        for reference in references:
            target = reference["targetTypeId"]
            owner = reference["targetOwnerShardId"]
            candidates = reference["candidateTargets"]
            if reference["candidateTargetCount"] < len(candidates):
                raise FullTreeDataTruthError("type reference candidate sample exceeds its committed count")
            if reference["evidenceDieOffsetCount"] < len(reference["evidenceDieOffsets"]):
                raise FullTreeDataTruthError("type reference evidence sample exceeds its committed count")
            if reference["candidateTargetCount"] == len(candidates) and reference["candidateTargetsSha256"] != _sha(canonical_json_bytes(candidates)):
                raise FullTreeDataTruthError("type reference candidate commitment differs")
            if reference["evidenceDieOffsetCount"] == len(reference["evidenceDieOffsets"]) and reference["evidenceDieOffsetsSha256"] != _sha(canonical_json_bytes(reference["evidenceDieOffsets"])):
                raise FullTreeDataTruthError("type reference evidence commitment differs")
            for candidate in candidates:
                if type_owners.get(candidate["targetTypeId"]) != candidate["targetOwnerShardId"]:
                    raise FullTreeDataTruthError("type reference candidate has a dangling or substituted owner")
            if target is None:
                if owner is not None or reference["reasonCode"] is None:
                    raise FullTreeDataTruthError("unresolved type reference has contradictory evidence")
                if reference["resolutionCode"] == "unresolved-authenticated-target-set" and reference["candidateTargetCount"] < 2:
                    raise FullTreeDataTruthError("ambiguous type reference has fewer than two candidates")
            elif reference["reasonCode"] is not None or type_owners.get(target) != owner:
                raise FullTreeDataTruthError(
                    f"type reference {target} has a dangling or substituted owner"
                )
            elif not any(candidate["targetTypeId"] == target and candidate["targetOwnerShardId"] == owner for candidate in candidates):
                raise FullTreeDataTruthError("resolved type reference is absent from its candidate evidence")


def generate_full_tree_data_truth(*, scope: dict[str, Any], scope_sha256: str, inventory: dict[str, Any], observation_root: Path, output_root: Path) -> dict[str, Any]:
    started = time.monotonic(); cpu_started = time.process_time()
    observation_index = load_complete_shard_index(observation_root)
    observation_payload = (observation_root / "index.json").read_bytes()
    inputs, units = data_shard_inputs(inventory, scope_sha256=scope_sha256, rich_sha256=scope["oracle"]["richArtifactSha256"])
    expected = {item.identifier: item for item in inputs}
    unit_to_shard = {unit["id"]: unit["shardId"] for unit in inventory["units"]}
    oracle = {"configurationSha256": _configuration_sha256(), "dataObservationIndexSha256": _sha(observation_payload), "inventoryIndexSha256": inventory["indexSha256"], "scopeSha256": scope_sha256}
    output_root.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=".data-truth-", suffix=".sqlite", dir=output_root) as temporary:
        database = sqlite3.connect(temporary.name)
        try:
            database.executescript("CREATE TABLE observations (kind TEXT, identity TEXT, observation_id TEXT PRIMARY KEY, payload BLOB); CREATE INDEX observations_identity ON observations(kind,identity); CREATE TABLE type_targets (die_offset TEXT PRIMARY KEY, identity TEXT NOT NULL, unit_id TEXT NOT NULL, quality TEXT NOT NULL); CREATE INDEX type_targets_identity ON type_targets(identity); CREATE TABLE merged (kind TEXT, owner_shard TEXT, identity TEXT PRIMARY KEY, payload BLOB); CREATE INDEX merged_owner ON merged(owner_shard,kind,identity);")
            for checkpoint in observation_index["shards"]:
                _check_runtime_bounds(scope, started=started, cpu_started=cpu_started, database_path=Path(temporary.name))
                shard_id = checkpoint["shardId"]
                payload = (observation_root / "outputs" / f"{shard_id}.json").read_bytes()
                if _sha(payload) != checkpoint["outputSha256"]:
                    raise FullTreeDataTruthError(f"data observation shard {shard_id} changed")
                document = json.loads(payload)
                validate_data_observation_shard(document, scope=scope, scope_sha256=scope_sha256, inventory=inventory, shard=expected[shard_id], units=units[shard_id])
                database.executemany("INSERT INTO type_targets VALUES (?,?,?,?)", ((item["dieOffset"], _type_key(item), item["unitId"], "source-aligned" if item["declaration"]["sourcePath"] is not None or item["declaration"]["externalPathSha256"] is not None else "producer-declaration" if item["declarationOnly"] else "producer-definition") for item in document["types"]))
                database.executemany("INSERT INTO observations VALUES ('type',?,?,?)", ((_type_key(item), item["id"], canonical_json_bytes(item)) for item in document["types"]))
                database.executemany("INSERT INTO observations VALUES ('global',?,?,?)", ((_global_key(item), item["id"], canonical_json_bytes(item)) for item in document["globals"]))
                database.commit()

            cursor = database.execute("SELECT kind,identity,payload FROM observations ORDER BY kind,identity,observation_id")
            for merge_index, ((kind, identity), rows) in enumerate(itertools.groupby(cursor, key=lambda row: (row[0], row[1]))):
                if merge_index % 4096 == 0: _check_runtime_bounds(scope, started=started, cpu_started=cpu_started, database_path=Path(temporary.name))
                records = [json.loads(row[2]) for row in rows]
                owner = min(item["unitId"] for item in records)
                if kind == "type":
                    records = [
                        {
                            **item,
                            "members": [
                                {
                                    **member,
                                    "typeReference": _resolve_type_reference(
                                        member["typeReference"], database, unit_to_shard
                                    ),
                                }
                                for member in item["members"]
                            ],
                        }
                        for item in records
                    ]
                    definitions = [item for item in records if not item["declarationOnly"]]
                    layouts = {_type_layout(item) for item in definitions}
                    if len(layouts) > 1:
                        raise FullTreeDataTruthError(f"incompatible aggregate definitions for type-{identity[:32]}")
                    layout_records = definitions if definitions else records
                    layout = layout_records[0]
                    layout = {
                        **layout,
                        "members": [
                            {
                                **member,
                                "typeReference": _merge_type_references(
                                    [item["members"][member_index]["typeReference"] for item in layout_records],
                                    f"type-{identity[:32]}-member-{member_index}",
                                ),
                            }
                            for member_index, member in enumerate(layout["members"])
                        ],
                    }
                    merged = {"alignment": layout["alignment"], "byteSize": layout["byteSize"], "context": layout["context"], "declarations": _unique(records, "declaration"), "id": f"type-{identity[:32]}", "members": layout["members"], "name": layout["name"], "observationIds": sorted(item["id"] for item in records), "ownerUnitId": owner, "population": "scored" if definitions and layout["byteSize"] is not None else "unobservable", "reasonCode": None if definitions and layout["byteSize"] is not None else "declaration-only-or-size-unobservable", "tag": layout["tag"]}
                else:
                    address = _one_compatible(records, "addressRva", identity)
                    references = [_resolve_type_reference(item["typeReference"], database, unit_to_shard) for item in records]
                    merged = {"addressRva": address, "alignment": _one_compatible(records, "alignment", identity), "declarations": _unique(records, "declaration"), "external": bool(_one_compatible(records, "external", identity) or False), "id": f"global-{identity[:32]}", "mutability": _one_compatible(records, "mutability", identity) or "unknown", "names": sorted({name for item in records for name in item["names"]}), "observationIds": sorted(item["id"] for item in records), "ownerUnitId": owner, "population": "scored" if address is not None else "unobservable", "reasonCode": None if address is not None else records[0]["reasonCode"], "size": _one_compatible(records, "size", identity), "tls": bool(_one_compatible(records, "tls", identity) or False), "typeReference": _merge_type_references(references, f"global-{identity[:32]}"), "visibility": _one_compatible(records, "visibility", identity) or "unknown"}
                database.execute("INSERT INTO merged VALUES (?,?,?,?)", (kind, unit_to_shard[owner], identity, canonical_json_bytes(merged)))
            database.commit()
            shard_records = []; aggregate: dict[str, int] = {}; total_output_bytes = 0
            for shard in inventory["shards"]:
                _check_runtime_bounds(scope, started=started, cpu_started=cpu_started, database_path=Path(temporary.name))
                globals_ = [json.loads(row[0]) for row in database.execute("SELECT payload FROM merged WHERE owner_shard=? AND kind='global' ORDER BY identity", (shard["id"],))]
                types = [json.loads(row[0]) for row in database.execute("SELECT payload FROM merged WHERE owner_shard=? AND kind='type' ORDER BY identity", (shard["id"],))]
                references = [item["typeReference"] for item in globals_] + [member["typeReference"] for item in types for member in item["members"]]
                counts = {"ambiguousTypeReferences": sum(item["resolutionCode"] == "unresolved-authenticated-target-set" for item in references), "bases": sum(member["kind"] == "base" for item in types for member in item["members"]), "crossShardTypeReferences": sum(item["targetOwnerShardId"] is not None and item["targetOwnerShardId"] != shard["id"] for item in references), "enumerators": sum(member["kind"] == "enumerator" for item in types for member in item["members"]), "fields": sum(member["kind"] == "field" for item in types for member in item["members"]), "globals": len(globals_), "resolvedTypeReferences": sum(item["targetTypeId"] is not None for item in references), "types": len(types), "unobservableGlobals": sum(item["population"] == "unobservable" for item in globals_), "unobservableTypes": sum(item["population"] == "unobservable" for item in types), "unresolvedTypeReferences": sum(item["targetTypeId"] is None for item in references)}
                document = {"counts": counts, "globals": globals_, "oracle": oracle, "schemaVersion": 1, "shard": {"id": shard["id"], "unitIds": shard["unitIds"]}, "types": types}
                _validate_document(document)
                payload = canonical_json_bytes(document)
                entities = counts["globals"] + counts["types"]
                if entities > scope["bounds"]["perShard"]["entities"]:
                    raise FullTreeDataTruthError(f"data truth shard {shard['id']} exceeds its entity bound")
                if len(payload) > scope["bounds"]["perShard"]["serializedBytes"]:
                    raise FullTreeDataTruthError(f"data truth shard {shard['id']} exceeds its byte bound")
                total_output_bytes += len(payload)
                relative = f"shards/{shard['id']}.json"; path = output_root / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(payload)
                shard_records.append({"id": shard["id"], "path": relative, "bytes": len(payload), "sha256": _sha(payload), **counts})
                for name, value in counts.items(): aggregate[name] = aggregate.get(name, 0) + value
            total_entities = aggregate.get("globals", 0) + aggregate.get("types", 0)
            if total_entities > scope["bounds"]["wholeRun"]["entities"]:
                raise FullTreeDataTruthError("data truth exceeds its whole-run entity bound")
            if total_output_bytes > scope["bounds"]["wholeRun"]["serializedBytes"]:
                raise FullTreeDataTruthError("data truth exceeds its whole-run output bound")
            without_hash = {"complete": True, "counts": dict(sorted(aggregate.items())), "oracle": oracle, "schemaVersion": 1, "shards": shard_records}
            index = {**without_hash, "indexSha256": _sha(canonical_json_bytes(without_hash))}; (output_root / "index.json").write_bytes(canonical_json_bytes(index)); validate_full_tree_data_truth_index(index, output_root=output_root, scope_sha256=scope_sha256, inventory=inventory); return index
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as error:
            if isinstance(error, FullTreeDataTruthError): raise
            raise FullTreeDataTruthError(f"cannot generate data truth: {error}") from error
        finally:
            database.close()
