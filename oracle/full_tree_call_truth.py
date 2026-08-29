"""Resolve DWARF call observations through authenticated function namespaces."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
from typing import Any

from oracle.bounded_shards import load_complete_shard_index
from oracle.full_tree_call_observations import call_shard_inputs, validate_call_observation_shard
from oracle.full_tree_elf_functions import validate_full_tree_elf_function_index
from oracle.full_tree_function_truth import validate_full_tree_function_truth_index
from oracle.full_tree_scope import canonical_json_bytes


class FullTreeCallTruthError(ValueError):
    """Raised when a call edge cannot be resolved without heuristic matching."""


POLICY = {
    "id": "full-tree-call-truth",
    "version": 1,
    "identity": "caller-id-and-return-pc-rva",
    "externalNamespace": "exact-undefined-elf-function-name",
    "thunkPolicy": "physical-target-retained-semantic-target-explicitly-unresolved",
}


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _configuration_sha256() -> str:
    schema = Path(__file__).with_name("full-tree-call-truth.schema.json").read_bytes()
    return _sha(canonical_json_bytes(POLICY) + schema)


def _external_id(name: str) -> str:
    return "external-function-" + _sha(name.encode("utf-8"))[:32]


def _validate_document(document: dict[str, Any]) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]
        schema = json.loads(Path(__file__).with_name("full-tree-call-truth.schema.json").read_text(encoding="utf-8"))
        fastjsonschema.compile(schema)(document)
    except (ModuleNotFoundError, OSError, json.JSONDecodeError) as error:
        raise FullTreeCallTruthError(f"cannot validate call truth: {error}") from error
    except fastjsonschema.JsonSchemaException as error:
        raise FullTreeCallTruthError(f"call truth fails JSON Schema: {error}") from error
    calls = document["calls"]
    if calls != sorted(calls, key=lambda item: item["id"]):
        raise FullTreeCallTruthError("call truth edges are not ordered")
    if len({item["id"] for item in calls}) != len(calls):
        raise FullTreeCallTruthError("call truth duplicates an edge identity")
    expected = {
        "directInternal": sum(item["targetKind"] == "direct-internal" for item in calls),
        "edges": len(calls),
        "external": sum(item["targetKind"] == "external" for item in calls),
        "indirectUnresolved": sum(item["targetKind"] == "indirect-unresolved" for item in calls),
        "observations": sum(len(item["observationIds"]) for item in calls),
        "unobservable": sum(item["population"] == "unobservable" for item in calls),
    }
    if document["counts"] != expected:
        raise FullTreeCallTruthError("call truth counts do not reconcile")


def validate_full_tree_call_truth_index(
    index: dict[str, Any],
    *,
    output_root: Path,
    inventory: dict[str, Any],
    expected_oracle: dict[str, Any] | None = None,
) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]

        schema = json.loads(
            Path(__file__).with_name("full-tree-call-truth-index.schema.json").read_text(encoding="utf-8")
        )
        fastjsonschema.compile(schema)(index)
    except Exception as error:
        raise FullTreeCallTruthError(f"call truth index fails validation: {error}") from error
    if expected_oracle is not None and index["oracle"] != expected_oracle:
        raise FullTreeCallTruthError("call truth index oracle bindings differ")
    without_hash = {key: value for key, value in index.items() if key != "indexSha256"}
    if index["indexSha256"] != _sha(canonical_json_bytes(without_hash)):
        raise FullTreeCallTruthError("call truth index hash does not reconcile")
    expected_ids = [shard["id"] for shard in inventory["shards"]]
    if [record["id"] for record in index["shards"]] != expected_ids:
        raise FullTreeCallTruthError("call truth shard population or ordering differs")
    aggregate: dict[str, int] = defaultdict(int)
    for record in index["shards"]:
        payload = (output_root / record["path"]).read_bytes()
        if len(payload) != record["bytes"] or _sha(payload) != record["sha256"]:
            raise FullTreeCallTruthError(f"call truth shard {record['id']} changed")
        document = json.loads(payload)
        _validate_document(document)
        if document["oracle"] != index["oracle"] or document["shard"] != {"id": record["id"]}:
            raise FullTreeCallTruthError(f"call truth shard {record['id']} bindings differ")
        for name, value in document["counts"].items():
            if record[name] != value:
                raise FullTreeCallTruthError(f"call truth shard {record['id']} count differs")
            aggregate[name] += value
    if index["counts"] != dict(sorted(aggregate.items())):
        raise FullTreeCallTruthError("call truth aggregate counts do not reconcile")


def generate_full_tree_call_truth(
    *,
    scope: dict[str, Any],
    scope_sha256: str,
    inventory: dict[str, Any],
    elf_index_path: Path,
    function_truth_root: Path,
    call_observation_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    function_index_payload = (function_truth_root / "index.json").read_bytes()
    function_index = json.loads(function_index_payload.decode("utf-8"))
    validate_full_tree_function_truth_index(
        function_index,
        output_root=function_truth_root,
        scope=scope,
        scope_sha256=scope_sha256,
        inventory=inventory,
        observation_index_sha256=function_index["oracle"]["observationIndexSha256"],
        elf_index_sha256=function_index["oracle"]["elfIndexSha256"],
    )
    elf_payload = elf_index_path.read_bytes()
    elf_index = json.loads(elf_payload.decode("utf-8"))
    validate_full_tree_elf_function_index(elf_index, scope=scope, scope_sha256=scope_sha256, inventory=inventory)
    if _sha(elf_payload) != function_index["oracle"]["elfIndexSha256"]:
        raise FullTreeCallTruthError("call truth ELF index differs from function truth")
    call_index = load_complete_shard_index(call_observation_root)
    call_index_payload = (call_observation_root / "index.json").read_bytes()
    call_inputs, units = call_shard_inputs(
        inventory,
        scope_sha256=scope_sha256,
        rich_sha256=scope["oracle"]["richArtifactSha256"],
    )
    expected_call_inputs = {item.identifier: item for item in call_inputs}
    oracle = {
        "callObservationIndexSha256": _sha(call_index_payload),
        "configurationSha256": _configuration_sha256(),
        "elfIndexSha256": _sha(elf_payload),
        "functionTruthIndexSha256": _sha(function_index_payload),
        "inventoryIndexSha256": inventory["indexSha256"],
        "scopeSha256": scope_sha256,
    }
    output_root.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=".call-truth-", suffix=".sqlite", dir=output_root) as database_file:
        database = sqlite3.connect(database_file.name)
        try:
            database.executescript(
                """
                CREATE TABLE functions (id TEXT PRIMARY KEY, owner_shard TEXT NOT NULL, entity_kind TEXT NOT NULL);
                CREATE TABLE externals (name TEXT PRIMARY KEY, id TEXT NOT NULL);
                CREATE TABLE observations (edge_key TEXT NOT NULL, observation_id TEXT PRIMARY KEY,
                                           source_shard TEXT NOT NULL, payload BLOB NOT NULL);
                CREATE INDEX observations_edge ON observations(edge_key);
                """
            )
            for shard_record in function_index["shards"]:
                document = json.loads((function_truth_root / shard_record["path"]).read_text(encoding="utf-8"))
                database.executemany(
                    "INSERT INTO functions VALUES (?, ?, ?)",
                    ((item["id"], shard_record["id"], item["entityKind"]) for item in document["functions"]),
                )
            database.executemany(
                "INSERT INTO externals VALUES (?, ?)",
                ((item["name"], _external_id(item["name"])) for item in elf_index["externalFunctions"]),
            )
            for checkpoint in call_index["shards"]:
                shard_id = checkpoint["shardId"]
                path = call_observation_root / "outputs" / f"{shard_id}.json"
                payload = path.read_bytes()
                if _sha(payload) != checkpoint["outputSha256"]:
                    raise FullTreeCallTruthError(f"call observation shard {shard_id} changed")
                document = json.loads(payload.decode("utf-8"))
                validate_call_observation_shard(
                    document,
                    scope=scope,
                    scope_sha256=scope_sha256,
                    inventory=inventory,
                    shard=expected_call_inputs[shard_id],
                    units=units[shard_id],
                )
                rows = []
                for item in document["calls"]:
                    edge_payload = (
                        {"callerId": item["callerId"], "returnPcRva": item["returnPcRva"]}
                        if item["population"] == "scored"
                        else {"observationId": item["id"]}
                    )
                    rows.append((_sha(canonical_json_bytes(edge_payload)), item["id"], shard_id, canonical_json_bytes(item)))
                database.executemany("INSERT INTO observations VALUES (?, ?, ?, ?)", rows)
                database.commit()

            by_shard: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for (edge_key,) in database.execute("SELECT DISTINCT edge_key FROM observations ORDER BY edge_key"):
                observations = [
                    json.loads(row[0])
                    for row in database.execute("SELECT payload FROM observations WHERE edge_key=? ORDER BY observation_id", (edge_key,))
                ]
                first = observations[0]
                signatures = {
                    canonical_json_bytes(
                        {
                            "callerId": item["callerId"],
                            "callerLocalReturnOffset": item["callerLocalReturnOffset"],
                            "population": item["population"],
                            "reasonCode": item["reasonCode"],
                            "returnPcRva": item["returnPcRva"],
                            "target": item["target"],
                        }
                    )
                    for item in observations
                }
                if len(signatures) != 1:
                    raise FullTreeCallTruthError(f"incompatible duplicate call observations for {edge_key}")
                caller_row = (
                    database.execute("SELECT owner_shard FROM functions WHERE id=?", (first["callerId"],)).fetchone()
                    if first["callerId"] is not None else None
                )
                if first["population"] == "scored" and caller_row is None:
                    raise FullTreeCallTruthError(f"call {first['id']} has a dangling caller identity")
                owner_shard = caller_row[0] if caller_row else database.execute(
                    "SELECT source_shard FROM observations WHERE edge_key=? ORDER BY source_shard LIMIT 1", (edge_key,)
                ).fetchone()[0]
                target = first["target"]
                population = first["population"]
                reason = first["reasonCode"]
                physical = None
                semantic = None
                external_ids: list[str] = []
                target_kind = target["kind"]
                if target_kind == "direct-internal":
                    target_row = database.execute("SELECT entity_kind FROM functions WHERE id=?", (target["functionId"],)).fetchone()
                    if target_row is None:
                        raise FullTreeCallTruthError(f"call {first['id']} has a dangling direct target")
                    physical = target["functionId"]
                    if target_row[0] == "thunk":
                        reason = "thunk-semantic-target-unresolved"
                    else:
                        semantic = physical
                elif target_kind == "external-unresolved":
                    target_kind = "external"
                    external_ids = sorted(
                        {row[0] for name in target["aliases"] if (row := database.execute("SELECT id FROM externals WHERE name=?", (name,)).fetchone())}
                    )
                    if not external_ids:
                        population = "unobservable"
                        reason = "external-without-elf-evidence"
                item = {
                    "callerId": first["callerId"],
                    "callerLocalReturnOffset": first["callerLocalReturnOffset"],
                    "externalTargetIds": external_ids,
                    "id": "call-edge-" + edge_key[:32],
                    "observationIds": sorted(observation["id"] for observation in observations),
                    "physicalTargetId": physical,
                    "population": population,
                    "reasonCode": reason,
                    "returnPcRva": first["returnPcRva"],
                    "semanticTargetId": semantic,
                    "targetKind": target_kind,
                }
                by_shard[owner_shard].append(item)

            shard_records = []
            aggregate = defaultdict(int)
            for shard in inventory["shards"]:
                calls = sorted(by_shard[shard["id"]], key=lambda item: item["id"])
                counts = {
                    "directInternal": sum(item["targetKind"] == "direct-internal" for item in calls),
                    "edges": len(calls),
                    "external": sum(item["targetKind"] == "external" for item in calls),
                    "indirectUnresolved": sum(item["targetKind"] == "indirect-unresolved" for item in calls),
                    "observations": sum(len(item["observationIds"]) for item in calls),
                    "unobservable": sum(item["population"] == "unobservable" for item in calls),
                }
                document = {"calls": calls, "counts": counts, "oracle": oracle, "schemaVersion": 1, "shard": {"id": shard["id"]}}
                _validate_document(document)
                payload = canonical_json_bytes(document)
                path = output_root / "shards" / f"{shard['id']}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
                shard_records.append({"id": shard["id"], "path": f"shards/{shard['id']}.json", "bytes": len(payload), "sha256": _sha(payload), **counts})
                for name, value in counts.items():
                    aggregate[name] += value
            index_without_hash = {"complete": True, "counts": dict(sorted(aggregate.items())), "oracle": oracle, "schemaVersion": 1, "shards": shard_records}
            index = {**index_without_hash, "indexSha256": _sha(canonical_json_bytes(index_without_hash))}
            (output_root / "index.json").write_bytes(canonical_json_bytes(index))
            validate_full_tree_call_truth_index(
                index,
                output_root=output_root,
                inventory=inventory,
                expected_oracle=oracle,
            )
            return index
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as error:
            if isinstance(error, FullTreeCallTruthError):
                raise
            raise FullTreeCallTruthError(f"cannot generate call truth: {error}") from error
        finally:
            database.close()
