"""Reconcile every DWARF data-truth entity with ELF object and ABI evidence."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path
from typing import Any

from oracle.full_tree_data_truth import validate_full_tree_data_truth_index
from oracle.full_tree_elf_data import validate_full_tree_elf_data_index
from oracle.full_tree_scope import canonical_json_bytes


class FullTreeDataReconciliationError(ValueError):
    """Raised when data populations, bindings, or identities do not reconcile."""


POLICY = {
    "id": "full-tree-data-reconciliation",
    "version": 1,
    "imageObjects": "exact-image-rva",
    "tlsObjects": "exact-authenticated-linkage-name",
    "elfOnlyOwnership": "explicit-elf-only-shard",
}


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _configuration_sha256() -> str:
    schema = Path(__file__).with_name("full-tree-data-reconciliation.schema.json").read_bytes()
    return _sha(canonical_json_bytes(POLICY) + schema)


def validate_full_tree_data_reconciliation(
    report: dict[str, Any],
    *,
    data_truth_index_sha256: str,
    elf_data_index_sha256: str,
    inventory: dict[str, Any],
    scope_sha256: str,
) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]

        schema = json.loads(
            Path(__file__).with_name("full-tree-data-reconciliation.schema.json").read_text(encoding="utf-8")
        )
        fastjsonschema.compile(schema)(report)
    except Exception as error:
        raise FullTreeDataReconciliationError(
            f"data reconciliation fails schema validation: {error}"
        ) from error
    expected_oracle = {
        "configurationSha256": _configuration_sha256(),
        "dataTruthIndexSha256": data_truth_index_sha256,
        "elfDataIndexSha256": elf_data_index_sha256,
        "inventoryIndexSha256": inventory["indexSha256"],
        "scopeSha256": scope_sha256,
    }
    if report["oracle"] != expected_oracle:
        raise FullTreeDataReconciliationError("data reconciliation bindings differ")
    without_hash = {key: value for key, value in report.items() if key != "reportSha256"}
    if report["reportSha256"] != _sha(canonical_json_bytes(without_hash)):
        raise FullTreeDataReconciliationError("data reconciliation hash does not reconcile")
    globals_ = report["globals"]
    if globals_ != sorted(globals_, key=lambda item: item["elfGlobalId"]):
        raise FullTreeDataReconciliationError("ELF data reconciliation records are not ordered")
    if len({item["elfGlobalId"] for item in globals_}) != len(globals_):
        raise FullTreeDataReconciliationError("ELF data reconciliation identities are duplicated")
    dwarf_only = report["dwarfOnlyScoredGlobals"]
    if dwarf_only != sorted(dwarf_only, key=lambda item: item["truthId"]):
        raise FullTreeDataReconciliationError("DWARF-only global records are not ordered")
    abi_objects = report["abiObjects"]
    if abi_objects != sorted(abi_objects, key=lambda item: (item["elfGlobalId"], item["aliasName"])):
        raise FullTreeDataReconciliationError("ABI object records are not ordered")
    counts = report["counts"]
    if counts["elfGlobals"] != len(globals_):
        raise FullTreeDataReconciliationError("ELF global count does not reconcile")
    if counts["matchedElfGlobals"] != sum(item["reconciliation"] != "elf-only" for item in globals_):
        raise FullTreeDataReconciliationError("matched ELF global count does not reconcile")
    if counts["elfOnlyGlobals"] != sum(item["reconciliation"] == "elf-only" for item in globals_):
        raise FullTreeDataReconciliationError("ELF-only global count does not reconcile")
    if counts["dwarfOnlyScoredGlobals"] != len(dwarf_only):
        raise FullTreeDataReconciliationError("DWARF-only scored global count does not reconcile")
    if counts["abiObjects"] != len(abi_objects):
        raise FullTreeDataReconciliationError("ABI object count does not reconcile")
    if counts["abiSlots"] != sum(item["slots"] for item in abi_objects):
        raise FullTreeDataReconciliationError("ABI slot count does not reconcile")
    if counts["abiResolvedSlots"] != sum(item["resolvedSlots"] for item in abi_objects):
        raise FullTreeDataReconciliationError("resolved ABI slot count does not reconcile")


def generate_full_tree_data_reconciliation(
    *,
    data_truth_root: Path,
    elf_data_index_path: Path,
    inventory: dict[str, Any],
    scope: dict[str, Any],
    scope_sha256: str,
) -> dict[str, Any]:
    data_payload = (data_truth_root / "index.json").read_bytes()
    data_index = json.loads(data_payload)
    validate_full_tree_data_truth_index(
        data_index,
        output_root=data_truth_root,
        scope_sha256=scope_sha256,
        inventory=inventory,
    )
    elf_payload = elf_data_index_path.read_bytes()
    elf_index = json.loads(elf_payload)
    validate_full_tree_elf_data_index(
        elf_index,
        scope=scope,
        scope_sha256=scope_sha256,
        inventory=inventory,
    )

    truth_by_id: dict[str, tuple[str, dict[str, Any]]] = {}
    image_rvas: dict[str, set[str]] = defaultdict(set)
    tls_names: dict[str, set[str]] = defaultdict(set)
    dwarf_globals = 0
    dwarf_scored = 0
    dwarf_unobservable = 0
    for shard_record in data_index["shards"]:
        document = json.loads((data_truth_root / shard_record["path"]).read_bytes())
        for item in document["globals"]:
            dwarf_globals += 1
            if item["population"] == "scored":
                dwarf_scored += 1
            else:
                dwarf_unobservable += 1
            truth_by_id[item["id"]] = (shard_record["id"], item)
            if item["addressRva"] is not None and not item["tls"]:
                image_rvas[item["addressRva"]].add(item["id"])
            if item["tls"]:
                for name in item["names"]:
                    tls_names[name].add(item["id"])

    matched_truth_ids: set[str] = set()
    global_records = []
    abi_records = []
    for elf_global in elf_index["globals"]:
        truth_ids: set[str] = set()
        if elf_global["addressKind"] == "image-rva":
            truth_ids.update(image_rvas.get(elf_global["address"], ()))
            reconciliation = "matched-by-rva" if truth_ids else "elf-only"
        else:
            for alias in elf_global["aliases"]:
                truth_ids.update(tls_names.get(alias["name"], ()))
            reconciliation = "matched-tls-by-linkage-name" if truth_ids else "elf-only"
        matched_truth_ids.update(truth_ids)
        owner_shards = sorted({truth_by_id[truth_id][0] for truth_id in truth_ids}) or ["elf-only"]
        global_records.append(
            {
                "address": elf_global["address"],
                "addressKind": elf_global["addressKind"],
                "aliasNames": sorted(alias["name"] for alias in elf_global["aliases"]),
                "dwarfTruthIds": sorted(truth_ids),
                "elfGlobalId": elf_global["id"],
                "ownerShardIds": owner_shards,
                "reconciliation": reconciliation,
            }
        )
        for alias in elf_global["aliases"]:
            abi = alias["abi"]
            if abi is None:
                continue
            abi_records.append(
                {
                    "aliasName": alias["name"],
                    "elfGlobalId": elf_global["id"],
                    "kind": abi["kind"],
                    "ownerMangledName": abi["ownerMangledName"],
                    "ownerShardIds": owner_shards,
                    "resolvedSlots": sum(slot["targetRva"] is not None for slot in abi["slots"]),
                    "slots": len(abi["slots"]),
                }
            )

    dwarf_only = [
        {"addressRva": item["addressRva"], "shardId": shard_id, "truthId": truth_id}
        for truth_id, (shard_id, item) in truth_by_id.items()
        if item["population"] == "scored" and truth_id not in matched_truth_ids
    ]
    global_records.sort(key=lambda item: item["elfGlobalId"])
    dwarf_only.sort(key=lambda item: item["truthId"])
    abi_records.sort(key=lambda item: (item["elfGlobalId"], item["aliasName"]))
    counts = {
        "abiObjects": len(abi_records),
        "abiResolvedSlots": sum(item["resolvedSlots"] for item in abi_records),
        "abiSlots": sum(item["slots"] for item in abi_records),
        "dwarfGlobals": dwarf_globals,
        "dwarfOnlyScoredGlobals": len(dwarf_only),
        "dwarfScoredGlobals": dwarf_scored,
        "dwarfTypes": data_index["counts"]["types"],
        "dwarfUnobservableGlobals": dwarf_unobservable,
        "elfGlobals": len(global_records),
        "elfOnlyGlobals": sum(item["reconciliation"] == "elf-only" for item in global_records),
        "matchedElfGlobals": sum(item["reconciliation"] != "elf-only" for item in global_records),
        "unexplainedEntities": 0,
    }
    oracle = {
        "configurationSha256": _configuration_sha256(),
        "dataTruthIndexSha256": _sha(data_payload),
        "elfDataIndexSha256": _sha(elf_payload),
        "inventoryIndexSha256": inventory["indexSha256"],
        "scopeSha256": scope_sha256,
    }
    without_hash = {
        "abiObjects": abi_records,
        "counts": counts,
        "dwarfOnlyScoredGlobals": dwarf_only,
        "globals": global_records,
        "oracle": oracle,
        "schemaVersion": 1,
    }
    report = {**without_hash, "reportSha256": _sha(canonical_json_bytes(without_hash))}
    validate_full_tree_data_reconciliation(
        report,
        data_truth_index_sha256=_sha(data_payload),
        elf_data_index_sha256=_sha(elf_payload),
        inventory=inventory,
        scope_sha256=scope_sha256,
    )
    return report
