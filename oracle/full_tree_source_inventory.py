"""Reconcile authenticated LLVM source units with DWARF and build exclusions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
from typing import Any

from oracle.full_tree_scope import canonical_json_bytes, shard_for_source_path


class FullTreeSourceInventoryError(ValueError):
    """Raised when source, DWARF, or build configuration populations drift."""


POLICY = {
    "id": "full-tree-source-inventory",
    "version": 1,
    "translationUnitSuffixes": [".C", ".S", ".c", ".cc", ".cpp", ".cxx", ".s"],
    "sourcePrefixes": ["clang/lib/", "clang/tools/", "llvm/lib/", "llvm/tools/"],
}
PROJECT_DIRECTORIES = {
    "bolt", "clang", "clang-tools-extra", "compiler-rt", "cross-project-tests", "flang", "flang-rt",
    "libc", "libclc", "libcxx", "libcxxabi", "libsycl", "libunwind", "lld", "lldb", "llvm",
    "llvm-libgcc", "mlir", "offload", "openmp", "orc-rt", "polly", "runtimes",
}


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _configuration_sha256() -> str:
    return _sha(canonical_json_bytes(POLICY) + Path(__file__).with_name("full-tree-source-inventory.schema.json").read_bytes())


def _source_only_reason(path: str) -> str:
    relative = path.removeprefix("source/")
    if relative.startswith(("clang/tools/", "llvm/tools/")):
        return "tool-not-linked-into-clang-driver"
    if relative.startswith("llvm/lib/Target/") and not relative.startswith("llvm/lib/Target/X86/"):
        return "target-not-enabled-or-not-linked"
    return "not-selected-by-authenticated-build-graph"


def generate_full_tree_source_inventory(
    archive_path: Path, *, source_lock: dict[str, Any], build_record: dict[str, Any],
    scope: dict[str, Any], scope_sha256: str, inventory: dict[str, Any],
) -> dict[str, Any]:
    archive_payload = archive_path.read_bytes()
    locked_archive = source_lock["source"]["archive"]
    if len(archive_payload) != locked_archive["bytes"] or _sha(archive_payload) != locked_archive["sha256"]:
        raise FullTreeSourceInventoryError("source archive differs from its lock")
    configure = build_record["commands"]["configure"]
    if "-DLLVM_ENABLE_PROJECTS=clang" not in configure or "-DLLVM_TARGETS_TO_BUILD=X86" not in configure:
        raise FullTreeSourceInventoryError("build record does not select the locked Clang/X86 scope")
    names: set[str] = set()
    top_level: set[str] = set()
    maximum_members = 200_000
    with tarfile.open(archive_path, "r:xz") as archive:
        for count, member in enumerate(archive, start=1):
            if count > maximum_members:
                raise FullTreeSourceInventoryError("source archive exceeds its member bound")
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "llvm-project-22.1.6.src":
                raise FullTreeSourceInventoryError("source archive contains an unsafe or unexpected path")
            if not member.isfile() or len(path.parts) < 2:
                continue
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            if relative in names:
                raise FullTreeSourceInventoryError(f"source archive duplicates {relative}")
            names.add(relative)
            top_level.add(path.parts[1])

    candidates = sorted(
        "source/" + name for name in names
        if name.startswith(tuple(POLICY["sourcePrefixes"])) and PurePosixPath(name).suffix in POLICY["translationUnitSuffixes"]
    )
    linked_by_path = {
        unit["sourcePath"]: unit for unit in inventory["units"] if unit["sourceKind"] == "handwritten"
    }
    if set(linked_by_path) - set(candidates):
        raise FullTreeSourceInventoryError("DWARF inventory contains a handwritten unit absent from source candidates")
    source_units = []
    for path in candidates:
        linked = linked_by_path.get(path)
        source_units.append(
            {
                "classification": "linked" if linked else "source-only",
                "path": path,
                "reasonCode": None if linked else _source_only_reason(path),
                "shardId": linked["shardId"] if linked else shard_for_source_path(scope, path),
                "unitId": linked["id"] if linked else None,
            }
        )
    tablegen_inputs = [
        {
            "classification": "enabled-project-input" if name.startswith(("clang/", "llvm/")) else "disabled-project-input",
            "path": "source/" + name,
        }
        for name in sorted(names)
        if name.endswith(".td")
    ]
    disabled_projects = sorted(PROJECT_DIRECTORIES.intersection(top_level) - {"clang", "llvm"})
    generated_units = sorted(
        ({"path": unit["sourcePath"], "shardId": unit["shardId"], "unitId": unit["id"]}
         for unit in inventory["units"] if unit["sourceKind"] == "generated"),
        key=lambda item: item["unitId"],
    )
    counts = {
        "candidateTranslationUnits": len(source_units),
        "disabledProjects": len(disabled_projects),
        "generatedCompilationUnits": len(generated_units),
        "linkedSourceUnits": sum(item["classification"] == "linked" for item in source_units),
        "sourceOnlyUnits": sum(item["classification"] == "source-only" for item in source_units),
        "tablegenInputs": len(tablegen_inputs),
    }
    without_hash = {
        "build": {"configureSha256": _sha(canonical_json_bytes(configure)), "disabledProjects": disabled_projects, "enabledProjects": ["clang", "llvm"], "targets": ["X86"]},
        "counts": counts,
        "generatedCompilationUnits": generated_units,
        "oracle": {
            "buildRecordSha256": _sha(canonical_json_bytes(build_record)),
            "configurationSha256": _configuration_sha256(),
            "inventoryIndexSha256": inventory["indexSha256"],
            "scopeSha256": scope_sha256,
            "sourceArchiveBytes": len(archive_payload),
            "sourceArchiveSha256": _sha(archive_payload),
            "sourceLockSha256": _sha(canonical_json_bytes(source_lock)),
        },
        "schemaVersion": 1,
        "sourceUnits": source_units,
        "tablegenInputs": tablegen_inputs,
    }
    report = {**without_hash, "reportSha256": _sha(canonical_json_bytes(without_hash))}
    validate_full_tree_source_inventory(report, inventory=inventory, scope_sha256=scope_sha256)
    return report


def validate_full_tree_source_inventory(report: dict[str, Any], *, inventory: dict[str, Any], scope_sha256: str) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]
        schema = json.loads(Path(__file__).with_name("full-tree-source-inventory.schema.json").read_text(encoding="utf-8"))
        fastjsonschema.compile(schema)(report)
    except Exception as error:
        raise FullTreeSourceInventoryError(f"source inventory fails validation: {error}") from error
    without_hash = {key: value for key, value in report.items() if key != "reportSha256"}
    if report["reportSha256"] != _sha(canonical_json_bytes(without_hash)):
        raise FullTreeSourceInventoryError("source inventory hash does not reconcile")
    if report["oracle"]["scopeSha256"] != scope_sha256 or report["oracle"]["inventoryIndexSha256"] != inventory["indexSha256"]:
        raise FullTreeSourceInventoryError("source inventory bindings differ")
    units = report["sourceUnits"]
    if units != sorted(units, key=lambda item: item["path"]) or len({item["path"] for item in units}) != len(units):
        raise FullTreeSourceInventoryError("source units are not ordered and unique")
    tablegen = report["tablegenInputs"]
    if tablegen != sorted(tablegen, key=lambda item: item["path"]) or len({item["path"] for item in tablegen}) != len(tablegen):
        raise FullTreeSourceInventoryError("TableGen inputs are not ordered and unique")
    linked = [item for item in units if item["classification"] == "linked"]
    expected_linked = {unit["id"] for unit in inventory["units"] if unit["sourceKind"] == "handwritten"}
    if {item["unitId"] for item in linked} != expected_linked:
        raise FullTreeSourceInventoryError("source inventory does not cover every handwritten DWARF unit")
    generated = report["generatedCompilationUnits"]
    expected_generated = {unit["id"] for unit in inventory["units"] if unit["sourceKind"] == "generated"}
    if {item["unitId"] for item in generated} != expected_generated:
        raise FullTreeSourceInventoryError("source inventory does not cover every generated DWARF unit")
    expected_counts = {
        "candidateTranslationUnits": len(units), "disabledProjects": len(report["build"]["disabledProjects"]),
        "generatedCompilationUnits": len(generated), "linkedSourceUnits": len(linked),
        "sourceOnlyUnits": len(units) - len(linked), "tablegenInputs": len(tablegen),
    }
    if report["counts"] != expected_counts:
        raise FullTreeSourceInventoryError("source inventory counts do not reconcile")
