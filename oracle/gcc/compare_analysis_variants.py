"""Replay complete diagnostic analyzer censuses; never select a production profile."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from oracle.function_recovery import ScoringError, _decode_json, _read_regular_snapshot
from oracle.function_recovery_profile import (
    _artifact_metadata_from_manifest,
    _verified_artifact_manifest_snapshot,
)

DEFAULT_MANIFEST = Path(__file__).resolve().parent / "16.2.0/cc1-oracle-manifest.json"

MAX_CENSUS_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 1_000_000
MAX_REPORT_BYTES = 64 * 1024 * 1024
VARIANTS = {
    "baseline": (),
    "no-switch": ("Decompiler Switch Analysis",),
    "no-call-convention": ("Call Convention ID",),
    "no-switch-no-call-convention": ("Call Convention ID", "Decompiler Switch Analysis"),
    "lean": ("Call Convention ID", "Decompiler Switch Analysis", "Stack", "x86 Constant Reference Analyzer"),
}
_FIELDS = {
    "schemaVersion", "kind", "authority", "inputSha256", "imageBase", "languageId",
    "compilerSpecId", "entries", "entryCount", "entriesSha256", "disabledAnalyzers",
}
_HEX = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _address(value: Any) -> int:
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        raise ScoringError("census address is not canonical unsigned 64-bit hexadecimal")
    return int(value, 16)


def _snapshot(path: Path, label: str, limit: int) -> tuple[dict, dict]:
    payload = _read_regular_snapshot(path, label, limit)
    return _decode_json(payload, label), {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}


def load_census(path: Path, *, variant: str, artifact: Any) -> tuple[dict, dict, tuple[int, ...]]:
    if variant not in VARIANTS:
        raise ScoringError("unknown analyzer variant")
    census, record = _snapshot(path, f"{variant} census", MAX_CENSUS_BYTES)
    if set(census) != _FIELDS or type(census.get("schemaVersion")) is not int or census["schemaVersion"] != 1:
        raise ScoringError("unsupported or non-closed census schema")
    if census["kind"] != "ghidra-function-entry-census-v1" or census["authority"] != "diagnostic-only":
        raise ScoringError("census is not diagnostic entry evidence")
    if census["inputSha256"] != artifact.input_sha256 or _address(census["imageBase"]) != artifact.elf_image_base:
        raise ScoringError("census input or image base differs from the manifest")
    for field in ("languageId", "compilerSpecId"):
        value = census[field]
        if not isinstance(value, str) or not 1 <= len(value) <= 256 or any(ord(c) < 32 for c in value):
            raise ScoringError(f"invalid census {field}")
    if census["disabledAnalyzers"] != list(VARIANTS[variant]):
        raise ScoringError("census does not prove the requested variant's exact disabled options")
    entries = census["entries"]
    count = census["entryCount"]
    if not isinstance(entries, list) or type(count) is not int or not 1 <= count <= MAX_ENTRIES or len(entries) != count:
        raise ScoringError("census entry count is invalid or incomplete")
    digest = census["entriesSha256"]
    if not isinstance(digest, str) or not _SHA.fullmatch(digest):
        raise ScoringError("invalid census entry digest")
    decoded: list[int] = []
    hasher = hashlib.sha256()
    for text in entries:
        address = _address(text)
        if decoded and address <= decoded[-1]:
            raise ScoringError("census entries must be sorted and unique")
        rva = address - artifact.elf_image_base
        if not any(span.start <= rva < span.end_exclusive for span in artifact.executable_ranges):
            raise ScoringError("census entry is outside executable manifest ranges")
        decoded.append(address)
        hasher.update((text + "\n").encode("ascii"))
    if hasher.hexdigest() != digest:
        raise ScoringError("census entry digest does not match the retained entries")
    return census, record, tuple(decoded)


def compare_variants(
    *, manifest_path: Path, baseline_path: Path, variant_paths: Mapping[str, Path],
    rich_artifact_path: Path | None = None, stripped_artifact_path: Path | None = None,
) -> dict:
    """Compare retained starts, optionally against complete authenticated physical facts.

    A reviewed cc1 source-function oracle is not supplied by this diagnostic path.
    Raw physical facts retain compiler-generated starts and are not source-accuracy
    or production-admission evidence.
    """
    if not variant_paths or "baseline" in variant_paths or set(variant_paths) - VARIANTS.keys():
        raise ScoringError("at least one distinct declared comparison variant is required")
    if (rich_artifact_path is None) != (stripped_artifact_path is None):
        raise ScoringError("both ELF twins are required for physical reference verification")
    manifest, manifest_record = _snapshot(manifest_path, "cc1 manifest", 16 * 1024 * 1024)
    artifact = _artifact_metadata_from_manifest(manifest, "stripped")
    baseline, baseline_record, baseline_entries = load_census(baseline_path, variant="baseline", artifact=artifact)
    baseline_set = set(baseline_entries)
    variants: dict[str, dict] = {}
    for name, path in sorted(variant_paths.items()):
        census, record, entries = load_census(path, variant=name, artifact=artifact)
        if any(census[field] != baseline[field] for field in ("languageId", "compilerSpecId")):
            raise ScoringError("census language/compiler selection differs between variants")
        recovered = set(entries)
        variants[name] = {
            "census": record, "entryCount": len(entries), "entriesSha256": census["entriesSha256"],
            "disabledAnalyzers": census["disabledAnalyzers"],
            "addedEntries": [hex(x) for x in sorted(recovered - baseline_set)],
            "removedEntries": [hex(x) for x in sorted(baseline_set - recovered)],
            "unchangedEntries": len(recovered & baseline_set),
        }
    report = {
        "schemaVersion": 1, "kind": "gcc-analyzer-entry-comparison-v1", "authority": "diagnostic-only",
        "productionProfileSelected": False, "releaseEligible": False,
        "reviewedAccuracy": {"status": "unavailable", "reason": "no authenticated reviewed cc1 source-function oracle"},
        "inputVerification": "manifest-metadata-only", "manifest": manifest_record,
        "inputSha256": artifact.input_sha256, "imageBase": hex(artifact.elf_image_base),
        "baseline": {"census": baseline_record, "entryCount": len(baseline_entries), "entriesSha256": baseline["entriesSha256"]},
        "variants": variants,
    }
    if rich_artifact_path is not None:
        from oracle.physical_function_starts import collect_physical_function_starts
        with _verified_artifact_manifest_snapshot(
            manifest_path, artifact_overrides={"full": rich_artifact_path, "stripped": stripped_artifact_path},
        ) as snapshot:
            if hashlib.sha256(snapshot.manifest_payload).hexdigest() != manifest_record["sha256"]:
                raise ScoringError("manifest changed before authenticated reference capture")
            reference = collect_physical_function_starts(
                snapshot.artifact_paths["rich"], expected_sha256=snapshot.manifest["artifacts"]["full"]["sha256"],
            )
        if _address(reference["elfImageBase"]) != artifact.elf_image_base:
            raise ScoringError("physical reference image base differs from recovered census")
        physical = {_address(item["rva"]) + artifact.elf_image_base for item in reference["functions"]}
        report["inputVerification"] = "manifest-and-elf-twins-verified"
        report["physicalReference"] = reference
        report["physicalReference"]["authority"] = "diagnostic-physical-starts-with-no-policy-exclusions"
        for variant in variants.values():
            for label in ("addedEntries", "removedEntries"):
                variant[label + "InPhysicalReference"] = [entry for entry in variant[label] if _address(entry) in physical]
        report["baseline"]["entriesInPhysicalReference"] = len(baseline_set & physical)
    # Bound the exact serialized report before any publication.
    if len(report_bytes(report)) > MAX_REPORT_BYTES:
        raise ScoringError("analyzer comparison exceeds its report byte bound")
    return report


def report_bytes(report: dict) -> bytes:
    return (json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
