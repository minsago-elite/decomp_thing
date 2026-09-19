#!/usr/bin/env python3
"""Report the retained GCC accuracy evidence without inventing a score.

The report is deliberately smaller than a structural score.  It binds the
checked GCC function oracle and artifact pair, counts the exact oracle
populations, and records which parent requirements still have no authenticated
production input.  Missing model, call-oracle, or replay evidence is emitted as
an explicit unavailable state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import os
import stat
import sys
import tempfile
from collections import Counter
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.elf_oracle import verify_oracle_manifest  # noqa: E402
from oracle.function_recovery import load_function_oracle  # noqa: E402


REPORT_ID = "gcc-driver-accuracy-coverage-v1"
REGISTRY_PATH = (
    "src/main/kotlin/decompengine/oracle/structural/"
    "StructuralReplayAdapterRegistry.kt"
)


class CoverageError(RuntimeError):
    """Raised when the checked oracle inputs cannot be authenticated."""


def _read_regular(path: Path, label: str) -> bytes:
    try:
        if path.is_symlink():
            raise CoverageError(f"{label} is a symlink: {path}")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise CoverageError(f"{label} is not a regular file: {path}")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except CoverageError:
        raise
    except OSError as error:
        raise CoverageError(f"cannot read {label} {path}: {error}") from error


def _json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(_read_regular(path, label))
    except json.JSONDecodeError as error:
        raise CoverageError(f"{label} is not valid JSON: {error}") from error
    if not isinstance(value, dict):
        raise CoverageError(f"{label} must contain a JSON object")
    return value


def _sha256(path: Path, label: str) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise CoverageError(f"cannot hash {label} {path}: {error}") from error
    return digest.hexdigest()


def _record(path: Path, label: str) -> dict[str, Any]:
    payload = _read_regular(path, label)
    return {
        "path": path.name,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _required_mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CoverageError(f"{path} must be an object")
    return value


def _verify_bound_file(
    path: Path,
    label: str,
    expected: dict[str, Any],
) -> dict[str, Any]:
    actual = _record(path, label)
    if actual["bytes"] != expected.get("bytes"):
        raise CoverageError(
            f"{label} byte length does not match its authenticated manifest record"
        )
    if actual["sha256"] != expected.get("sha256"):
        raise CoverageError(
            f"{label} SHA-256 does not match its authenticated manifest record"
        )
    return actual


def _historical_unattested_score() -> dict[str, Any]:
    return {
        "status": "historical-unattested",
        "productionVerified": False,
        "source": "docs/gcc-function-recovery-scoring.md",
        "reason": (
            "The documented score used schema-v1 model bytes whose exporter and "
            "loader provenance was not authenticated; those model and report bytes "
            "are not retained as current production inputs."
        ),
        "rich": {
            "precision": {"numerator": 3283, "denominator": 3288},
            "recall": {"numerator": 3283, "denominator": 3284},
        },
        "stripped": {
            "precision": {"numerator": 3268, "denominator": 3272},
            "recall": {"numerator": 3268, "denominator": 3284},
        },
    }


def build_report(profile_directory: Path) -> dict[str, Any]:
    profile_directory = profile_directory.resolve()
    manifest_path = profile_directory / "oracle-manifest.json"
    source_lock_path = profile_directory / "source-lock.json"
    build_record_path = profile_directory / "build-record.json"
    function_oracle_path = profile_directory / "function-recovery-oracle.json"
    exclusions_path = profile_directory / "function-recovery-exclusions.json"
    manifest = _json(manifest_path, "oracle artifact manifest")
    manifest_sha256 = _sha256(manifest_path, "oracle artifact manifest")

    try:
        verified_manifest = verify_oracle_manifest(manifest_path)
    except Exception as error:  # verifier has several intentional failure types
        raise CoverageError(f"oracle artifact manifest verification failed: {error}") from error
    if verified_manifest != manifest:
        raise CoverageError("oracle artifact manifest changed during verification")

    oracle = _json(function_oracle_path, "function recovery oracle")
    if oracle.get("scope") != "production":
        raise CoverageError("function recovery oracle is not production-scoped")
    oracle_metadata = _required_mapping(oracle.get("oracle"), "function oracle.oracle")
    if oracle_metadata.get("artifactManifestSha256") != manifest_sha256:
        raise CoverageError(
            "function recovery oracle is not bound to this artifact manifest"
        )
    # The semantic loader validates the closed oracle schema before this report
    # exposes any counts derived from it.
    loaded_oracle = load_function_oracle(function_oracle_path)
    raw_functions = oracle.get("functions")
    if not isinstance(raw_functions, list) or len(raw_functions) != len(loaded_oracle.functions):
        raise CoverageError("function recovery oracle loader count disagrees with JSON")

    manifest_inputs = _required_mapping(manifest.get("inputs"), "manifest.inputs")
    manifest_artifacts = _required_mapping(manifest.get("artifacts"), "manifest.artifacts")
    source_record = _required_mapping(manifest_inputs.get("sourceLock"), "manifest.inputs.sourceLock")
    build_record = _required_mapping(manifest_inputs.get("buildRecord"), "manifest.inputs.buildRecord")
    source_file = _verify_bound_file(source_lock_path, "source lock", source_record)
    build_file = _verify_bound_file(build_record_path, "build record", build_record)

    artifact_files: dict[str, dict[str, Any]] = {}
    for twin in ("full", "stripped"):
        artifact_record = _required_mapping(
            manifest_artifacts.get(twin), f"manifest.artifacts.{twin}"
        )
        relative = artifact_record.get("path")
        if not isinstance(relative, str):
            raise CoverageError(f"manifest.artifacts.{twin}.path must be a string")
        artifact_path = profile_directory / relative
        artifact_files[twin] = {
            **_verify_bound_file(artifact_path, f"{twin} artifact", artifact_record),
            "manifestPath": relative,
        }

    exclusions = _json(exclusions_path, "function recovery exclusions")
    excluded_records = exclusions.get("exclusions")
    if not isinstance(excluded_records, list):
        raise CoverageError("function recovery exclusions.exclusions must be an array")

    exclusion_counts = Counter(
        (function.get("exclusion") or {}).get("kind")
        for function in raw_functions
        if isinstance(function, dict)
    )
    scoreable_count = sum(
        isinstance(function, dict)
        and function.get("rva") is not None
        and function.get("exclusion") is None
        for function in raw_functions
    )
    inline_count = exclusion_counts.get("inlined", 0)
    generated_count = exclusion_counts.get("compiler-generated", 0)
    if len(excluded_records) != generated_count:
        raise CoverageError(
            "reviewed compiler-generated exclusion count disagrees with the oracle"
        )
    stripped_surviving_aliases = sum(
        1
        for function in raw_functions
        if isinstance(function, dict)
        for alias in function.get("aliases", [])
        if isinstance(alias, dict)
        and _required_mapping(alias.get("availability"), "function alias availability").get(
            "stripped"
        )
        == "surviving"
    )
    registry_path = REPOSITORY_ROOT / REGISTRY_PATH
    registry_text = _read_regular(registry_path, "structural replay registry").decode(
        "utf-8"
    )
    if "val production = StructuralReplayAdapterRegistry(emptyMap(), testOnly = false)" in registry_text:
        replay_status = {
            "status": "unavailable",
            "reasonCode": "production-registry-empty",
            "evidence": REGISTRY_PATH,
        }
    else:
        replay_status = {
            "status": "unresolved",
            "reasonCode": "production-registry-requires-review",
            "evidence": REGISTRY_PATH,
        }

    return {
        "schemaVersion": 1,
        "reportId": REPORT_ID,
        "profile": {
            "id": oracle_metadata.get("id"),
            "version": _required_mapping(manifest.get("oracle"), "manifest.oracle").get(
                "version"
            ),
            "sourceRevision": _required_mapping(
                manifest.get("oracle"), "manifest.oracle"
            ).get("sourceRevision"),
        },
        "provenance": {
            "status": "authenticated-oracle-inputs",
            "artifactManifest": {"path": manifest_path.name, "sha256": manifest_sha256},
            "sourceLock": source_file,
            "buildRecord": build_file,
            "functionOracle": {
                **_record(function_oracle_path, "function recovery oracle"),
                "path": function_oracle_path.name,
            },
            "exclusionProfile": {
                **_record(exclusions_path, "function recovery exclusions"),
                "path": exclusions_path.name,
            },
            "artifacts": artifact_files,
        },
        "dimensions": {
            "functionStarts": {
                "status": "oracle-covered-recovery-unavailable",
                "threshold": {"precisionAtLeast": 0.95, "recallAtLeast": 0.95},
                "oracle": {
                    "status": "available",
                    "recordCount": len(raw_functions),
                    "scoreableFunctionCount": scoreable_count,
                    "excluded": {
                        "compilerGenerated": generated_count,
                        "inlineOnly": inline_count,
                    },
                },
                "currentScore": {
                    "status": "unavailable",
                    "reasonCode": "no-retained-current-recovered-model",
                    "productionVerified": False,
                },
                "historicalReference": _historical_unattested_score(),
            },
            "survivingSymbolIdentity": {
                "status": "oracle-population-known-recovery-unavailable",
                "threshold": {"identityRecovery": 1.0},
                "oracle": {
                    "status": "available",
                    "strippedSurvivingAliasCount": stripped_surviving_aliases,
                    "populationDefinition": (
                        "aliases whose stripped availability is surviving in the "
                        "authenticated function oracle"
                    ),
                },
                "currentScore": {
                    "status": "unavailable",
                    "reasonCode": "no-retained-production-symbol-identity-report",
                    "productionVerified": False,
                },
            },
            "callEdges": {
                "status": "unavailable",
                "threshold": {"precisionAtLeast": 0.90, "recallAtLeast": 0.90},
                "oracle": {
                    "status": "unavailable",
                    "reasonCode": "no-authenticated-gcc-call-oracle",
                    "productionVerified": False,
                },
                "recovery": {
                    "status": "unavailable",
                    "reasonCode": "no-authenticated-gcc-recovered-call-sites",
                    "productionVerified": False,
                },
                "productionReplay": replay_status,
            },
        },
        "nextBoundary": {
            "status": "unresolved",
            "id": "gcc-structural-replay-call-edge-v1",
            "ownerIssues": [40, 681],
            "requiredInputs": [
                "authenticated GCC rich/stripped artifact binding from oracle-manifest.json",
                "bundled Ghidra JVM exporter and loader identity with image-base receipt",
                "recovered call-site/model snapshot bound to the same stripped artifact",
            ],
            "requiredEvidence": [
                "oracle-derived internal, external, indirect, unknown, and unobservable call facts",
                "stable function-boundary mapping reused for caller and endpoint identities",
                "per-edge exact, partial, missing, contradicted, and fabricated outcomes",
                "retained exporter, loader, target, input, and replay receipt hashes",
            ],
            "qualificationBoundary": {
                "status": "unavailable",
                "reasonCode": "production-replay-adapter-not-registered",
                "requiredAnalysisAuthority": "bundled-ghidra-jvm",
                "forbiddenSubstitutes": ["GHIDRA_HOME", "external-analyzeHeadless"],
            },
        },
    }


def _write_json(path: Path, report: dict[str, Any]) -> None:
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as temporary:
        temporary.write(payload)
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, path)


def render_human(report: dict[str, Any]) -> str:
    dimensions = report["dimensions"]
    return "\n".join(
        [
            f"profile: {report['profile']['id']}",
            f"function starts: {dimensions['functionStarts']['status']} "
            f"({dimensions['functionStarts']['oracle']['scoreableFunctionCount']} scoreable oracle functions)",
            f"surviving symbol identity: {dimensions['survivingSymbolIdentity']['status']} "
            f"({dimensions['survivingSymbolIdentity']['oracle']['strippedSurvivingAliasCount']} oracle aliases)",
            f"call edges: {dimensions['callEdges']['status']}",
            f"next boundary: {report['nextBoundary']['id']} ({report['nextBoundary']['status']})",
        ]
    ) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Emit exact retained GCC accuracy coverage and explicit gaps."
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=REPOSITORY_ROOT / "oracle/gcc/16.2.0",
        help="GCC oracle profile directory",
    )
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report = build_report(arguments.profile)
        _write_json(arguments.output, report)
    except CoverageError as error:
        print(f"coverage report failed: {error}", file=sys.stderr)
        return 1
    print(render_human(report), end="")
    print(f"JSON report: {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
