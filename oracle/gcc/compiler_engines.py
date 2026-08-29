"""Authenticated GCC cc1/lto1 benchmark profile and derived build records."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from oracle.full_tree_scope import canonical_json_bytes
from oracle.gcc.verify_oracle_artifacts import validate_build_record
from oracle.gcc.verify_source_lock import VerificationError, load_and_validate_lock


MAX_PROFILE_BYTES = 1024 * 1024


def _load_json(path: Path, label: str, maximum: int = MAX_PROFILE_BYTES) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"{label} must be a non-symlink regular file: {path}")
    payload = path.read_bytes()
    if not 0 < len(payload) <= maximum:
        raise VerificationError(f"{label} must contain 1..{maximum} bytes")
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label} is invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"{label} root must be an object")
    return value, payload


def _bound_file(root: Path, relative: str, digest: str, label: str) -> Path:
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or len(candidate.parts) != 1 or candidate.name != relative:
        raise VerificationError(f"{label} path must be one normalized base name")
    path = root / relative
    _, payload = _load_json(path, label, 32 * 1024 * 1024)
    if hashlib.sha256(payload).hexdigest() != digest:
        raise VerificationError(f"{label} SHA-256 does not match compiler-engine profile")
    return path


def derive_engine_build_record(base: dict[str, Any], engine: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    result["schemaVersion"] = 3
    result["buildSystem"] = "autoconf"
    result["oracle"]["sourceProfileId"] = base["oracle"]["id"]
    result["oracle"]["id"] = f"gcc-{engine['id']}-{base['oracle']['version']}"
    result["commands"]["stageFull"] = [
        "/usr/bin/install",
        "-m",
        "0755",
        engine["buildOutput"],
        "{full}",
    ]
    result["outputs"] = {
        "full": engine["fullArtifact"],
        "stripped": engine["strippedArtifact"],
    }
    return result


def load_compiler_engine_profile(path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    profile, payload = _load_json(path, "compiler-engine profile")
    if payload != canonical_json_bytes(profile):
        raise VerificationError("compiler-engine profile is not canonical JSON")
    try:
        import fastjsonschema  # type: ignore[import-untyped]
    except ModuleNotFoundError as error:
        raise VerificationError("compiler-engine validation requires pinned oracle dependencies") from error
    schema, _ = _load_json(Path(__file__).with_name("compiler-engines.schema.json"), "compiler-engine schema")
    try:
        fastjsonschema.compile(schema)(profile)
    except fastjsonschema.JsonSchemaException as error:
        raise VerificationError(f"compiler-engine profile fails JSON Schema: {error}") from error

    root = path.parent
    provenance = profile["provenance"]
    source_path = _bound_file(root, provenance["sourceLockPath"], provenance["sourceLockSha256"], "source lock")
    build_path = _bound_file(root, provenance["baseBuildRecordPath"], provenance["baseBuildRecordSha256"], "base build record")
    _bound_file(root, provenance["toolchainReproductionPath"], provenance["toolchainReproductionSha256"], "toolchain reproduction lock")
    source_lock = load_and_validate_lock(source_path)
    base, _ = _load_json(build_path, "base build record", 32 * 1024 * 1024)
    validate_build_record(base, source_lock, provenance["sourceLockSha256"])
    if base["oracle"]["version"] != profile["benchmark"]["version"]:
        raise VerificationError("compiler-engine benchmark version does not match base build")
    if base["commands"]["compile"] != ["/usr/bin/make", "-j4", "all-gcc"]:
        raise VerificationError("compiler-engine base build must use the authenticated all-gcc command")

    engines = profile["engines"]
    if [engine["id"] for engine in engines] != ["cc1", "lto1"]:
        raise VerificationError("compiler engines must be ordered cc1 then lto1")
    derived: dict[str, dict[str, Any]] = {}
    for engine in engines:
        identifier = engine["id"]
        expected = {
            "buildOutput": f"/oracle/build/gcc/{identifier}",
            "buildRecord": f"{identifier}-build-record.json",
            "fullArtifact": f"artifacts/gcc-{identifier}.full",
            "functionOracle": f"{identifier}-function-recovery-oracle.json",
            "oracleManifest": f"{identifier}-oracle-manifest.json",
            "reconstructionArchive": f"{identifier}-reconstruction.zip",
            "strippedArtifact": f"artifacts/gcc-{identifier}.stripped",
        }
        for field, value in expected.items():
            if engine[field] != value:
                raise VerificationError(f"compiler engine {identifier} has inconsistent {field}")
        record = derive_engine_build_record(base, engine)
        validate_build_record(record, source_lock, provenance["sourceLockSha256"])
        derived[identifier] = record
    return profile, derived
