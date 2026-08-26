"""GCC provenance adapter for the program-agnostic behavior runner."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import tempfile
from typing import Any, Mapping

from oracle.behavior_corpus import (
    BehaviorCorpusError,
    _container_runtime_environment,
    _decode_json,
    _read_regular_snapshot,
    _snapshot_control_client,
    _verify_oci_runtime,
    _write_exclusive,
    load_corpus,
    run_corpus,
)
from oracle.gcc.generate_behavior_corpus import sandbox_profile
from oracle.gcc.verify_oracle_artifacts import verify_oracle_manifest
from oracle.gcc.verify_source_lock import VerificationError


def _resolve_profile_path(directory: Path, relative: str, label: str) -> Path:
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise BehaviorCorpusError(f"{label} path in GCC manifest is not canonical")
    root = directory.resolve()
    path = root.joinpath(*candidate.parts)
    if path.is_symlink():
        raise BehaviorCorpusError(f"{label} path in GCC manifest is a symlink")
    try:
        path.resolve().relative_to(root)
    except ValueError as error:
        raise BehaviorCorpusError(f"{label} path escapes the GCC profile") from error
    return path


def _authenticate_profile(
    corpus: Mapping[str, Any], manifest_path: Path
) -> Path:
    try:
        manifest = verify_oracle_manifest(manifest_path)
    except VerificationError as error:
        raise BehaviorCorpusError(f"GCC artifact manifest verification failed: {error}") from error
    if corpus["scope"] != "production" or corpus["id"] != "gcc-16-2-0-driver-behavior":
        raise BehaviorCorpusError("GCC behavior adapter requires its production corpus id")
    if corpus["sandbox"] != sandbox_profile():
        raise BehaviorCorpusError(
            "GCC behavior corpus changed its authenticated executor profile"
        )
    stripped = manifest["artifacts"]["stripped"]
    if (
        corpus["executable"]["bytes"] != stripped["bytes"]
        or corpus["executable"]["sha256"] != stripped["sha256"]
    ):
        raise BehaviorCorpusError(
            "GCC behavior corpus executable does not match the verified stripped twin"
        )
    directory = manifest_path.absolute().parent.resolve()
    executable_path = _resolve_profile_path(
        directory, stripped["path"], "stripped artifact"
    )
    build_input = manifest["inputs"]["buildRecord"]
    build_path = _resolve_profile_path(directory, build_input["path"], "build record")
    try:
        build_payload = _read_regular_snapshot(
            build_path, "verified GCC build record", 16 * 1024 * 1024
        )
        if (
            len(build_payload) != build_input["bytes"]
            or hashlib.sha256(build_payload).hexdigest() != build_input["sha256"]
        ):
            raise BehaviorCorpusError(
                "GCC build record snapshot no longer matches the verified manifest"
            )
        build_record = _decode_json(build_payload, "verified GCC build record")
        image_digest = build_record["environment"]["container"]["digest"]
        platform_name = build_record["environment"]["container"]["platform"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise BehaviorCorpusError(f"cannot read verified GCC build runtime: {error}") from error
    if (
        corpus["sandbox"]["imageDigest"] != image_digest
        or corpus["sandbox"]["platform"] != platform_name
    ):
        raise BehaviorCorpusError(
            "GCC behavior sandbox does not match the verified build runtime"
        )
    return executable_path


def run_gcc_behavior_corpus(
    corpus_path: Path,
    manifest_path: Path,
    *,
    container_runtime: Path,
    container_runtime_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    corpus, payload = load_corpus(corpus_path)
    executable_path = _authenticate_profile(corpus, manifest_path)
    return run_corpus(
        corpus,
        executable_path,
        corpus_payload=payload,
        container_runtime=container_runtime,
        container_runtime_environment=container_runtime_environment,
    )


def verify_gcc_executor_profile(
    container_runtime: Path,
    *,
    container_runtime_environment: Mapping[str, str] | None = None,
) -> None:
    """Verify the GCC example's exact executor using one private client snapshot."""

    runtime_environment = _container_runtime_environment(
        container_runtime_environment
    )
    runtime_payload = _snapshot_control_client(container_runtime)
    with tempfile.TemporaryDirectory(prefix="behavior-executor-probe-") as directory:
        staged_runtime = Path(directory) / "container-runtime"
        _write_exclusive(staged_runtime, runtime_payload, 0o500)
        _verify_oci_runtime(
            staged_runtime,
            runtime_environment,
            sandbox_profile(),
        )
