"""LLVM provenance adapter for the program-agnostic behavior runner."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
import tempfile
from typing import Any, Mapping

from oracle.behavior_corpus import (
    BehaviorCorpusError,
    _container_runtime_environment,
    _snapshot_control_client,
    _verify_oci_runtime,
    _write_exclusive,
    load_corpus,
    run_corpus,
)
from oracle.elf_oracle import verify_oracle_manifest
from oracle.llvm.generate_behavior_corpus import sandbox_profile
from oracle.source_lock import VerificationError


def _resolve_profile_path(directory: Path, relative: str, label: str) -> Path:
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise BehaviorCorpusError(f"{label} path in LLVM manifest is not canonical")
    root = directory.resolve()
    path = root.joinpath(*candidate.parts)
    if path.is_symlink():
        raise BehaviorCorpusError(f"{label} path in LLVM manifest is a symlink")
    try:
        path.resolve().relative_to(root)
    except ValueError as error:
        raise BehaviorCorpusError(f"{label} path escapes the LLVM profile") from error
    return path


def _authenticate_profile(corpus: Mapping[str, Any], manifest_path: Path) -> Path:
    try:
        manifest = verify_oracle_manifest(manifest_path)
    except VerificationError as error:
        raise BehaviorCorpusError(
            f"LLVM artifact manifest verification failed: {error}"
        ) from error
    if corpus["scope"] != "production" or corpus["id"] != "clang-22-1-6-driver-behavior":
        raise BehaviorCorpusError("LLVM behavior adapter requires its production corpus id")
    if corpus["sandbox"] != sandbox_profile():
        raise BehaviorCorpusError("LLVM behavior corpus changed its authenticated executor profile")
    stripped = manifest["artifacts"]["stripped"]
    if corpus["executable"] != {
        "bytes": stripped["bytes"],
        "sha256": stripped["sha256"],
    }:
        raise BehaviorCorpusError(
            "LLVM behavior corpus executable does not match the verified stripped twin"
        )
    directory = manifest_path.absolute().parent.resolve()
    executable_path = _resolve_profile_path(directory, stripped["path"], "stripped artifact")
    return executable_path


def run_llvm_behavior_corpus(
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


def verify_llvm_executor_profile(
    container_runtime: Path,
    *,
    container_runtime_environment: Mapping[str, str] | None = None,
) -> None:
    environment = _container_runtime_environment(container_runtime_environment)
    payload = _snapshot_control_client(container_runtime)
    with tempfile.TemporaryDirectory(prefix="behavior-executor-probe-") as directory:
        staged = Path(directory) / "container-runtime"
        _write_exclusive(staged, payload, 0o500)
        _verify_oci_runtime(staged, environment, sandbox_profile())
