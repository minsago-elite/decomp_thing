"""GCC benchmark adapter for the program-agnostic recovery scorer.

This module preserves the issue #39 import/CLI surface while adding only the
GCC oracle-manifest and ELF-twin authentication profile. Matching, metrics,
model loading, report rendering, and schemas are defined by
``oracle.function_recovery`` and contain no GCC-specific semantics.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Mapping

from oracle.function_recovery import (
    Artifact,
    Evidence,
    ExecutableRange,
    FunctionOracle,
    NearAssignment,
    OracleAlias,
    OracleFunction,
    RecoveredFunction,
    RecoveredModel,
    ScoringError,
    MAX_ALIASES_PER_FUNCTION,
    MAX_AMBIGUITY_EDGES,
    MAX_ARTIFACT_BYTES,
    MAX_EVIDENCE_PER_ALIAS,
    MAX_FUNCTION_RECORDS,
    MAX_IDENTIFIER_CHARACTERS,
    MAX_JSON_INPUT_BYTES,
    MAX_MANIFEST_BYTES,
    MAX_MATCHING_CELLS,
    MAX_MODEL_GLOBALS_OR_TYPES,
    MAX_MODEL_REFERENCES_PER_FUNCTION,
    MAX_REPORT_BYTES,
    MAX_SUPPORTING_INPUT_BYTES,
    MAX_TEXT_CHARACTERS,
    _ScoringContext,
    _TWIN_NAMES,
    _artifact_verified_unattested_model_context,
    _decode_json,
    _fixture_context,
    _integer,
    _minimum_cost_near_assignment,
    _object,
    _read_regular_snapshot,
    _score_function_recovery_with_context,
    _string,
    load_function_oracle,
    load_program_model,
    render_human_report,
    report_json_bytes,
    score_function_recovery,
    write_report,
)


def _stage_bounded_regular_snapshot(
    source: Path,
    destination: Path,
    label: str,
    maximum_bytes: int,
    *,
    expected_bytes: int | None = None,
) -> None:
    """Stream one stable, bounded source snapshot into a private staging tree."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_descriptor: int | None = None
    destination_descriptor: int | None = None
    try:
        if source.is_symlink():
            raise ScoringError(f"{label} is not a non-symlink regular file: {source}")
        source_descriptor = os.open(source, flags)
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ScoringError(f"{label} is not a non-symlink regular file: {source}")
        if before.st_size > maximum_bytes:
            raise ScoringError(
                f"{label} exceeds the {maximum_bytes}-byte input limit"
            )
        if expected_bytes is not None and before.st_size != expected_bytes:
            raise ScoringError(
                f"{label} byte length does not match the artifact manifest"
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        copied = 0
        while copied < before.st_size:
            chunk = os.read(source_descriptor, min(1024 * 1024, before.st_size - copied))
            if not chunk:
                break
            offset = 0
            while offset < len(chunk):
                written = os.write(destination_descriptor, chunk[offset:])
                if written <= 0:
                    raise ScoringError(f"could not finish staging {label}")
                offset += written
            copied += len(chunk)
        grew = bool(os.read(source_descriptor, 1))
        after = os.fstat(source_descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or copied != after.st_size or grew:
            raise ScoringError(f"{label} changed while its snapshot was staged")
    except ScoringError:
        raise
    except MemoryError as error:
        raise ScoringError(
            f"not enough memory to stage the bounded {label} snapshot"
        ) from error
    except OSError as error:
        raise ScoringError(f"cannot stage {label} {source}: {error}") from error
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)


def _stage_payload(
    destination: Path,
    payload: bytes | bytearray,
    label: str,
) -> None:
    """Write an already authenticated in-memory snapshot without another copy."""

    descriptor: int | None = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        view = memoryview(payload)
        written = 0
        try:
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise ScoringError(f"could not finish staging {label}")
                written += count
        finally:
            view.release()
    except MemoryError as error:
        raise ScoringError(
            f"not enough memory to stage the bounded {label} snapshot"
        ) from error
    except OSError as error:
        raise ScoringError(f"cannot stage {label}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _verify_artifact_manifest_binding(
    oracle: FunctionOracle,
    artifact_manifest_path: Path | None,
) -> _ScoringContext:
    if oracle.scope == "fixture":
        if artifact_manifest_path is not None:
            raise ScoringError(
                "fixture scoring may not claim an artifact-manifest binding"
            )
        return _fixture_context()
    if artifact_manifest_path is None:
        raise ScoringError(
            "production scoring requires the bound --artifact-manifest"
        )
    assert oracle.artifact_manifest_sha256 is not None
    manifest_payload = _read_regular_snapshot(
        artifact_manifest_path,
        "artifact manifest",
        MAX_MANIFEST_BYTES,
    )
    actual_manifest_sha256 = hashlib.sha256(manifest_payload).hexdigest()
    if actual_manifest_sha256 != oracle.artifact_manifest_sha256:
        raise ScoringError(
            "artifact manifest SHA-256 does not match the production function oracle"
        )

    # Verify the exact bytes just hashed. Calling verify_oracle_manifest(path)
    # would reopen the pathname and permit a hash/verification snapshot race.
    from oracle.gcc.verify_oracle_artifacts import (
        _assemble_manifest,
        _compare_exact,
        _resolve_within,
        _validate_input_record,
    )
    from oracle.gcc.verify_source_lock import VerificationError

    try:
        manifest = _decode_json(manifest_payload, "artifact manifest")
        manifest_root = _object(
            manifest,
            "artifact manifest",
            {"schemaVersion", "oracle", "inputs", "artifacts", "equivalence"},
        )
        if (
            isinstance(manifest_root["schemaVersion"], bool)
            or manifest_root["schemaVersion"] != 1
        ):
            raise ScoringError("artifact manifest schemaVersion must be the integer 1")
        inputs = _object(
            manifest_root["inputs"],
            "artifact manifest.inputs",
            {"sourceLock", "buildRecord"},
        )
        source_record = _validate_input_record(
            inputs["sourceLock"],
            "artifact manifest.inputs.sourceLock",
        )
        build_record = _validate_input_record(
            inputs["buildRecord"],
            "artifact manifest.inputs.buildRecord",
        )
        directory = artifact_manifest_path.absolute().parent.resolve()
        source_path = _resolve_within(directory, source_record["path"], "source lock")
        build_path = _resolve_within(directory, build_record["path"], "build record")
        source_bytes = _integer(
            source_record["bytes"],
            "artifact manifest.inputs.sourceLock.bytes",
            minimum=1,
            maximum=MAX_SUPPORTING_INPUT_BYTES,
        )
        build_bytes = _integer(
            build_record["bytes"],
            "artifact manifest.inputs.buildRecord.bytes",
            minimum=1,
            maximum=MAX_SUPPORTING_INPUT_BYTES,
        )
        source_payload = _read_regular_snapshot(
            source_path,
            "source lock",
            MAX_SUPPORTING_INPUT_BYTES,
        )
        build_payload = _read_regular_snapshot(
            build_path,
            "build record",
            MAX_SUPPORTING_INPUT_BYTES,
        )
        if len(source_payload) != source_bytes:
            raise ScoringError(
                "source lock byte length does not match the artifact manifest"
            )
        if len(build_payload) != build_bytes:
            raise ScoringError(
                "build record byte length does not match the artifact manifest"
            )
        source_lock = _decode_json(source_payload, "source lock")
        build_data = _decode_json(build_payload, "build record")

        tag_evidence = source_lock["revision"]["tagEvidence"]
        supporting_records: tuple[tuple[Any, Any, str], ...] = (
            (
                tag_evidence["payloadFile"],
                tag_evidence["payloadBytes"],
                "annotated-tag payload",
            ),
            (
                tag_evidence["signatureFile"],
                tag_evidence["signatureBytes"],
                "annotated-tag signature",
            ),
            (
                source_lock["signing"]["keyFile"],
                None,
                "release signing key",
            ),
        )
        evidence_sources: list[tuple[Path, str, int | None]] = []
        for relative, expected_evidence_bytes, label in supporting_records:
            relative_path = _string(
                relative,
                f"source lock {label} path",
                maximum=MAX_IDENTIFIER_CHARACTERS,
            )
            evidence_path = _resolve_within(
                source_path.parent,
                relative_path,
                label,
            )
            validated_expected_bytes: int | None = None
            if expected_evidence_bytes is not None:
                validated_expected_bytes = _integer(
                    expected_evidence_bytes,
                    f"source lock {label} bytes",
                    minimum=0,
                    maximum=MAX_SUPPORTING_INPUT_BYTES,
                )
            evidence_sources.append(
                (evidence_path, label, validated_expected_bytes)
            )

        artifact_records = _object(
            manifest_root["artifacts"],
            "artifact manifest.artifacts",
            {"full", "stripped"},
        )
        build_outputs = _object(
            build_data["outputs"],
            "build record.outputs",
            {"full", "stripped"},
        )
        artifact_sources: list[tuple[Path, str, int]] = []
        for manifest_name in ("full", "stripped"):
            record_path = f"artifact manifest.artifacts.{manifest_name}"
            artifact_record = _object(
                artifact_records[manifest_name],
                record_path,
                {"path", "bytes", "sha256", "elf"},
            )
            relative_path = _string(
                artifact_record["path"],
                f"{record_path}.path",
                maximum=MAX_IDENTIFIER_CHARACTERS,
            )
            build_relative_path = _string(
                build_outputs[manifest_name],
                f"build record.outputs.{manifest_name}",
                maximum=MAX_IDENTIFIER_CHARACTERS,
            )
            if relative_path != build_relative_path:
                raise ScoringError(
                    f"{record_path}.path does not match the build-record output"
                )
            recorded_bytes = _integer(
                artifact_record["bytes"],
                f"{record_path}.bytes",
                minimum=1,
                maximum=MAX_ARTIFACT_BYTES,
            )
            artifact_path = _resolve_within(
                directory,
                relative_path,
                f"{manifest_name} artifact",
            )
            artifact_sources.append(
                (artifact_path, f"{manifest_name} artifact", recorded_bytes)
            )

        # The legacy GCC derivation helpers are intentionally reused for their
        # schema/signature/ELF checks, but they read by pathname.  Give them a
        # private tree of stable bounded snapshots rather than the mutable
        # original paths checked above.
        with tempfile.TemporaryDirectory(
            prefix="gcc-function-score-manifest-"
        ) as staging_directory:
            staging_root = Path(staging_directory)
            staged_source = staging_root / source_path.relative_to(directory)
            staged_build = staging_root / build_path.relative_to(directory)
            _stage_payload(staged_source, source_payload, "source lock")
            _stage_payload(staged_build, build_payload, "build record")

            for evidence_path, label, expected_evidence_bytes in evidence_sources:
                staged_evidence = staging_root / evidence_path.relative_to(directory)
                _stage_bounded_regular_snapshot(
                    evidence_path,
                    staged_evidence,
                    label,
                    MAX_SUPPORTING_INPUT_BYTES,
                    expected_bytes=expected_evidence_bytes,
                )

            for artifact_path, label, recorded_bytes in artifact_sources:
                staged_artifact = staging_root / artifact_path.relative_to(directory)
                _stage_bounded_regular_snapshot(
                    artifact_path,
                    staged_artifact,
                    label,
                    MAX_ARTIFACT_BYTES,
                    expected_bytes=recorded_bytes,
                )

            expected = _assemble_manifest(
                staging_root,
                staged_source,
                source_record["path"],
                staged_build,
                build_record["path"],
            )
        _compare_exact(manifest, expected, "artifact manifest")
    except ScoringError:
        raise
    except MemoryError as error:
        raise ScoringError(
            "not enough memory to verify bounded artifact-manifest inputs"
        ) from error
    except (
        VerificationError,
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
        OSError,
    ) as error:
        raise ScoringError(f"artifact manifest verification failed: {error}") from error

    manifest_hashes = {
        "rich": manifest["artifacts"]["full"]["sha256"],
        "stripped": manifest["artifacts"]["stripped"]["sha256"],
    }
    if oracle.identifier != manifest["oracle"]["id"]:
        raise ScoringError(
            "function-oracle id does not match the artifact manifest oracle id"
        )
    for twin in _TWIN_NAMES:
        if oracle.artifacts[twin].input_sha256 != manifest_hashes[twin]:
            raise ScoringError(
                f"{twin} function-oracle artifact hash does not match artifact manifest"
            )
        observed_metadata = _artifact_metadata_from_manifest(manifest, twin)
        recorded_metadata = oracle.artifacts[twin]
        if recorded_metadata.elf_type != observed_metadata.elf_type:
            raise ScoringError(
                f"{twin} function-oracle ELF type does not match artifact manifest"
            )
        if recorded_metadata.elf_image_base != observed_metadata.elf_image_base:
            raise ScoringError(
                f"{twin} function-oracle ELF image base does not match artifact manifest"
            )
        if recorded_metadata.executable_ranges != observed_metadata.executable_ranges:
            raise ScoringError(
                f"{twin} function-oracle executable ranges do not match artifact manifest"
            )
    return _artifact_verified_unattested_model_context()


def _artifact_metadata_from_manifest(
    manifest: Mapping[str, Any],
    twin: str,
) -> Artifact:
    manifest_name = "full" if twin == "rich" else "stripped"
    artifact = manifest["artifacts"][manifest_name]
    elf = artifact["elf"]
    load_segments = [
        segment
        for segment in elf["programHeaders"]
        if segment["typeName"] == "PT_LOAD" and segment["memorySize"] > 0
    ]
    if not load_segments:
        raise ScoringError(f"{twin} artifact manifest has no nonempty PT_LOAD")
    image_base = min(segment["virtualAddress"] for segment in load_segments)
    executable_ranges = tuple(
        ExecutableRange(
            start=segment["virtualAddress"] - image_base,
            end_exclusive=(
                segment["virtualAddress"] + segment["memorySize"] - image_base
            ),
        )
        for segment in sorted(load_segments, key=lambda value: value["virtualAddress"])
        if segment["flags"] & 1
    )
    if not executable_ranges:
        raise ScoringError(f"{twin} artifact manifest has no executable PT_LOAD")
    return Artifact(
        input_sha256=artifact["sha256"],
        elf_type=elf["header"]["typeName"],
        elf_image_base=image_base,
        executable_ranges=executable_ranges,
    )


def _score_files_impl(
    oracle_path: Path,
    rich_model_path: Path,
    stripped_model_path: Path,
    *,
    rich_model_image_base: int,
    stripped_model_image_base: int,
    artifact_manifest_path: Path | None = None,
) -> dict[str, Any]:
    oracle = load_function_oracle(oracle_path)
    context = _verify_artifact_manifest_binding(oracle, artifact_manifest_path)
    if oracle.scope == "production":
        supplied_bases = {
            "rich": rich_model_image_base,
            "stripped": stripped_model_image_base,
        }
        for twin in _TWIN_NAMES:
            if supplied_bases[twin] != oracle.artifacts[twin].elf_image_base:
                raise ScoringError(
                    f"{twin} program-model image base must equal the "
                    "manifest-validated ELF image base for production schema-v1 scoring"
                )
    recovered = {
        "rich": load_program_model(
            rich_model_path,
            twin="rich",
            artifact=oracle.artifacts["rich"],
            model_image_base=rich_model_image_base,
        ),
        "stripped": load_program_model(
            stripped_model_path,
            twin="stripped",
            artifact=oracle.artifacts["stripped"],
            model_image_base=stripped_model_image_base,
        ),
    }
    return _score_function_recovery_with_context(oracle, recovered, context)


def score_files(
    oracle_path: Path,
    rich_model_path: Path,
    stripped_model_path: Path,
    *,
    rich_model_image_base: int,
    stripped_model_image_base: int,
    artifact_manifest_path: Path | None = None,
) -> dict[str, Any]:
    """Authenticate the GCC artifact profile, then invoke the generic scorer."""

    try:
        return _score_files_impl(
            oracle_path,
            rich_model_path,
            stripped_model_path,
            rich_model_image_base=rich_model_image_base,
            stripped_model_image_base=stripped_model_image_base,
            artifact_manifest_path=artifact_manifest_path,
        )
    except ScoringError:
        raise
    except MemoryError as error:
        raise ScoringError(
            "not enough memory for the bounded function-recovery score"
        ) from error
    except ValueError as error:
        raise ScoringError(f"invalid scoring input value: {error}") from error
