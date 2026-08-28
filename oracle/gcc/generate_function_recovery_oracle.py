"""GCC profile for the generic ELF/DWARF oracle generator.

Only manifest authentication, artifact path binding, and the reviewed exclusion
profile live here.  Extraction and normalization semantics are shared by any
compatible ELF pair through :mod:`oracle.function_recovery_oracle`.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
from typing import Any, Callable

from oracle.function_recovery import (
    ScoringError,
    _decode_json,
    _read_regular_snapshot,
    load_function_oracle,
)
from oracle.function_recovery_oracle import (
    OracleGenerationError,
    generate_function_oracle,
    load_explicit_exclusions,
    oracle_json_bytes,
    write_oracle,
)
from oracle.function_recovery_profile import (
    _VerifiedArtifactManifestSnapshot,
    _artifact_metadata_from_manifest,
    _verified_artifact_manifest_snapshot,
)


MAX_GENERATION_SCHEMA_BYTES = 4 * 1024 * 1024


def _schema_validate(document: dict[str, Any], schema_path: Path) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]
    except ModuleNotFoundError as error:
        raise OracleGenerationError(
            "schema validation requires the pinned oracle-generation requirements"
        ) from error
    try:
        schema = _decode_json(
            _read_regular_snapshot(
                schema_path,
                "function oracle schema",
                MAX_GENERATION_SCHEMA_BYTES,
            ),
            "function oracle schema",
        )
        fastjsonschema.compile(schema)(document)
    except (ScoringError, fastjsonschema.JsonSchemaException) as error:
        raise OracleGenerationError(f"generated oracle fails JSON Schema: {error}") from error


def _semantic_validate(document: dict[str, Any]) -> None:
    with tempfile.TemporaryDirectory(prefix="function-oracle-validation-") as directory:
        path = Path(directory) / "oracle.json"
        path.write_bytes(oracle_json_bytes(document))
        try:
            load_function_oracle(path)
        except ScoringError as error:
            raise OracleGenerationError(
                f"generated oracle fails semantic validation: {error}"
            ) from error


def _manifest_snapshot(
    manifest_path: Path,
    artifact_overrides: dict[str, Path],
) -> _VerifiedArtifactManifestSnapshot:
    try:
        return _verified_artifact_manifest_snapshot(
            manifest_path,
            artifact_overrides=artifact_overrides,
        )
    except ScoringError as error:
        raise OracleGenerationError(f"artifact manifest verification failed: {error}") from error


def generate_gcc_profile_oracle(
    *,
    manifest_path: Path,
    exclusions_path: Path,
    output_path: Path,
    schema_path: Path,
    rich_artifact_path: Path | None = None,
    stripped_artifact_path: Path | None = None,
    near_miss_bytes: int = 16,
    symbol_name_selector: Callable[[str], bool] | None = None,
    compilation_unit_selector: Callable[[str], bool] | None = None,
    include_inline_only: bool = True,
) -> dict[str, Any]:
    """Authenticate a benchmark profile and publish its normalized oracle."""

    artifact_overrides = {
        name: path
        for name, path in (
            ("full", rich_artifact_path),
            ("stripped", stripped_artifact_path),
        )
        if path is not None
    }
    with _manifest_snapshot(manifest_path, artifact_overrides) as snapshot:
        manifest_payload = snapshot.manifest_payload
        manifest = snapshot.manifest
        manifest_root = manifest_path.absolute().parent.resolve()
        artifacts = manifest["artifacts"]
        protected_inputs = {
            manifest_path.resolve(strict=False),
            exclusions_path.resolve(strict=False),
            schema_path.resolve(strict=False),
            *(
                path.resolve(strict=False)
                for path in snapshot.dependency_source_paths
            ),
            *(
                (manifest_root / artifacts[name]["path"]).resolve(strict=False)
                for name in ("full", "stripped")
            ),
        }
        if output_path.resolve(strict=False) in protected_inputs:
            raise OracleGenerationError("output must not replace a generation input")
        profile_sha256, exclusions = load_explicit_exclusions(exclusions_path)
        if profile_sha256 != artifacts["full"]["sha256"]:
            raise OracleGenerationError(
                "reviewed exclusion profile is not bound to the rich manifest artifact"
            )

        document = generate_function_oracle(
            snapshot.artifact_paths["rich"],
            snapshot.artifact_paths["stripped"],
            oracle_id=manifest["oracle"]["id"],
            artifact_manifest_sha256=hashlib.sha256(manifest_payload).hexdigest(),
            explicit_exclusions=exclusions,
            expected_rich_sha256=artifacts["full"]["sha256"],
            expected_stripped_sha256=artifacts["stripped"]["sha256"],
            near_miss_bytes=near_miss_bytes,
            symbol_name_selector=symbol_name_selector,
            compilation_unit_selector=compilation_unit_selector,
            include_inline_only=include_inline_only,
        )
        for twin in ("rich", "stripped"):
            expected = _artifact_metadata_from_manifest(manifest, twin)
            actual = document["artifacts"][twin]
            if actual != {
                "inputSha256": expected.input_sha256,
                "elfType": expected.elf_type,
                "elfImageBase": hex(expected.elf_image_base),
                "executableRvaRanges": [
                    {"start": hex(item.start), "endExclusive": hex(item.end_exclusive)}
                    for item in expected.executable_ranges
                ],
            }:
                raise OracleGenerationError(
                    f"generic {twin} ELF metadata disagrees with the verified manifest"
                )
        _schema_validate(document, schema_path)
        _semantic_validate(document)
        write_oracle(output_path, document)
        return document
