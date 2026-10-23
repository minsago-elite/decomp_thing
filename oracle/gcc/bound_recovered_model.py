"""Load a recovered GCC stripped-twin model bound to the authenticated oracle.

The model bytes must be named by a structural full-export binding and its
qualification record, and both must agree with the profile's artifact manifest
and the stripped oracle artifact.  Callers receive the validated oracle, model
and a provenance record suitable for retaining in a measured report; nothing
here admits the model for release scoring.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from oracle.function_recovery import (
    FunctionOracle,
    RecoveredModel,
    ScoringError,
    load_function_oracle,
    load_program_model,
)
from oracle.gcc.report_accuracy_coverage import (
    CoverageError,
    _json,
    _required_mapping,
    _sha256,
)


TWIN = "stripped"


@dataclass(frozen=True)
class BoundStrippedModel:
    oracle_path: Path
    oracle: FunctionOracle
    model: RecoveredModel
    provenance: dict[str, Any]


def _require_equal(actual: Any, expected: Any, message: str) -> None:
    if actual != expected:
        raise CoverageError(message)


def load_bound_stripped_model(
    profile_directory: Path,
    program_model_path: Path,
    binding_path: Path,
    qualification_path: Path,
    *,
    run_id: int,
    artifact_id: int,
) -> BoundStrippedModel:
    profile_directory = profile_directory.resolve()
    manifest_path = profile_directory / "oracle-manifest.json"
    oracle_path = profile_directory / "function-recovery-oracle.json"
    manifest = _json(manifest_path, "oracle artifact manifest")
    manifest_sha256 = _sha256(manifest_path, "oracle artifact manifest")
    stripped_record = _required_mapping(
        _required_mapping(manifest.get("artifacts"), "manifest.artifacts").get(TWIN),
        f"manifest.artifacts.{TWIN}",
    )
    oracle = load_function_oracle(oracle_path)
    _require_equal(
        oracle.artifact_manifest_sha256,
        manifest_sha256,
        "function recovery oracle is not bound to this artifact manifest",
    )
    artifact = oracle.artifacts[TWIN]
    _require_equal(
        artifact.input_sha256,
        stripped_record.get("sha256"),
        "function oracle stripped artifact disagrees with the manifest",
    )

    binding = _json(binding_path, "structural full-export binding")
    qualification = _json(qualification_path, "qualification record")
    model_sha256 = _sha256(program_model_path, "program model")
    model_binding = _required_mapping(binding.get("programModel"), "binding.programModel")
    input_binding = _required_mapping(binding.get("inputBinary"), "binding.inputBinary")
    target = _required_mapping(binding.get("targetDescriptor"), "binding.targetDescriptor")
    _require_equal(
        binding.get("artifactManifestSha256"),
        manifest_sha256,
        "binding is not bound to this artifact manifest",
    )
    _require_equal(
        input_binding.get("sha256"),
        artifact.input_sha256,
        "binding input binary is not the stripped oracle artifact",
    )
    _require_equal(
        model_binding.get("sha256"),
        model_sha256,
        "program model bytes do not match the binding",
    )
    _require_equal(
        qualification.get("programModelSha256"),
        model_sha256,
        "program model bytes do not match the qualification record",
    )
    _require_equal(
        qualification.get("outputTreeSha256"),
        binding.get("outputTreeSha256"),
        "qualification and binding output trees disagree",
    )
    image_base_text = target.get("imageBase")
    if not isinstance(image_base_text, str):
        raise CoverageError("binding.targetDescriptor.imageBase must be a string")
    image_base = int(image_base_text, 16)
    _require_equal(
        image_base,
        artifact.elf_image_base,
        "binding image base disagrees with the stripped oracle artifact",
    )
    try:
        model = load_program_model(
            program_model_path,
            twin=TWIN,
            artifact=artifact,
            model_image_base=image_base,
        )
    except ScoringError as error:
        raise CoverageError(f"program model rejected: {error}") from error
    _require_equal(
        len(model.functions),
        model_binding.get("functionCount"),
        "program model function count disagrees with the binding",
    )

    provenance = {
        "artifactManifestSha256": manifest_sha256,
        "strippedInputSha256": artifact.input_sha256,
        "imageBase": hex(image_base),
        "workflowRunId": run_id,
        "artifactId": artifact_id,
        "programModel": {
            "sha256": model_sha256,
            "functionCount": len(model.functions),
        },
        "outputTreeSha256": binding.get("outputTreeSha256"),
        "exporterSha256": _required_mapping(
            binding.get("exporter"), "binding.exporter"
        ).get("sha256"),
        "ghidraArchiveSha256": _required_mapping(
            binding.get("ghidraArchive"), "binding.ghidraArchive"
        ).get("sha256"),
        "receiptLineageSha256": binding.get("receiptLineageSha256"),
        "sourceRevision": binding.get("sourceRevision"),
        "qualification": {
            "provider": qualification.get("provider"),
            "releaseEligible": qualification.get("releaseEligible"),
            "complete": qualification.get("complete"),
            "scored": qualification.get("scored"),
            "limitation": qualification.get("limitation"),
        },
    }
    return BoundStrippedModel(
        oracle_path=oracle_path,
        oracle=oracle,
        model=model,
        provenance=provenance,
    )
