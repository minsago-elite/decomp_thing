"""Load a recovered GCC stripped-twin model bound to the authenticated oracle.

The model bytes must be named by a closed-schema structural full-export binding
and its qualification record, and both must agree with the profile's artifact
manifest and the stripped oracle artifact.  The model is hashed and parsed from
one snapshot.  Callers receive the validated oracle, model and a provenance
record suitable for retaining in a measured report; nothing here admits the
model for release scoring, and a qualification claiming release eligibility is
rejected because no release-scoring authority exists for this capture.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

from oracle.function_recovery import (
    Artifact,
    FunctionOracle,
    RecoveredModel,
    ScoringError,
    load_function_oracle,
    load_program_model,
)
from oracle.gcc.report_accuracy_coverage import (
    CoverageError,
    _json,
    _json_snapshot,
    _required_mapping,
    _sha256,
)


TWIN = "stripped"
BINDING_PROVIDER = "gcc-compiler-engine-structural-full-export-binding-v2"
LINEAGE_PROVIDER = "gcc-bundled-full-export-receipt-lineage-v1"
QUALIFICATION_PROVIDER = "gcc-driver-live-full-export-capture-v1"
PROFILE_ID = "gcc-driver-16.2.0"
PROFILE_VERSION = "16.2.0"
# Matches the producer cap in GccBundledFullExportCliResult; the qualification
# record is a small fixed-shape object.
BINDING_MAX_BYTES = 256 * 1024
QUALIFICATION_MAX_BYTES = 64 * 1024

BINDING_KEYS = frozenset(
    {
        "artifactManifestSha256",
        "compilerEngineProfileSha256",
        "exporter",
        "fullExportProfileSha256",
        "ghidraArchive",
        "inputBinary",
        "outputTreeSha256",
        "profileId",
        "profileVersion",
        "programModel",
        "provider",
        "receiptLineage",
        "receiptLineageSha256",
        "schemaVersion",
        "sourceRevision",
        "targetDescriptor",
        "targetDescriptorSha256",
    }
)
LINEAGE_KEYS = frozenset(
    {
        "compilerEngineProfileSha256",
        "engineId",
        "executionPayloadSha256",
        "executionReceiptSha256",
        "exportAssessmentReceiptSha256",
        "exportAssessmentSha256",
        "intentSha256",
        "operationId",
        "provider",
        "schemaVersion",
    }
)
TARGET_DESCRIPTOR = {
    "abi": "sysv-amd64",
    "architecture": "x86_64",
    "dataEncoding": "little-endian",
    "elfClass": "ELF64",
    "elfType": "ET_EXEC",
    "ghidraCompilerSpec": "gcc",
    "ghidraLanguage": "x86:LE:64:default",
    "id": "sysv-amd64-elf-v1",
    "machine": 62,
    "osAbi": 3,
    "pointerBits": 64,
}
TARGET_DIGEST_KEYS = frozenset({"checkedTargetAbiSha256", "executableRangesSha256"})
QUALIFICATION_KEYS = frozenset(
    {
        "benchmarkAccepted",
        "boundaryBindingSha256",
        "boundaryObservationSha256",
        "complete",
        "diagnosticStdoutAuthority",
        "diagnosticStdoutBytes",
        "diagnosticStdoutSha256",
        "engine",
        "functionCount",
        "limitation",
        "operationId",
        "outputTreeSha256",
        "programModelBytes",
        "programModelSha256",
        "provider",
        "releaseEligible",
        "requestSha256",
        "scored",
    }
)
_DIGEST = re.compile(r"[0-9a-f]{64}")
_REVISION = re.compile(r"[0-9a-f]{40}")
_IMAGE_BASE = re.compile(r"0x[0-9a-f]+")


@dataclass(frozen=True)
class BoundStrippedModel:
    oracle: FunctionOracle
    model: RecoveredModel
    provenance: dict[str, Any]


def _require_equal(actual: Any, expected: Any, message: str) -> None:
    if actual != expected:
        raise CoverageError(message)


def _require_keys(value: dict[str, Any], keys: frozenset[str], label: str) -> None:
    if set(value) != keys:
        raise CoverageError(f"{label} does not have the closed schema key set")


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise CoverageError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _count(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise CoverageError(f"{label} must be a non-negative integer")
    return value


def _commitment(value: Any, label: str, extra: frozenset[str] = frozenset()) -> dict[str, Any]:
    mapping = _required_mapping(value, label)
    _require_keys(mapping, frozenset({"bytes", "sha256"}) | extra, label)
    _count(mapping["bytes"], f"{label}.bytes")
    _digest(mapping["sha256"], f"{label}.sha256")
    return mapping


def verify_binding(binding: dict[str, Any]) -> None:
    """Reject anything but a closed v2 structural full-export binding."""

    _require_keys(binding, BINDING_KEYS, "binding")
    _require_equal(binding["provider"], BINDING_PROVIDER, "binding provider is not v2")
    if type(binding["schemaVersion"]) is not int or binding["schemaVersion"] != 2:
        raise CoverageError("binding schemaVersion must be 2")
    _require_equal(binding["profileId"], PROFILE_ID, "binding profileId is not the driver profile")
    _require_equal(
        binding["profileVersion"], PROFILE_VERSION, "binding profileVersion disagrees"
    )
    for key in (
        "artifactManifestSha256",
        "compilerEngineProfileSha256",
        "fullExportProfileSha256",
        "outputTreeSha256",
        "receiptLineageSha256",
        "targetDescriptorSha256",
    ):
        _digest(binding[key], f"binding.{key}")
    source_revision = binding["sourceRevision"]
    if not isinstance(source_revision, str) or _REVISION.fullmatch(source_revision) is None:
        raise CoverageError("binding.sourceRevision must be a full lowercase commit id")
    exporter = _commitment(binding["exporter"], "binding.exporter", frozenset({"recoveryMode"}))
    _require_equal(exporter["recoveryMode"], "full", "binding exporter is not a full export")
    _commitment(binding["ghidraArchive"], "binding.ghidraArchive")
    _commitment(binding["inputBinary"], "binding.inputBinary")
    model = _commitment(
        binding["programModel"], "binding.programModel", frozenset({"functionCount"})
    )
    _count(model["functionCount"], "binding.programModel.functionCount")

    lineage = _required_mapping(binding["receiptLineage"], "binding.receiptLineage")
    _require_keys(lineage, LINEAGE_KEYS, "binding.receiptLineage")
    _require_equal(lineage["provider"], LINEAGE_PROVIDER, "receipt lineage provider disagrees")
    if type(lineage["schemaVersion"]) is not int or lineage["schemaVersion"] != 1:
        raise CoverageError("receipt lineage schemaVersion must be 1")
    _require_equal(lineage["engineId"], "driver", "receipt lineage engine is not the driver")
    for key in LINEAGE_KEYS - {"provider", "schemaVersion", "engineId"}:
        _digest(lineage[key], f"binding.receiptLineage.{key}")
    _require_equal(
        lineage["compilerEngineProfileSha256"],
        binding["compilerEngineProfileSha256"],
        "receipt lineage compiler engine profile disagrees with the binding",
    )

    target = _required_mapping(binding["targetDescriptor"], "binding.targetDescriptor")
    _require_keys(
        target,
        frozenset(TARGET_DESCRIPTOR) | TARGET_DIGEST_KEYS | {"imageBase"},
        "binding.targetDescriptor",
    )
    for key, expected in TARGET_DESCRIPTOR.items():
        if type(target[key]) is not type(expected) or target[key] != expected:
            raise CoverageError(f"binding.targetDescriptor.{key} disagrees with the profile")
    for key in TARGET_DIGEST_KEYS:
        _digest(target[key], f"binding.targetDescriptor.{key}")
    image_base = target["imageBase"]
    if not isinstance(image_base, str) or _IMAGE_BASE.fullmatch(image_base) is None:
        raise CoverageError("binding.targetDescriptor.imageBase must be lowercase hex")


def verify_qualification(qualification: dict[str, Any], binding: dict[str, Any]) -> None:
    """Accept only a non-release diagnostic qualification bound to ``binding``."""

    _require_keys(qualification, QUALIFICATION_KEYS, "qualification")
    _require_equal(
        qualification["provider"], QUALIFICATION_PROVIDER, "qualification provider disagrees"
    )
    _require_equal(qualification["engine"], "driver", "qualification engine is not the driver")
    for key in ("releaseEligible", "scored", "benchmarkAccepted", "complete"):
        if qualification[key] is not False:
            raise CoverageError(
                f"qualification.{key} must be false; no release-scoring authority "
                "exists for this capture"
            )
    for key in (
        "boundaryBindingSha256",
        "boundaryObservationSha256",
        "diagnosticStdoutSha256",
        "operationId",
        "outputTreeSha256",
        "programModelSha256",
        "requestSha256",
    ):
        _digest(qualification[key], f"qualification.{key}")
    if not isinstance(qualification["limitation"], str) or not qualification["limitation"]:
        raise CoverageError("qualification.limitation must be a non-empty string")
    _count(qualification["diagnosticStdoutBytes"], "qualification.diagnosticStdoutBytes")
    lineage = binding["receiptLineage"]
    model = binding["programModel"]
    _require_equal(
        qualification["operationId"],
        lineage["operationId"],
        "qualification operation disagrees with the receipt lineage",
    )
    _require_equal(
        qualification["requestSha256"],
        lineage["intentSha256"],
        "qualification request disagrees with the receipt lineage intent",
    )
    _require_equal(
        qualification["outputTreeSha256"],
        binding["outputTreeSha256"],
        "qualification and binding output trees disagree",
    )
    _require_equal(
        qualification["programModelSha256"],
        model["sha256"],
        "qualification and binding program models disagree",
    )
    _require_equal(
        _count(qualification["programModelBytes"], "qualification.programModelBytes"),
        model["bytes"],
        "qualification and binding program model sizes disagree",
    )
    _require_equal(
        _count(qualification["functionCount"], "qualification.functionCount"),
        model["functionCount"],
        "qualification and binding function counts disagree",
    )


def bound_provenance(
    manifest_sha256: str,
    artifact: Artifact,
    binding: dict[str, Any],
    qualification: dict[str, Any],
) -> dict[str, Any]:
    """Verify both records against the oracle and return their provenance.

    The provenance is derived only from the verified records, so a retained
    report can be checked against the same binding without the model bytes.
    """

    verify_binding(binding)
    verify_qualification(qualification, binding)
    _require_equal(
        binding["artifactManifestSha256"],
        manifest_sha256,
        "binding is not bound to this artifact manifest",
    )
    _require_equal(
        binding["inputBinary"]["sha256"],
        artifact.input_sha256,
        "binding input binary is not the stripped oracle artifact",
    )
    image_base = int(binding["targetDescriptor"]["imageBase"], 16)
    _require_equal(
        image_base,
        artifact.elf_image_base,
        "binding image base disagrees with the stripped oracle artifact",
    )
    model_binding = binding["programModel"]
    return {
        "artifactManifestSha256": manifest_sha256,
        "strippedInputSha256": artifact.input_sha256,
        "imageBase": hex(image_base),
        "programModel": {
            "sha256": model_binding["sha256"],
            "functionCount": model_binding["functionCount"],
        },
        "outputTreeSha256": binding["outputTreeSha256"],
        "exporterSha256": binding["exporter"]["sha256"],
        "ghidraArchiveSha256": binding["ghidraArchive"]["sha256"],
        "receiptLineageSha256": binding["receiptLineageSha256"],
        "sourceRevision": binding["sourceRevision"],
        "qualification": {
            "provider": qualification["provider"],
            "releaseEligible": False,
            "complete": qualification["complete"],
            "scored": qualification["scored"],
            "limitation": qualification["limitation"],
        },
    }


@dataclass(frozen=True)
class BoundRecords:
    provenance: dict[str, Any]
    binding_record: dict[str, Any]
    qualification_record: dict[str, Any]


def load_bound_provenance(
    manifest_sha256: str,
    artifact: Artifact,
    binding_path: Path,
    qualification_path: Path,
) -> BoundRecords:
    """Read both records through bounded snapshots and return their provenance.

    The byte records describe the same snapshots that were verified.
    """

    binding, binding_record = _json_snapshot(
        binding_path, "structural full-export binding", BINDING_MAX_BYTES
    )
    qualification, qualification_record = _json_snapshot(
        qualification_path, "qualification record", QUALIFICATION_MAX_BYTES
    )
    return BoundRecords(
        provenance=bound_provenance(manifest_sha256, artifact, binding, qualification),
        binding_record=binding_record,
        qualification_record=qualification_record,
    )


def load_bound_stripped_model(
    profile_directory: Path,
    program_model_path: Path,
    binding_path: Path,
    qualification_path: Path,
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

    provenance = load_bound_provenance(
        manifest_sha256, artifact, binding_path, qualification_path
    ).provenance
    model_binding = provenance["programModel"]
    try:
        model = load_program_model(
            program_model_path,
            twin=TWIN,
            artifact=artifact,
            model_image_base=artifact.elf_image_base,
            expected_sha256=model_binding["sha256"],
        )
    except ScoringError as error:
        raise CoverageError(f"program model rejected: {error}") from error
    _require_equal(
        len(model.functions),
        model_binding["functionCount"],
        "program model function count disagrees with the binding",
    )
    return BoundStrippedModel(
        oracle=oracle,
        model=model,
        provenance=provenance,
    )
