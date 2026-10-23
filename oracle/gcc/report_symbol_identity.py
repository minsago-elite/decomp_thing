#!/usr/bin/env python3
"""Measure GCC surviving-symbol identity against a bound recovered model.

The population is enumerated from the authenticated function oracle: every
alias whose stripped availability is ``surviving``.  Each alias is looked up at
its oracle RVA in a recovered stripped-twin program model whose bytes are bound
by a structural full-export binding and qualification record to the same
artifact manifest and stripped input.  The report records per-symbol outcomes;
it does not admit the model for release scoring.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.function_recovery import (  # noqa: E402
    ScoringError,
    load_function_oracle,
    load_program_model,
)
from oracle.gcc.report_accuracy_coverage import (  # noqa: E402
    CoverageError,
    _json,
    _required_mapping,
    _sha256,
    _write_json,
)


REPORT_ID = "gcc-driver-surviving-symbol-identity-v1"
TWIN = "stripped"


def enumerate_population(oracle_path: Path) -> list[dict[str, Any]]:
    """Return the sorted surviving stripped alias population of the oracle."""

    oracle = load_function_oracle(oracle_path)
    population = []
    for function in oracle.functions:
        for alias in function.aliases:
            if alias.availability[TWIN] != "surviving":
                continue
            if function.rva is None:
                raise CoverageError(
                    f"surviving alias {alias.name} has no oracle RVA"
                )
            population.append(
                {
                    "oracleId": function.identifier,
                    "name": alias.name,
                    "rva": function.rva,
                    "excluded": function.exclusion is not None,
                }
            )
    population.sort(key=lambda item: (item["rva"], item["name"]))
    return population


def _require_equal(actual: Any, expected: Any, message: str) -> None:
    if actual != expected:
        raise CoverageError(message)


def build_report(
    profile_directory: Path,
    program_model_path: Path,
    binding_path: Path,
    qualification_path: Path,
    *,
    run_id: int,
    artifact_id: int,
) -> dict[str, Any]:
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

    recovered_by_rva = {function.rva: function for function in model.functions}
    outcomes = []
    for member in enumerate_population(oracle_path):
        recovered = recovered_by_rva.get(member["rva"])
        if recovered is None:
            outcome = "missing"
        elif recovered.name != member["name"]:
            outcome = "name-mismatch"
        else:
            outcome = "exact"
        outcomes.append(
            {
                "oracleId": member["oracleId"],
                "name": member["name"],
                "rva": hex(member["rva"]),
                "oracleExcluded": member["excluded"],
                "outcome": outcome,
                "recoveredName": None if recovered is None else recovered.name,
                "recoveredStatus": None if recovered is None else recovered.status,
            }
        )
    counts = {
        kind: sum(item["outcome"] == kind for item in outcomes)
        for kind in ("exact", "name-mismatch", "missing")
    }
    exact = counts["exact"]
    total = len(outcomes)
    return {
        "schemaVersion": 1,
        "reportId": REPORT_ID,
        "twin": TWIN,
        "populationDefinition": (
            "aliases whose stripped availability is surviving in the "
            "authenticated function oracle, looked up at the oracle RVA"
        ),
        "provenance": {
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
        },
        "summary": {
            "population": total,
            **counts,
            "identityRecovery": {
                "numerator": exact,
                "denominator": total,
                "value": None if total == 0 else round(exact / total, 6),
            },
        },
        "productionVerified": False,
        "symbols": outcomes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure GCC surviving-symbol identity in a bound recovered model."
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=REPOSITORY_ROOT / "oracle/gcc/16.2.0",
    )
    parser.add_argument("--program-model", type=Path, required=True)
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report = build_report(
            arguments.profile,
            arguments.program_model,
            arguments.binding,
            arguments.qualification,
            run_id=arguments.run_id,
            artifact_id=arguments.artifact_id,
        )
        _write_json(arguments.output, report)
    except CoverageError as error:
        print(f"symbol identity report failed: {error}", file=sys.stderr)
        return 1
    summary = report["summary"]
    print(
        f"surviving symbol identity: {summary['exact']}/{summary['population']} exact "
        f"({summary['name-mismatch']} name mismatch, {summary['missing']} missing)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
