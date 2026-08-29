"""Build and validate persistent Clang diagnostic fidelity identities."""

from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any
from oracle.behavior_corpus import corpus_json_bytes, validate_corpus
from oracle.full_tree_scope import canonical_json_bytes


class ClangDiagnosticMatrixError(ValueError):
    """Raised when diagnostic expectations drift from the reviewed corpus."""


OWNER_BY_CASE = {
    "assemble-invalid": "clang-integrated-assembler", "diagnostic-color-always": "clang-diagnostics-renderer",
    "diagnostic-color-never": "clang-diagnostics-renderer", "diagnostic-error-limit": "clang-diagnostics-engine",
    "diagnostic-fixit": "clang-parser", "diagnostic-invalid-option": "clang-driver-options",
    "diagnostic-missing-include": "clang-lex", "diagnostic-syntax": "clang-parser",
    "diagnostic-template-backtrace": "clang-sema", "diagnostic-warning-option": "clang-sema",
    "driver-missing-linker": "clang-driver-toolchain", "link-undefined-symbol": "clang-driver-linker",
    "pch-reuse-wrong-target": "clang-serialization",
    "preprocess-malformed-macro": "clang-lex",
    "response-file-recursion": "clang-driver-response-files", "target-unsupported-aarch64": "clang-driver-targets",
}


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _mismatch(case_id: str, field: str) -> str:
    return "clang-diagnostic-" + _sha(f"{case_id}:{field}".encode())[:32]


def generate_clang_diagnostic_matrix(corpus: dict[str, Any]) -> dict[str, Any]:
    validated = validate_corpus(corpus)
    diagnostic_cases = [item for item in validated["cases"] if "diagnostics" in item["categories"]]
    ids = {item["id"] for item in diagnostic_cases}
    if ids != OWNER_BY_CASE.keys():
        missing = sorted(ids.symmetric_difference(OWNER_BY_CASE))
        raise ClangDiagnosticMatrixError("diagnostic ownership map differs: " + ", ".join(missing))
    cases = []
    for item in diagnostic_cases:
        cases.append({
            "categories": item["categories"], "exitCode": item["expected"]["exitCode"], "id": item["id"],
            "mismatchIds": {field: _mismatch(item["id"], field) for field in ("exitCode", "order", "stderr", "stdout")},
            "normalizations": {field: item["expected"][field]["normalizations"] for field in ("stderr", "stdout")},
            "ownerSubsystem": OWNER_BY_CASE[item["id"]], "stderrSha256": item["expected"]["stderr"]["sha256"],
            "stdoutSha256": item["expected"]["stdout"]["sha256"],
        })
    without_hash = {
        "cases": cases, "corpusSha256": _sha(corpus_json_bytes(validated)), "id": "clang-22.1.6-diagnostics-v1",
        "policy": {"forbiddenNormalizations": ["diagnostic-wording", "identifier", "line-column", "option-name", "ordering", "severity"], "locale": "C", "pathNormalization": "only exact authenticated workspace/oracle roots", "terminalWidth": "non-tty-no-width"},
        "schemaVersion": 1,
    }
    result = {**without_hash, "matrixSha256": _sha(canonical_json_bytes(without_hash))}
    validate_clang_diagnostic_matrix(result, validated)
    return result


def validate_clang_diagnostic_matrix(matrix: dict[str, Any], corpus: dict[str, Any]) -> None:
    validated = validate_corpus(corpus)
    try:
        import fastjsonschema  # type: ignore[import-untyped]
        schema = json.loads(Path(__file__).with_name("clang-diagnostic-matrix.schema.json").read_text(encoding="utf-8"))
        fastjsonschema.compile(schema)(matrix)
    except Exception as error:
        raise ClangDiagnosticMatrixError(f"diagnostic matrix fails schema validation: {error}") from error
    without_hash = {key: value for key, value in matrix.items() if key != "matrixSha256"}
    if matrix["matrixSha256"] != _sha(canonical_json_bytes(without_hash)) or matrix["corpusSha256"] != _sha(corpus_json_bytes(validated)):
        raise ClangDiagnosticMatrixError("diagnostic matrix hash binding differs")
    if matrix["id"] != "clang-22.1.6-diagnostics-v1":
        raise ClangDiagnosticMatrixError("diagnostic matrix id differs")
    corpus_cases = {item["id"]: item for item in validated["cases"]}
    if [item["id"] for item in matrix["cases"]] != sorted(OWNER_BY_CASE):
        raise ClangDiagnosticMatrixError("diagnostic matrix case membership or order differs")
    for item in matrix["cases"]:
        case = corpus_cases[item["id"]]
        if item["ownerSubsystem"] != OWNER_BY_CASE[item["id"]] or item["stderrSha256"] != case["expected"]["stderr"]["sha256"] or item["stdoutSha256"] != case["expected"]["stdout"]["sha256"] or item["exitCode"] != case["expected"]["exitCode"]:
            raise ClangDiagnosticMatrixError(f"diagnostic case {item['id']} differs from corpus")
        if item["mismatchIds"] != {field: _mismatch(item["id"], field) for field in ("exitCode", "order", "stderr", "stdout")}:
            raise ClangDiagnosticMatrixError(f"diagnostic case {item['id']} mismatch identities differ")
