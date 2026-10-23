#!/usr/bin/env python3
"""Score GCC stripped-twin function starts against a bound recovered model.

Boundaries are scored with the function-recovery scorer: oracle functions
without an exclusion form the reference population, recovered functions at
excluded oracle RVAs are ignored, exact matches are paired by RVA, and the
remainder is paired by minimum-cost near-match assignment.  The recovered
model must be bound to the authenticated oracle through its structural
full-export binding and qualification record.  The report retains every false
positive, false negative and ignored recovery; it does not admit the model for
release scoring.
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import sys
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.function_recovery import _score_twin  # noqa: E402
from oracle.gcc.bound_recovered_model import (  # noqa: E402
    TWIN,
    load_bound_stripped_model,
)
from oracle.gcc.report_accuracy_coverage import (  # noqa: E402
    CoverageError,
    _write_json,
)


REPORT_ID = "gcc-driver-function-start-score-v1"
SUMMARY_FIELDS = (
    "referenceCount",
    "rawRecoveredCount",
    "scoredRecoveredCount",
    "ignoredExcludedCount",
    "exactMatches",
    "nearMisses",
    "truePositives",
    "falsePositives",
    "falseNegatives",
    "precision",
    "recall",
    "f1",
)


def build_report(
    profile_directory: Path,
    program_model_path: Path,
    binding_path: Path,
    qualification_path: Path,
    *,
    run_id: int,
    artifact_id: int,
) -> dict[str, Any]:
    bound = load_bound_stripped_model(
        profile_directory,
        program_model_path,
        binding_path,
        qualification_path,
        run_id=run_id,
        artifact_id=artifact_id,
    )
    scored = _score_twin(
        bound.oracle, bound.model, twin=TWIN, report_projection=[0] * 8
    )
    boundaries = scored["boundaries"]
    exclusions = Counter(
        function.exclusion.kind
        for function in bound.oracle.functions
        if function.exclusion is not None
    )
    return {
        "schemaVersion": 1,
        "reportId": REPORT_ID,
        "twin": TWIN,
        "populationDefinition": (
            "authenticated function oracle entries without an exclusion; "
            "recovered functions at excluded oracle RVAs are ignored"
        ),
        "provenance": bound.provenance,
        "oracle": {
            "functionCount": len(bound.oracle.functions),
            "exclusions": dict(sorted(exclusions.items())),
        },
        "summary": {field: boundaries[field] for field in SUMMARY_FIELDS},
        "productionVerified": False,
        "nearMisses": scored["nearMisses"],
        "falsePositives": scored["falsePositives"],
        "falseNegatives": scored["falseNegatives"],
        "ignoredExcludedRecoveries": scored["ignoredExcludedRecoveries"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Score GCC stripped function starts in a bound recovered model."
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
        print(f"function start report failed: {error}", file=sys.stderr)
        return 1
    summary = report["summary"]
    precision = summary["precision"]
    recall = summary["recall"]
    print(
        f"function starts: precision {precision['numerator']}/{precision['denominator']}, "
        f"recall {recall['numerator']}/{recall['denominator']} "
        f"({summary['nearMisses']} near miss, {summary['falsePositives']} false positive, "
        f"{summary['falseNegatives']} false negative)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
