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

from oracle.function_recovery import (  # noqa: E402
    _TWIN_NAMES,
    ScoringError,
    _preflight_report_projection,
    _score_twin,
)
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
) -> dict[str, Any]:
    bound = load_bound_stripped_model(
        profile_directory,
        program_model_path,
        binding_path,
        qualification_path,
    )
    try:
        # Charging the bound model against every twin slot overestimates the
        # single-twin report, so the scorer's output limit still holds.
        report_projection = _preflight_report_projection(
            bound.oracle, {twin: bound.model for twin in _TWIN_NAMES}
        )
        scored = _score_twin(
            bound.oracle,
            bound.model,
            twin=TWIN,
            report_projection=report_projection,
        )
    except ScoringError as error:
        raise CoverageError(f"function start scoring failed: {error}") from error
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
        # Exact matches pair equal RVAs, so the oracle RVA identifies both sides.
        "exactMatchRvas": sorted(
            (match["oracleRva"] for match in scored["exactMatches"]),
            key=lambda rva: int(rva, 16),
        ),
        "nearMisses": scored["nearMisses"],
        "falsePositives": scored["falsePositives"],
        "falseNegatives": scored["falseNegatives"],
        "ignoredExcludedRecoveries": scored["ignoredExcludedRecoveries"],
    }


def build_parser() -> argparse.ArgumentParser:
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
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    try:
        report = build_report(
            arguments.profile,
            arguments.program_model,
            arguments.binding,
            arguments.qualification,
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
