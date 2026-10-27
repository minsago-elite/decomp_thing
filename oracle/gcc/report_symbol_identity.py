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
    MAX_REPORT_BYTES,
    FunctionOracle,
    ScoringError,
    _json_string_encoded_size,
    report_json_bytes,
)
from oracle.gcc.bound_recovered_model import (  # noqa: E402
    TWIN,
    load_bound_stripped_model,
)
from oracle.gcc.report_accuracy_coverage import (  # noqa: E402
    CoverageError,
    _write_payload,
)


REPORT_ID = "gcc-driver-surviving-symbol-identity-v1"
# Upper bounds on the indented JSON bytes of the fixed report envelope and of
# one symbol record excluding its variable-length strings.
_REPORT_ENVELOPE_BYTES = 64 * 1024
_SYMBOL_RECORD_BYTES = 384


def _charge(projection: list[int], size: int) -> None:
    projection[0] += size
    if projection[0] > MAX_REPORT_BYTES:
        raise CoverageError(
            f"projected symbol identity report exceeds the {MAX_REPORT_BYTES}-byte "
            "output limit"
        )


def enumerate_population(
    oracle: FunctionOracle, projection: list[int] | None = None
) -> list[dict[str, Any]]:
    """Return the sorted surviving stripped alias population of the oracle.

    Each member is charged against ``projection`` before it is materialized,
    so an oversized population is rejected without building the full list.
    """

    if projection is None:
        projection = [_REPORT_ENVELOPE_BYTES]
    population = []
    for function in oracle.functions:
        for alias in function.aliases:
            if alias.availability[TWIN] != "surviving":
                continue
            if function.rva is None:
                raise CoverageError(
                    f"surviving alias {alias.name} has no oracle RVA"
                )
            _charge(
                projection,
                _SYMBOL_RECORD_BYTES
                + _json_string_encoded_size(function.identifier)
                + _json_string_encoded_size(alias.name),
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
    recovered_by_rva = {function.rva: function for function in bound.model.functions}
    projection = [_REPORT_ENVELOPE_BYTES]
    outcomes = []
    for member in enumerate_population(bound.oracle, projection):
        recovered = recovered_by_rva.get(member["rva"])
        if recovered is not None:
            _charge(
                projection,
                _json_string_encoded_size(recovered.name)
                + _json_string_encoded_size(recovered.status),
            )
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
        "provenance": bound.provenance,
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


def build_parser() -> argparse.ArgumentParser:
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
        try:
            payload = report_json_bytes(report)
        except ScoringError as error:
            raise CoverageError(str(error)) from error
        _write_payload(arguments.output, payload)
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
