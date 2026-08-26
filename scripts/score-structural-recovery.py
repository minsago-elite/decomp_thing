#!/usr/bin/env python3
"""Emit a deterministic fixture structural-recovery report."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.structural_recovery import (  # noqa: E402
    StructuralScoringError,
    load_boundary_mapping,
    load_fixture_identity_map,
    load_fixture_recovered_structure,
    load_structural_oracle,
    load_target_abi_descriptor,
    render_summary,
    score_fixture_structural_recovery,
    write_report_atomic,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "score digest-bound fixture structural evidence; production evidence "
            "requires a benchmark adapter which replays the exporter and loader"
        )
    )
    parser.add_argument("--target-abi", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--boundary-score", type=Path, required=True)
    parser.add_argument("--boundary-twin", choices=("rich", "stripped"), required=True)
    parser.add_argument("--identity-map", type=Path, required=True)
    parser.add_argument("--recovered-model", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        target = load_target_abi_descriptor(arguments.target_abi)
        oracle = load_structural_oracle(arguments.oracle, target)
        boundary = load_boundary_mapping(
            arguments.boundary_score,
            twin=arguments.boundary_twin,
            target=target,
        )
        identity_map = load_fixture_identity_map(
            arguments.identity_map,
            oracle=oracle,
        )
        recovered = load_fixture_recovered_structure(
            arguments.recovered_model,
            target=target,
            oracle=oracle,
            boundary=boundary,
            identity_map=identity_map,
        )
        report = score_fixture_structural_recovery(
            oracle,
            recovered,
            boundary,
            identity_map,
            target,
        )
        write_report_atomic(arguments.json_output, report, target=target)
    except (OSError, StructuralScoringError) as error:
        print(f"structural scoring failed: {error}", file=sys.stderr)
        return 2
    print(render_summary(report))
    print(f"JSON report: {arguments.json_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
