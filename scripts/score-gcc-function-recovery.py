#!/usr/bin/env python3
"""GCC benchmark adapter for the program-agnostic function recovery scorer."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.gcc.score_function_recovery import (  # noqa: E402
    ScoringError,
    render_human_report,
    score_files,
    write_report,
)


def address(value: str) -> int:
    try:
        parsed = int(value, 16)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "must be a canonical lowercase hexadecimal address"
        ) from error
    if parsed < 0 or parsed >= 1 << 64 or hex(parsed) != value:
        raise argparse.ArgumentTypeError(
            "must be a canonical lowercase hexadecimal unsigned 64-bit address"
        )
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare both recovered program-model twins with a normalized "
            "DWARF/symbol function oracle. A concise report is printed and the "
            "complete deterministic report is written as JSON."
        )
    )
    parser.add_argument("--oracle", required=True, type=Path)
    parser.add_argument(
        "--artifact-manifest",
        type=Path,
        help="required for a production-scope oracle and forbidden for fixtures",
    )
    parser.add_argument("--rich-model", required=True, type=Path)
    parser.add_argument(
        "--rich-model-image-base",
        required=True,
        type=address,
        help="explicit image base used by addresses in the rich program model",
    )
    parser.add_argument("--stripped-model", required=True, type=Path)
    parser.add_argument(
        "--stripped-model-image-base",
        required=True,
        type=address,
        help="explicit image base used by addresses in the stripped program model",
    )
    parser.add_argument("--json-output", required=True, type=Path)
    arguments = parser.parse_args()

    inputs = {
        arguments.oracle.resolve(strict=False),
        arguments.rich_model.resolve(strict=False),
        arguments.stripped_model.resolve(strict=False),
    }
    if arguments.artifact_manifest is not None:
        inputs.add(arguments.artifact_manifest.resolve(strict=False))
    if arguments.json_output.resolve(strict=False) in inputs:
        print("scoring failed: JSON output must not replace an input", file=sys.stderr)
        return 1

    try:
        report = score_files(
            arguments.oracle,
            arguments.rich_model,
            arguments.stripped_model,
            rich_model_image_base=arguments.rich_model_image_base,
            stripped_model_image_base=arguments.stripped_model_image_base,
            artifact_manifest_path=arguments.artifact_manifest,
        )
        write_report(arguments.json_output, report)
    except ScoringError as error:
        print(f"scoring failed: {error}", file=sys.stderr)
        return 1

    print(render_human_report(report), end="")
    print(f"JSON report: {arguments.json_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
