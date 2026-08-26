#!/usr/bin/env python3
"""Generate the GCC benchmark's oracle through the generic ELF normalizer."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.function_recovery_oracle import OracleGenerationError  # noqa: E402
from oracle.gcc.generate_function_recovery_oracle import (  # noqa: E402
    generate_gcc_profile_oracle,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Authenticate the GCC benchmark artifact manifest, then normalize "
            "its ELF/DWARF twins with the program-agnostic oracle generator."
        )
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--exclusions", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--schema",
        type=Path,
        default=REPOSITORY_ROOT / "oracle/function-recovery-oracle.schema.json",
    )
    parser.add_argument(
        "--rich-artifact",
        type=Path,
        help="optional exact rich artifact mirror; its manifest hash is enforced",
    )
    parser.add_argument(
        "--stripped-artifact",
        type=Path,
        help="optional exact stripped artifact mirror; its manifest hash is enforced",
    )
    parser.add_argument("--near-miss-bytes", type=int, default=16)
    arguments = parser.parse_args()

    inputs = {
        arguments.manifest.resolve(strict=False),
        arguments.exclusions.resolve(strict=False),
        arguments.schema.resolve(strict=False),
    }
    if arguments.rich_artifact is not None:
        inputs.add(arguments.rich_artifact.resolve(strict=False))
    if arguments.stripped_artifact is not None:
        inputs.add(arguments.stripped_artifact.resolve(strict=False))
    if arguments.output.resolve(strict=False) in inputs:
        print("generation failed: output must not replace an input", file=sys.stderr)
        return 1
    try:
        document = generate_gcc_profile_oracle(
            manifest_path=arguments.manifest,
            exclusions_path=arguments.exclusions,
            output_path=arguments.output,
            schema_path=arguments.schema,
            rich_artifact_path=arguments.rich_artifact,
            stripped_artifact_path=arguments.stripped_artifact,
            near_miss_bytes=arguments.near_miss_bytes,
        )
    except OracleGenerationError as error:
        print(f"generation failed: {error}", file=sys.stderr)
        return 1

    functions = document["functions"]
    compiler_generated = sum(
        item["exclusion"] is not None
        and item["exclusion"]["kind"] == "compiler-generated"
        for item in functions
    )
    inline_only = sum(
        item["exclusion"] is not None and item["exclusion"]["kind"] == "inlined"
        for item in functions
    )
    print(f"generated {arguments.output}")
    print(f"  scoreable functions: {len(functions) - compiler_generated - inline_only}")
    print(f"  compiler-generated exclusions: {compiler_generated}")
    print(f"  inline-only exclusions: {inline_only}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
