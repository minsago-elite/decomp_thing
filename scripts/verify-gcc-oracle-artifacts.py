#!/usr/bin/env python3
"""Recompute and verify every GCC oracle artifact-manifest field."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.gcc.verify_oracle_artifacts import verify_oracle_manifest  # noqa: E402
from oracle.gcc.verify_source_lock import VerificationError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Strictly verify a source-bound GCC build record, both ELF artifacts, "
            "and their code/metadata relationship."
        )
    )
    parser.add_argument("manifest", type=Path)
    arguments = parser.parse_args()

    try:
        manifest = verify_oracle_manifest(arguments.manifest)
    except VerificationError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1

    equivalence = manifest["equivalence"]
    print(
        "verified GCC oracle pair: "
        f"{manifest['oracle']['version']} / {manifest['oracle']['sourceRevision']}"
    )
    print(f"  GNU Build ID:     {equivalence['buildId']}")
    print(f"  executable bytes: {equivalence['executableLoad']['bytes']}")
    print(f"  executable hash:  {equivalence['executableLoad']['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
