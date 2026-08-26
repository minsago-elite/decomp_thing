#!/usr/bin/env python3
"""Create a GCC oracle manifest after verifying a full/stripped ELF pair."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.gcc.verify_oracle_artifacts import create_oracle_manifest  # noqa: E402
from oracle.gcc.verify_source_lock import VerificationError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Derive and write a strict manifest for a DWARF-rich GCC driver and "
            "its stripped, code-identical twin."
        )
    )
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--build-record", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()

    try:
        manifest = create_oracle_manifest(
            arguments.output,
            arguments.source_lock,
            arguments.build_record,
        )
    except VerificationError as error:
        print(f"manifest creation failed: {error}", file=sys.stderr)
        return 1

    full = manifest["artifacts"]["full"]
    stripped = manifest["artifacts"]["stripped"]
    equivalence = manifest["equivalence"]
    print(f"wrote verified GCC oracle manifest: {arguments.output.resolve()}")
    print(f"  full SHA-256:     {full['sha256']}")
    print(f"  stripped SHA-256: {stripped['sha256']}")
    print(f"  GNU Build ID:     {equivalence['buildId']}")
    print(f"  executable bytes: {equivalence['executableLoad']['bytes']}")
    print(f"  executable hash:  {equivalence['executableLoad']['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
