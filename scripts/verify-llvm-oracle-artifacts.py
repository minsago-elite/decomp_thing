#!/usr/bin/env python3
"""Verify the checked LLVM source-aligned ELF oracle manifest and artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.elf_oracle import verify_oracle_manifest  # noqa: E402
from oracle.source_lock import VerificationError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    arguments = parser.parse_args()
    try:
        manifest = verify_oracle_manifest(arguments.manifest)
    except VerificationError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    print(
        "verified LLVM oracle pair: "
        f"{manifest['oracle']['id']} ({manifest['equivalence']['buildId']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

