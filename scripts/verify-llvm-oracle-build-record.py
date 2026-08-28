#!/usr/bin/env python3
"""Verify an LLVM oracle build record inside its pinned container."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.elf_oracle import verify_build_environment  # noqa: E402
from oracle.source_lock import VerificationError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--build-record", required=True, type=Path)
    parser.add_argument("--container-digest", required=True)
    arguments = parser.parse_args()
    try:
        record = verify_build_environment(
            arguments.build_record,
            arguments.source_lock,
            arguments.container_digest,
        )
    except VerificationError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    print(
        "verified LLVM oracle build environment: "
        f"{record['environment']['container']['image']}@"
        f"{record['environment']['container']['digest']}"
    )
    for tool in record["tools"]:
        print(f"  {tool['role']}: {tool['versionOutput'].splitlines()[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
