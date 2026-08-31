#!/usr/bin/env python3
"""Legacy non-authoritative Python compatibility generator for an LLVM ELF manifest.

The generated document is migration/test material only.  It cannot validate, certify,
or enter a new Kotlin-only release; the Kotlin/JVM verifier is the release authority.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.elf_oracle import create_oracle_manifest  # noqa: E402
from oracle.source_lock import VerificationError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__
    )
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--build-record", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--artifact-root",
        type=Path,
        help="root containing the build-record artifacts/ paths",
    )
    arguments = parser.parse_args()
    try:
        manifest = create_oracle_manifest(
            arguments.output,
            arguments.source_lock,
            arguments.build_record,
            artifact_root=arguments.artifact_root,
        )
    except VerificationError as error:
        print(f"manifest creation failed: {error}", file=sys.stderr)
        return 1
    print(f"wrote non-authoritative LLVM oracle manifest candidate: {arguments.output.resolve()}")
    print(f"  full SHA-256:     {manifest['artifacts']['full']['sha256']}")
    print(f"  stripped SHA-256: {manifest['artifacts']['stripped']['sha256']}")
    print(f"  GNU Build ID:     {manifest['equivalence']['buildId']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
