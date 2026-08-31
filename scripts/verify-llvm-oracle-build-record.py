#!/usr/bin/env python3
"""Legacy non-authoritative Python compatibility build-record verifier.

Required LLVM workflows use the descriptor-pinned Kotlin/JVM verifier. This wrapper cannot
validate, score, or certify a Kotlin-only oracle release.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.elf_oracle import verify_build_environment  # noqa: E402
from oracle.source_lock import VerificationError  # noqa: E402
from oracle.toolchain_reproduction import verify_reproduction_recipe  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--build-record", required=True, type=Path)
    parser.add_argument("--reproduction-lock", required=True, type=Path)
    parser.add_argument("--container-digest", required=True)
    arguments = parser.parse_args()
    try:
        reproduction = verify_reproduction_recipe(
            arguments.reproduction_lock,
            arguments.build_record,
            running_image_digest=arguments.container_digest,
        )
        record = verify_build_environment(
            arguments.build_record,
            arguments.source_lock,
            reproduction["recordedOrigin"]["imageDigest"],
        )
    except VerificationError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    print(
        "verified LLVM oracle build environment: "
        f"{record['environment']['container']['image']}@"
        f"{record['environment']['container']['digest']} "
        f"(running rebuild {arguments.container_digest})"
    )
    for tool in record["tools"]:
        print(f"  {tool['role']}: {tool['versionOutput'].splitlines()[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
