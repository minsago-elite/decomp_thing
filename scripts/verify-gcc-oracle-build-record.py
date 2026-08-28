#!/usr/bin/env python3
"""Verify a GCC oracle build record against the running pinned container."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.gcc.verify_oracle_artifacts import verify_build_environment  # noqa: E402
from oracle.gcc.toolchain_reproduction import approved_origin_digest  # noqa: E402
from oracle.gcc.verify_source_lock import VerificationError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the source binding, immutable container digest, platform, "
            "tool executable hashes, and exact compiler/linker/stripper versions "
            "recorded for a GCC oracle build."
        )
    )
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--build-record", required=True, type=Path)
    parser.add_argument(
        "--container-digest",
        required=True,
        help="sha256:<hex> digest of the image used to launch this environment",
    )
    parser.add_argument(
        "--reproduction-lock",
        type=Path,
        help=(
            "approved reproduction lock mapping the running image to the "
            "historical artifact-origin image"
        ),
    )
    arguments = parser.parse_args()

    try:
        artifact_origin_digest = arguments.container_digest
        if arguments.reproduction_lock is not None:
            artifact_origin_digest = approved_origin_digest(
                arguments.reproduction_lock,
                arguments.container_digest,
            )
        record = verify_build_environment(
            arguments.build_record,
            arguments.source_lock,
            artifact_origin_digest,
        )
    except VerificationError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1

    print(
        "verified GCC oracle build environment: "
        f"{record['environment']['container']['image']}@"
        f"{record['environment']['container']['digest']} "
        f"(running {arguments.container_digest})"
    )
    for tool in record["tools"]:
        first_line = tool["versionOutput"].splitlines()[0]
        print(f"  {tool['role']}: {first_line} [{tool['executableSha256']}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
