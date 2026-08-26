#!/usr/bin/env python3
"""Validate the GCC oracle source lock, optionally including downloaded bytes."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.gcc.verify_source_lock import (  # noqa: E402
    VerificationError,
    load_and_validate_lock,
    verify_source_release,
)


DEFAULT_LOCK = REPOSITORY_ROOT / "oracle/gcc/16.2.0/source-lock.json"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Strictly verify the pinned GCC source provenance lock."
    )
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument(
        "--metadata-only",
        action="store_true",
        help="validate only the lock schema and vendored signing-key identity",
    )
    parser.add_argument("--archive", type=Path, help="downloaded GCC .tar.xz")
    parser.add_argument("--signature", type=Path, help="downloaded detached .sig")
    arguments = parser.parse_args()

    try:
        if arguments.metadata_only:
            if arguments.archive is not None or arguments.signature is not None:
                parser.error("--metadata-only cannot be combined with artifact paths")
            data = load_and_validate_lock(arguments.lock)
            print(
                "verified GCC source-lock metadata: "
                f"{data['oracle']['version']} / {data['revision']['commit']}"
            )
            return 0
        if arguments.archive is None or arguments.signature is None:
            parser.error("full verification requires both --archive and --signature")
        data = verify_source_release(arguments.lock, arguments.archive, arguments.signature)
        print(
            "verified GCC source release: "
            f"{data['source']['archive']['sha256']} signed by "
            f"{data['signing']['signingFingerprint']}"
        )
        return 0
    except VerificationError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
