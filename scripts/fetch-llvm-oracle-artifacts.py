#!/usr/bin/env python3
"""Fetch the Clang oracle twins from their hash-locked release."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.release_artifacts import materialize_release_artifacts  # noqa: E402
from oracle.source_lock import VerificationError  # noqa: E402


DEFAULT_LOCK = REPOSITORY_ROOT / "oracle/llvm/22.1.6/release-artifacts.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_root", type=Path)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    arguments = parser.parse_args()
    try:
        artifacts = materialize_release_artifacts(
            arguments.lock,
            arguments.output_root,
        )
    except VerificationError as error:
        print(f"fetch failed: {error}", file=sys.stderr)
        return 1
    for role in ("full", "stripped"):
        print(f"verified {role} release artifact: {artifacts[role]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
