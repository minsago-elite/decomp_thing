#!/usr/bin/env python3
"""Verify a Docker inspect response against the GCC reproduction lock."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.gcc.toolchain_reproduction import verify_toolchain_reproduction  # noqa: E402
from oracle.gcc.verify_source_lock import VerificationError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Authenticate a deterministic GCC toolchain image reproduction."
    )
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--build-record", required=True, type=Path)
    parser.add_argument(
        "--inspect-json",
        type=Path,
        help="Docker image inspect JSON; stdin is used when omitted",
    )
    arguments = parser.parse_args()
    try:
        if arguments.inspect_json is None:
            inspected = json.load(sys.stdin)
        else:
            inspected = json.loads(arguments.inspect_json.read_text(encoding="utf-8"))
        lock = verify_toolchain_reproduction(
            arguments.lock,
            arguments.build_record,
            inspected,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, VerificationError) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    print(
        "verified reproduced GCC toolchain image: "
        f"{lock['reproducedImage']['imageDigest']} "
        f"(recorded artifact origin {lock['recordedOrigin']['imageDigest']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
