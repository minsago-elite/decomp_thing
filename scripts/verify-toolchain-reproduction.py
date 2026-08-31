#!/usr/bin/env python3
"""Legacy Python compatibility verifier; not Kotlin/JVM oracle or release authority."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.source_lock import VerificationError  # noqa: E402
from oracle.toolchain_reproduction import verify_reproduction_recipe  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
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
        if isinstance(inspected, list):
            if len(inspected) != 1:
                raise VerificationError("Docker inspect response must contain exactly one image")
            inspected = inspected[0]
        if not isinstance(inspected, dict):
            raise VerificationError("Docker inspect response must be an object")
        image_digest = inspected.get("Id")
        if inspected.get("Architecture") != "amd64" or inspected.get("Os") != "linux":
            raise VerificationError("reproduced image platform is not linux/amd64")
        lock = verify_reproduction_recipe(
            arguments.lock,
            arguments.build_record,
            running_image_digest=image_digest,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, VerificationError) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    print(
        "verified stable toolchain recipe for rebuilt image "
        f"{image_digest} (recorded artifact origin "
        f"{lock['recordedOrigin']['imageDigest']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
