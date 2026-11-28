#!/usr/bin/env python3
"""Verify an explicitly selected retained GCC function replay checkpoint offline."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from oracle.gcc.verify_production_function_replay_evidence import EvidenceError, verify


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="explicit repository evidence manifest path")
    arguments = parser.parse_args()
    try:
        result = verify(arguments.manifest)
    except EvidenceError as error:
        print(f"retained evidence rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
