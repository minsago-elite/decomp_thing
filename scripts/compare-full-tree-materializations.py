#!/usr/bin/env python3
"""Create a canonical byte-determinism report for two full-tree truth roots."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.full_tree_materialization_determinism import (  # noqa: E402
    FullTreeMaterializationDeterminismError,
    compare_full_tree_materializations,
)
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report = compare_full_tree_materializations(arguments.first, arguments.second)
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_bytes(canonical_json_bytes(report))
    except (FullTreeMaterializationDeterminismError, OSError, json.JSONDecodeError) as error:
        print(f"full-tree materialization comparison failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"files": report["files"], "identical": report["identical"]}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
