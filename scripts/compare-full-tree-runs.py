#!/usr/bin/env python3
"""Create a canonical byte-determinism report for two bounded shard runs."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(REPOSITORY_ROOT))
from oracle.full_tree_determinism import FullTreeDeterminismError, compare_full_tree_runs  # noqa: E402
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--first", type=Path, required=True); parser.add_argument("--second", type=Path, required=True); parser.add_argument("--output", type=Path, required=True); arguments = parser.parse_args()
    try: report = compare_full_tree_runs(arguments.first, arguments.second); arguments.output.write_bytes(canonical_json_bytes(report))
    except (FullTreeDeterminismError, OSError, json.JSONDecodeError) as error: print(f"full-tree determinism comparison failed: {error}", file=sys.stderr); return 1
    print(json.dumps({"identical": report["identical"], "shards": report["shards"]}, sort_keys=True, separators=(",", ":"))); return 0
if __name__ == "__main__": raise SystemExit(main())
