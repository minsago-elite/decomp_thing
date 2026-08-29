#!/usr/bin/env python3
"""Generate the canonical per-shard LLVM call observability baseline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.full_tree_call_baseline import (  # noqa: E402
    FullTreeCallBaselineError,
    generate_full_tree_call_baseline,
)
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402


def main() -> int:
    profile = REPOSITORY_ROOT / "oracle/llvm/22.1.6"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--truth-root", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, default=profile / "full-tree-inventory.json")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        inventory = json.loads(arguments.inventory.read_text(encoding="utf-8"))
        truth_index = json.loads((arguments.truth_root / "index.json").read_text(encoding="utf-8"))
        report = generate_full_tree_call_baseline(
            truth_index,
            truth_root=arguments.truth_root,
            inventory=inventory,
        )
        arguments.output.write_bytes(canonical_json_bytes(report))
    except (FullTreeCallBaselineError, OSError, json.JSONDecodeError) as error:
        print(f"full-tree call baseline failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report["aggregate"], sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
