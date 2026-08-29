#!/usr/bin/env python3
"""Generate resumable bounded DWARF call observations for the full LLVM tree."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.bounded_shards import BoundedShardError  # noqa: E402
from oracle.full_tree_call_observations import (  # noqa: E402
    FullTreeCallObservationError,
    run_full_tree_call_observations,
)
from oracle.full_tree_scope import load_full_tree_scope  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-scope.json")
    parser.add_argument("--inventory", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-inventory.json")
    parser.add_argument("--rich-artifact", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    arguments = parser.parse_args()
    try:
        scope = load_full_tree_scope(arguments.scope)
        inventory = json.loads(arguments.inventory.read_text(encoding="utf-8"))
        index = run_full_tree_call_observations(
            arguments.rich_artifact,
            scope=scope,
            scope_sha256=hashlib.sha256(arguments.scope.read_bytes()).hexdigest(),
            inventory=inventory,
            output_root=arguments.output_root,
            maximum_workers=arguments.workers,
        )
    except (BoundedShardError, FullTreeCallObservationError, OSError, json.JSONDecodeError) as error:
        print(f"full-tree call observation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(index["counts"], sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
