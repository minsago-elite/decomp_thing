#!/usr/bin/env python3
"""Generate or resume bounded DWARF function observations for every LLVM shard."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.bounded_shards import BoundedShardError  # noqa: E402
from oracle.full_tree_function_observations import (  # noqa: E402
    FullTreeFunctionObservationError,
    run_full_tree_function_observations,
)
from oracle.full_tree_inventory import FullTreeInventoryError, validate_inventory  # noqa: E402
from oracle.full_tree_scope import FullTreeScopeError, load_full_tree_scope  # noqa: E402


PROFILE = REPOSITORY_ROOT / "oracle/llvm/22.1.6"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, default=PROFILE / "full-tree-scope.json")
    parser.add_argument("--inventory", type=Path, default=PROFILE / "full-tree-inventory.json")
    parser.add_argument("--source-lock", type=Path, default=PROFILE / "source-lock.json")
    parser.add_argument("--manifest", type=Path, default=PROFILE / "oracle-manifest.json")
    parser.add_argument("--rich-artifact", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--workers", type=int, default=4)
    arguments = parser.parse_args()
    if not 1 <= arguments.workers <= 32:
        parser.error("--workers must be between 1 and 32")
    try:
        scope = load_full_tree_scope(
            arguments.scope,
            source_lock_path=arguments.source_lock,
            artifact_manifest_path=arguments.manifest,
        )
        scope_sha256 = hashlib.sha256(arguments.scope.read_bytes()).hexdigest()
        inventory = json.loads(arguments.inventory.read_text(encoding="utf-8"))
        validate_inventory(inventory, scope, scope_sha256)
        index = run_full_tree_function_observations(
            arguments.rich_artifact,
            scope=scope,
            scope_sha256=scope_sha256,
            inventory=inventory,
            output_root=arguments.output_root,
            maximum_workers=arguments.workers,
            isolate_workers=True,
        )
    except (
        BoundedShardError,
        FullTreeFunctionObservationError,
        FullTreeInventoryError,
        FullTreeScopeError,
        OSError,
        json.JSONDecodeError,
    ) as error:
        print(f"full-tree function observation failed: {error}", file=sys.stderr)
        return 1
    counts = index["counts"]
    print(
        f"completed {counts['shards']} function-observation shards with "
        f"{counts['entities']} entities and {counts['serializedBytes']} bytes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
