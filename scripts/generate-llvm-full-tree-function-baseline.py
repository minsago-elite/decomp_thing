#!/usr/bin/env python3
"""Generate the canonical per-shard LLVM stripped-function baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.full_tree_function_baseline import (  # noqa: E402
    FullTreeFunctionBaselineError,
    generate_full_tree_function_baseline,
)
from oracle.full_tree_scope import canonical_json_bytes, load_full_tree_scope  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-scope.json")
    parser.add_argument("--source-lock", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/source-lock.json")
    parser.add_argument("--manifest", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/oracle-manifest.json")
    parser.add_argument("--inventory", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-inventory.json")
    parser.add_argument("--truth-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        scope = load_full_tree_scope(
            arguments.scope,
            source_lock_path=arguments.source_lock,
            artifact_manifest_path=arguments.manifest,
        )
        inventory = json.loads(arguments.inventory.read_text(encoding="utf-8"))
        truth_index = json.loads((arguments.truth_root / "index.json").read_text(encoding="utf-8"))
        report = generate_full_tree_function_baseline(
            truth_index,
            truth_root=arguments.truth_root,
            scope=scope,
            scope_sha256=hashlib.sha256(arguments.scope.read_bytes()).hexdigest(),
            inventory=inventory,
        )
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_bytes(canonical_json_bytes(report))
    except (FullTreeFunctionBaselineError, OSError, json.JSONDecodeError) as error:
        print(f"full-tree function baseline failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report["aggregate"], sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
