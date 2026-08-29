#!/usr/bin/env python3
"""Merge full-tree LLVM global and aggregate observations into canonical truth."""

from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))
from oracle.full_tree_data_truth import FullTreeDataTruthError, generate_full_tree_data_truth  # noqa: E402
from oracle.full_tree_scope import load_full_tree_scope  # noqa: E402

def main() -> int:
    profile = REPOSITORY_ROOT / "oracle/llvm/22.1.6"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, default=profile / "full-tree-scope.json"); parser.add_argument("--inventory", type=Path, default=profile / "full-tree-inventory.json")
    parser.add_argument("--source-lock", type=Path, default=profile / "source-lock.json"); parser.add_argument("--manifest", type=Path, default=profile / "oracle-manifest.json")
    parser.add_argument("--observations", required=True, type=Path); parser.add_argument("--output-root", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        scope = load_full_tree_scope(arguments.scope, source_lock_path=arguments.source_lock, artifact_manifest_path=arguments.manifest)
        inventory = json.loads(arguments.inventory.read_text(encoding="utf-8"))
        index = generate_full_tree_data_truth(scope=scope, scope_sha256=hashlib.sha256(arguments.scope.read_bytes()).hexdigest(), inventory=inventory, observation_root=arguments.observations, output_root=arguments.output_root)
    except (FullTreeDataTruthError, OSError, json.JSONDecodeError) as error:
        print(f"full-tree data reconciliation failed: {error}", file=sys.stderr); return 1
    print(json.dumps(index["counts"], sort_keys=True, separators=(",", ":"))); return 0

if __name__ == "__main__":
    raise SystemExit(main())
