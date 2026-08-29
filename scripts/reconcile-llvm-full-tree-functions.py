#!/usr/bin/env python3
"""Reconcile authenticated LLVM DWARF observations and ELF function twins."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.full_tree_function_truth import (  # noqa: E402
    FullTreeFunctionTruthError,
    reconcile_full_tree_function_truth,
)
from oracle.full_tree_scope import canonical_json_bytes, load_full_tree_scope  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-scope.json")
    parser.add_argument("--source-lock", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/source-lock.json")
    parser.add_argument("--manifest", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/oracle-manifest.json")
    parser.add_argument("--inventory", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-inventory.json")
    parser.add_argument("--elf-index", type=Path, required=True)
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        scope = load_full_tree_scope(
            arguments.scope,
            source_lock_path=arguments.source_lock,
            artifact_manifest_path=arguments.manifest,
        )
        inventory_payload = arguments.inventory.read_bytes()
        inventory = json.loads(inventory_payload.decode("utf-8"))
        if inventory_payload != canonical_json_bytes(inventory):
            raise FullTreeFunctionTruthError("inventory is not canonical")
        index = reconcile_full_tree_function_truth(
            scope=scope,
            scope_sha256=hashlib.sha256(arguments.scope.read_bytes()).hexdigest(),
            inventory=inventory,
            elf_index_path=arguments.elf_index,
            observation_root=arguments.observations,
            output_root=arguments.output_root,
        )
    except (FullTreeFunctionTruthError, OSError, json.JSONDecodeError) as error:
        print(f"full-tree function reconciliation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(index["counts"], sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
