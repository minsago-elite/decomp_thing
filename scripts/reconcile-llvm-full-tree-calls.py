#!/usr/bin/env python3
"""Resolve full-tree LLVM call observations through function and ELF truth."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.full_tree_call_truth import FullTreeCallTruthError, generate_full_tree_call_truth  # noqa: E402
from oracle.full_tree_scope import load_full_tree_scope  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-scope.json")
    parser.add_argument("--source-lock", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/source-lock.json")
    parser.add_argument("--manifest", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/oracle-manifest.json")
    parser.add_argument("--inventory", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-inventory.json")
    parser.add_argument("--elf-index", type=Path, required=True)
    parser.add_argument("--function-truth-root", type=Path, required=True)
    parser.add_argument("--call-observations", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        scope = load_full_tree_scope(
            arguments.scope,
            source_lock_path=arguments.source_lock,
            artifact_manifest_path=arguments.manifest,
        )
        inventory = json.loads(arguments.inventory.read_text(encoding="utf-8"))
        index = generate_full_tree_call_truth(
            scope=scope,
            scope_sha256=hashlib.sha256(arguments.scope.read_bytes()).hexdigest(),
            inventory=inventory,
            elf_index_path=arguments.elf_index,
            function_truth_root=arguments.function_truth_root,
            call_observation_root=arguments.call_observations,
            output_root=arguments.output_root,
        )
    except (FullTreeCallTruthError, OSError, json.JSONDecodeError) as error:
        print(f"full-tree call reconciliation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(index["counts"], sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
