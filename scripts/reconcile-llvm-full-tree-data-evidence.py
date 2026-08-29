#!/usr/bin/env python3
"""Reconcile canonical LLVM DWARF data truth with ELF global and ABI truth."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.full_tree_data_reconciliation import (  # noqa: E402
    FullTreeDataReconciliationError,
    generate_full_tree_data_reconciliation,
)
from oracle.full_tree_scope import canonical_json_bytes, load_full_tree_scope  # noqa: E402


def main() -> int:
    profile = REPOSITORY_ROOT / "oracle/llvm/22.1.6"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, default=profile / "full-tree-scope.json")
    parser.add_argument("--inventory", type=Path, default=profile / "full-tree-inventory.json")
    parser.add_argument("--source-lock", type=Path, default=profile / "source-lock.json")
    parser.add_argument("--manifest", type=Path, default=profile / "oracle-manifest.json")
    parser.add_argument("--data-truth-root", type=Path, required=True)
    parser.add_argument("--elf-data-index", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        scope = load_full_tree_scope(
            arguments.scope,
            source_lock_path=arguments.source_lock,
            artifact_manifest_path=arguments.manifest,
        )
        inventory = json.loads(arguments.inventory.read_text(encoding="utf-8"))
        report = generate_full_tree_data_reconciliation(
            data_truth_root=arguments.data_truth_root,
            elf_data_index_path=arguments.elf_data_index,
            inventory=inventory,
            scope=scope,
            scope_sha256=hashlib.sha256(arguments.scope.read_bytes()).hexdigest(),
        )
        arguments.output.write_bytes(canonical_json_bytes(report))
    except (FullTreeDataReconciliationError, OSError, json.JSONDecodeError) as error:
        print(f"full-tree data evidence reconciliation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report["counts"], sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
