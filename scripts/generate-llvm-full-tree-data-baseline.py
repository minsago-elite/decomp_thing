#!/usr/bin/env python3
"""Generate per-shard LLVM global, type, and ABI observability baselines."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.full_tree_data_baseline import (  # noqa: E402
    FullTreeDataBaselineError,
    generate_full_tree_data_baseline,
)
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402


def main() -> int:
    profile = REPOSITORY_ROOT / "oracle/llvm/22.1.6"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, default=profile / "full-tree-scope.json")
    parser.add_argument("--inventory", type=Path, default=profile / "full-tree-inventory.json")
    parser.add_argument("--data-truth-root", type=Path, required=True)
    parser.add_argument("--reconciliation-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        inventory = json.loads(arguments.inventory.read_text(encoding="utf-8"))
        report = generate_full_tree_data_baseline(
            data_truth_root=arguments.data_truth_root,
            reconciliation_report_path=arguments.reconciliation_report,
            inventory=inventory,
            scope_sha256=hashlib.sha256(arguments.scope.read_bytes()).hexdigest(),
        )
        arguments.output.write_bytes(canonical_json_bytes(report))
    except (FullTreeDataBaselineError, OSError, json.JSONDecodeError) as error:
        print(f"full-tree data baseline failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report["aggregate"], sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
