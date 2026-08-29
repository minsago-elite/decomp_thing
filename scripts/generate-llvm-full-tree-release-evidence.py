#!/usr/bin/env python3
"""Generate canonical machine and human A13 full-tree release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.full_tree_release_evidence import (  # noqa: E402
    FullTreeReleaseEvidenceError,
    generate_full_tree_release_evidence,
    render_full_tree_release_summary,
)
from oracle.full_tree_scope import canonical_json_bytes, load_full_tree_scope  # noqa: E402


def _pair(parser: argparse.ArgumentParser, name: str) -> None:
    parser.add_argument(f"--{name}-first", type=Path, required=True)
    parser.add_argument(f"--{name}-second", type=Path, required=True)


def main() -> int:
    profile = REPOSITORY_ROOT / "oracle/llvm/22.1.6"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, default=profile / "full-tree-scope.json")
    parser.add_argument("--source-lock", type=Path, default=profile / "source-lock.json")
    parser.add_argument("--manifest", type=Path, default=profile / "oracle-manifest.json")
    parser.add_argument("--inventory", type=Path, default=profile / "full-tree-inventory.json")
    parser.add_argument("--source-inventory", type=Path, default=profile / "full-tree-source-inventory.json")
    parser.add_argument("--function-elf", type=Path, required=True)
    _pair(parser, "function-observations"); _pair(parser, "function-truth")
    parser.add_argument("--function-baseline", type=Path, required=True)
    _pair(parser, "call-observations"); _pair(parser, "call-truth")
    parser.add_argument("--call-baseline", type=Path, required=True)
    parser.add_argument("--data-elf", type=Path, required=True)
    _pair(parser, "data-observations"); _pair(parser, "data-truth")
    parser.add_argument("--data-reconciliation", type=Path, required=True)
    parser.add_argument("--data-baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        scope = load_full_tree_scope(arguments.scope, source_lock_path=arguments.source_lock, artifact_manifest_path=arguments.manifest)
        inventory = json.loads(arguments.inventory.read_text(encoding="utf-8"))
        report = generate_full_tree_release_evidence(
            scope=scope, scope_sha256=hashlib.sha256(arguments.scope.read_bytes()).hexdigest(), inventory=inventory,
            source_inventory_path=arguments.source_inventory,
            function_elf_path=arguments.function_elf,
            function_observation_roots=(arguments.function_observations_first, arguments.function_observations_second),
            function_truth_roots=(arguments.function_truth_first, arguments.function_truth_second), function_baseline_path=arguments.function_baseline,
            call_observation_roots=(arguments.call_observations_first, arguments.call_observations_second),
            call_truth_roots=(arguments.call_truth_first, arguments.call_truth_second), call_baseline_path=arguments.call_baseline,
            data_elf_path=arguments.data_elf, data_observation_roots=(arguments.data_observations_first, arguments.data_observations_second),
            data_truth_roots=(arguments.data_truth_first, arguments.data_truth_second), data_reconciliation_path=arguments.data_reconciliation,
            data_baseline_path=arguments.data_baseline,
        )
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_bytes(canonical_json_bytes(report))
        arguments.summary.parent.mkdir(parents=True, exist_ok=True)
        arguments.summary.write_text(render_full_tree_release_summary(report), encoding="utf-8")
    except (FullTreeReleaseEvidenceError, OSError, json.JSONDecodeError, ValueError) as error:
        print(f"full-tree release evidence failed: {error}", file=sys.stderr)
        return 1
    print(report["reportSha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
