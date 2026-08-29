#!/usr/bin/env python3
"""Verify the authenticated LLVM full-tree scope and shard policy."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.full_tree_scope import FullTreeScopeError, load_full_tree_scope  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-scope.json")
    parser.add_argument("--source-lock", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/source-lock.json")
    parser.add_argument("--manifest", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/oracle-manifest.json")
    arguments = parser.parse_args()
    try:
        scope = load_full_tree_scope(
            arguments.scope,
            source_lock_path=arguments.source_lock,
            artifact_manifest_path=arguments.manifest,
        )
    except (FullTreeScopeError, OSError) as error:
        print(f"full-tree scope verification failed: {error}", file=sys.stderr)
        return 1
    print(f"verified full-tree scope: {scope['oracle']['id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
