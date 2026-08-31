#!/usr/bin/env python3
"""Legacy Python compatibility generator; not Kotlin/JVM oracle or release authority."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.full_tree_inventory import FullTreeInventoryError, generate_inventory, validate_inventory  # noqa: E402
from oracle.full_tree_scope import FullTreeScopeError, canonical_json_bytes, load_full_tree_scope  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-scope.json")
    parser.add_argument("--source-lock", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/source-lock.json")
    parser.add_argument("--manifest", type=Path, default=REPOSITORY_ROOT / "oracle/llvm/22.1.6/oracle-manifest.json")
    parser.add_argument("--rich-artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        scope = load_full_tree_scope(arguments.scope, source_lock_path=arguments.source_lock, artifact_manifest_path=arguments.manifest)
        scope_sha256 = hashlib.sha256(arguments.scope.read_bytes()).hexdigest()
        inventory = generate_inventory(arguments.rich_artifact, scope, scope_sha256)
        validate_inventory(inventory, scope, scope_sha256)
        payload = canonical_json_bytes(inventory)
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = arguments.output.with_name(f".{arguments.output.name}.tmp")
        temporary.write_bytes(payload)
        temporary.replace(arguments.output)
    except (FullTreeInventoryError, FullTreeScopeError, OSError) as error:
        print(f"full-tree inventory generation failed: {error}", file=sys.stderr)
        return 1
    print(f"wrote {inventory['counts']['compilationUnits']} units in {inventory['counts']['shards']} shards")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
