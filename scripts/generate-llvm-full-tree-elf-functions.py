#!/usr/bin/env python3
"""Generate the authenticated ELF-only full-tree Clang function index."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.full_tree_elf_functions import (  # noqa: E402
    FullTreeElfFunctionError,
    generate_full_tree_elf_function_index,
)
from oracle.full_tree_inventory import FullTreeInventoryError, validate_inventory  # noqa: E402
from oracle.full_tree_scope import FullTreeScopeError, canonical_json_bytes, load_full_tree_scope  # noqa: E402


PROFILE = REPOSITORY_ROOT / "oracle/llvm/22.1.6"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, default=PROFILE / "full-tree-scope.json")
    parser.add_argument("--inventory", type=Path, default=PROFILE / "full-tree-inventory.json")
    parser.add_argument("--source-lock", type=Path, default=PROFILE / "source-lock.json")
    parser.add_argument("--manifest", type=Path, default=PROFILE / "oracle-manifest.json")
    parser.add_argument("--rich-artifact", required=True, type=Path)
    parser.add_argument("--stripped-artifact", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        scope = load_full_tree_scope(
            arguments.scope,
            source_lock_path=arguments.source_lock,
            artifact_manifest_path=arguments.manifest,
        )
        scope_sha256 = hashlib.sha256(arguments.scope.read_bytes()).hexdigest()
        inventory = json.loads(arguments.inventory.read_text(encoding="utf-8"))
        validate_inventory(inventory, scope, scope_sha256)
        document = generate_full_tree_elf_function_index(
            arguments.rich_artifact,
            arguments.stripped_artifact,
            scope=scope,
            scope_sha256=scope_sha256,
            inventory=inventory,
        )
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = arguments.output.with_name(f".{arguments.output.name}.tmp")
        temporary.write_bytes(canonical_json_bytes(document))
        temporary.replace(arguments.output)
    except (
        FullTreeElfFunctionError,
        FullTreeInventoryError,
        FullTreeScopeError,
        OSError,
        json.JSONDecodeError,
    ) as error:
        print(f"ELF function index generation failed: {error}", file=sys.stderr)
        return 1
    print(
        f"wrote {document['counts']['functionRvas']} ELF function RVAs and "
        f"{document['counts']['aliases']} aliases"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
