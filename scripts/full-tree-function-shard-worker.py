#!/usr/bin/env python3
"""Internal one-process worker for a bounded full-tree function shard."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import resource
import sys
import threading


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.bounded_shards import ShardInput  # noqa: E402
from oracle.full_tree_function_observations import (  # noqa: E402
    FullTreeFunctionObservationError,
    _produce_shard,
    _shard_inputs,
)
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rich-artifact", required=True, type=Path)
    parser.add_argument("--scope", required=True, type=Path)
    parser.add_argument("--scope-sha256", required=True)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--shard", required=True)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        scope_payload = arguments.scope.read_bytes()
        inventory_payload = arguments.inventory.read_bytes()
        scope = json.loads(scope_payload.decode("utf-8"))
        inventory = json.loads(inventory_payload.decode("utf-8"))
        if scope_payload != canonical_json_bytes(scope) or hashlib.sha256(scope_payload).hexdigest() != arguments.scope_sha256:
            raise FullTreeFunctionObservationError("worker scope bytes do not match")
        if inventory_payload != canonical_json_bytes(inventory):
            raise FullTreeFunctionObservationError("worker inventory is not canonical")
        inputs, units = _shard_inputs(
            inventory,
            scope_sha256=arguments.scope_sha256,
            rich_sha256=scope["oracle"]["richArtifactSha256"],
        )
        selected = [item for item in inputs if item.identifier == arguments.shard]
        if len(selected) != 1 or selected[0].input_sha256 != arguments.input_sha256:
            raise FullTreeFunctionObservationError("worker shard input binding does not match")
        entities = _produce_shard(
            arguments.rich_artifact,
            scope=scope,
            scope_sha256=arguments.scope_sha256,
            inventory=inventory,
            shard=selected[0],
            units=units[arguments.shard],
            output=arguments.output,
            cancelled=threading.Event(),
        )
        maximum_resident_bytes = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024
    except (FullTreeFunctionObservationError, OSError, json.JSONDecodeError) as error:
        print(f"shard worker failed: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "entities": entities,
                "maximumResidentBytes": maximum_resident_bytes,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
