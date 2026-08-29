#!/usr/bin/env python3
"""Internal one-process worker for a bounded full-tree data shard."""

from __future__ import annotations
import argparse, hashlib, json, resource, sys, threading
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))
from oracle.full_tree_data_observations import FullTreeDataObservationError, data_shard_inputs, produce_data_observation_shard  # noqa: E402
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rich-artifact", required=True, type=Path); parser.add_argument("--scope", required=True, type=Path)
    parser.add_argument("--scope-sha256", required=True); parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--shard", required=True); parser.add_argument("--input-sha256", required=True); parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        scope_payload = arguments.scope.read_bytes(); inventory_payload = arguments.inventory.read_bytes()
        scope = json.loads(scope_payload); inventory = json.loads(inventory_payload)
        if scope_payload != canonical_json_bytes(scope) or hashlib.sha256(scope_payload).hexdigest() != arguments.scope_sha256 or inventory_payload != canonical_json_bytes(inventory):
            raise FullTreeDataObservationError("worker control bindings do not match")
        inputs, units = data_shard_inputs(inventory, scope_sha256=arguments.scope_sha256, rich_sha256=scope["oracle"]["richArtifactSha256"])
        selected = [item for item in inputs if item.identifier == arguments.shard]
        if len(selected) != 1 or selected[0].input_sha256 != arguments.input_sha256:
            raise FullTreeDataObservationError("worker shard binding does not match")
        entities = produce_data_observation_shard(arguments.rich_artifact, scope=scope, scope_sha256=arguments.scope_sha256, inventory=inventory, shard=selected[0], units=units[arguments.shard], output=arguments.output, cancelled=threading.Event())
        resident = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024
        usage = resource.getrusage(resource.RUSAGE_SELF)
    except (FullTreeDataObservationError, OSError, json.JSONDecodeError) as error:
        print(f"data shard worker failed: {error}", file=sys.stderr); return 1
    print(json.dumps({"entities": entities, "maximumResidentBytes": resident, "systemCpuSeconds": usage.ru_stime, "userCpuSeconds": usage.ru_utime}, sort_keys=True, separators=(",", ":"))); return 0

if __name__ == "__main__":
    raise SystemExit(main())
