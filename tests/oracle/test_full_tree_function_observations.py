from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.bounded_shards import load_complete_shard_index  # noqa: E402
from oracle.full_tree_function_observations import run_full_tree_function_observations  # noqa: E402
from oracle.full_tree_inventory import generate_inventory  # noqa: E402
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402


class FullTreeFunctionObservationTest(unittest.TestCase):
    def test_all_units_are_observed_once_and_repeated_runs_are_identical(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-tree-functions-") as temporary:
            root = Path(temporary)
            source = root / "source/clang/lib/Driver"
            source.mkdir(parents=True)
            (source / "first.c").write_text(
                "extern int second(int); int first(int value) { return second(value); }\n",
                encoding="utf-8",
            )
            (source / "second.c").write_text(
                "static inline int twice(int value) { return value + value; }\n"
                "int second(int value) { return twice(value); }\n",
                encoding="utf-8",
            )
            objects = []
            for name in ("first", "second"):
                target = root / f"{name}.o"
                subprocess.run(
                    ["gcc", "-g", "-O1", "-c", source / f"{name}.c", "-o", target],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                objects.append(target)
            artifact = root / "fixture"
            subprocess.run(
                ["gcc", *objects, "-nostdlib", "-Wl,-e,first", "-o", artifact],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            scope = json.loads(
                (REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-scope.json").read_text(encoding="utf-8")
            )
            scope["oracle"]["richArtifactSha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
            scope["pathPolicy"]["prefixMaps"] = [{"from": f"{root}/", "to": "source/"}]
            scope["sharding"]["rules"] = [
                {"componentDepth": 1, "pathPrefix": "source/source/clang/lib/", "shardPrefix": "clang-lib"}
            ]
            scope_sha256 = hashlib.sha256(canonical_json_bytes(scope)).hexdigest()
            inventory = generate_inventory(artifact, scope, scope_sha256)
            output = root / "observations"
            first = run_full_tree_function_observations(
                artifact,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                output_root=output,
                maximum_workers=2,
            )
            first_bytes = (output / "index.json").read_bytes()
            second = run_full_tree_function_observations(
                artifact,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                output_root=output,
                maximum_workers=2,
            )
            self.assertEqual(first, second)
            self.assertEqual(first_bytes, (output / "index.json").read_bytes())
            self.assertEqual(first, load_complete_shard_index(output))
            shard = json.loads(next((output / "outputs").glob("*.json")).read_text(encoding="utf-8"))
            self.assertEqual(2, shard["counts"]["units"])
            self.assertGreaterEqual(shard["counts"]["emittedRvas"], 2)
            self.assertEqual(
                sorted(item["rva"] for item in shard["emitted"]),
                [item["rva"] for item in shard["emitted"]],
            )


if __name__ == "__main__":
    unittest.main()
