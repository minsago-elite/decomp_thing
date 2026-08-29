from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.full_tree_inventory import (  # noqa: E402
    FullTreeInventoryError,
    generate_inventory,
    validate_inventory,
)
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402
from oracle.full_tree_scope import load_full_tree_scope  # noqa: E402


CHECKED_SCOPE = REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-scope.json"
CHECKED_INVENTORY = REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-inventory.json"
CHECKED_SOURCE_LOCK = REPOSITORY_ROOT / "oracle/llvm/22.1.6/source-lock.json"
CHECKED_MANIFEST = REPOSITORY_ROOT / "oracle/llvm/22.1.6/oracle-manifest.json"


class CheckedFullTreeInventoryTest(unittest.TestCase):
    def test_checked_inventory_reconciles_all_production_units_and_shards(self) -> None:
        scope = load_full_tree_scope(
            CHECKED_SCOPE,
            source_lock_path=CHECKED_SOURCE_LOCK,
            artifact_manifest_path=CHECKED_MANIFEST,
        )
        scope_sha256 = hashlib.sha256(CHECKED_SCOPE.read_bytes()).hexdigest()
        inventory = json.loads(CHECKED_INVENTORY.read_text(encoding="utf-8"))

        validate_inventory(inventory, scope, scope_sha256)

        self.assertEqual(canonical_json_bytes(inventory), CHECKED_INVENTORY.read_bytes())
        self.assertEqual(2150, inventory["counts"]["compilationUnits"])
        self.assertEqual(57, inventory["counts"]["shards"])
        self.assertEqual(2150, sum(len(shard["unitIds"]) for shard in inventory["shards"]))


class FullTreeInventoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="full-tree-inventory-")
        self.root = Path(self.temporary.name)
        source = self.root / "source/clang/lib/Driver"
        source.mkdir(parents=True)
        (source / "main.c").write_text("extern int helper(void); int main(void) { return helper(); }\n", encoding="utf-8")
        (source / "helper.c").write_text("int helper(void) { return 0; }\n", encoding="utf-8")
        objects = []
        for name in ("main", "helper"):
            object_path = self.root / f"{name}.o"
            subprocess.run(
                ["gcc", "-g", "-O0", "-c", str(source / f"{name}.c"), "-o", str(object_path)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            objects.append(object_path)
        self.artifact = self.root / "fixture"
        subprocess.run(
            ["gcc", *(str(path) for path in objects), "-o", str(self.artifact)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.scope = json.loads(
            (REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-scope.json").read_text(encoding="utf-8"),
        )
        self.scope["oracle"]["richArtifactSha256"] = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.scope["pathPolicy"]["prefixMaps"] = [
            {"from": f"{self.root}/", "to": "source/"},
        ]
        self.scope["sharding"]["rules"] = [
            {"componentDepth": 1, "pathPrefix": "source/source/clang/lib/", "shardPrefix": "clang-lib"},
        ]
        self.scope_sha256 = hashlib.sha256(canonical_json_bytes(self.scope)).hexdigest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_generation_is_byte_deterministic_and_assigns_each_unit_once(self) -> None:
        first = generate_inventory(self.artifact, self.scope, self.scope_sha256)
        second = generate_inventory(self.artifact, self.scope, self.scope_sha256)
        validate_inventory(first, self.scope, self.scope_sha256)

        self.assertEqual(canonical_json_bytes(first), canonical_json_bytes(second))
        self.assertEqual(2, first["counts"]["compilationUnits"])
        self.assertEqual(2, first["counts"]["handwrittenUnits"])
        self.assertEqual(1, first["counts"]["shards"])
        self.assertEqual(
            sorted(unit["id"] for unit in first["units"]),
            first["shards"][0]["unitIds"],
        )

    def test_hash_count_duplicate_and_shard_mutations_fail_closed(self) -> None:
        inventory = generate_inventory(self.artifact, self.scope, self.scope_sha256)
        mutations = []
        bad_hash = copy.deepcopy(inventory)
        bad_hash["indexSha256"] = "0" * 64
        mutations.append((bad_hash, "index hash"))
        bad_count = copy.deepcopy(inventory)
        bad_count["counts"]["compilationUnits"] += 1
        mutations.append((bad_count, "counts"))
        duplicate = copy.deepcopy(inventory)
        duplicate["units"][1]["id"] = duplicate["units"][0]["id"]
        mutations.append((duplicate, "index hash|unique"))
        bad_shard = copy.deepcopy(inventory)
        bad_shard["shards"][0]["unitIds"] = bad_shard["shards"][0]["unitIds"][:-1]
        mutations.append((bad_shard, "shard ownership"))

        for mutation, message in mutations:
            with self.subTest(message=message), self.assertRaisesRegex(FullTreeInventoryError, message):
                validate_inventory(mutation, self.scope, self.scope_sha256)

    def test_artifact_substitution_and_unit_bound_fail_before_output(self) -> None:
        substituted = copy.deepcopy(self.scope)
        substituted["oracle"]["richArtifactSha256"] = "0" * 64
        with self.assertRaisesRegex(FullTreeInventoryError, "does not match"):
            generate_inventory(self.artifact, substituted, self.scope_sha256)

        bounded = copy.deepcopy(self.scope)
        bounded["bounds"]["wholeRun"]["compilationUnits"] = 1
        with self.assertRaisesRegex(FullTreeInventoryError, "exceeds scope bound"):
            generate_inventory(self.artifact, bounded, self.scope_sha256)


if __name__ == "__main__":
    unittest.main()
