from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.full_tree_scope import (  # noqa: E402
    FullTreeScopeError,
    canonical_json_bytes,
    load_full_tree_scope,
    normalize_source_path,
    shard_for_source_path,
)


SCOPE = REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-scope.json"
SOURCE_LOCK = REPOSITORY_ROOT / "oracle/llvm/22.1.6/source-lock.json"
MANIFEST = REPOSITORY_ROOT / "oracle/llvm/22.1.6/oracle-manifest.json"


class FullTreeScopeTest(unittest.TestCase):
    def load(self) -> dict[str, object]:
        return load_full_tree_scope(SCOPE, source_lock_path=SOURCE_LOCK, artifact_manifest_path=MANIFEST)

    def test_checked_scope_is_canonical_artifact_bound_and_has_finite_bounds(self) -> None:
        scope = self.load()
        self.assertEqual(canonical_json_bytes(scope), SCOPE.read_bytes())
        self.assertEqual("clang-llvm-full-tree-22.1.6", scope["oracle"]["id"])
        self.assertLessEqual(
            scope["bounds"]["perShard"]["entities"],
            scope["bounds"]["wholeRun"]["entities"],
        )

    def test_explicit_path_mapping_and_sharding_are_stable(self) -> None:
        scope = self.load()
        source = normalize_source_path(
            scope,
            "/usr/src/llvm-oracle/llvm-project-22.1.6.src/clang/lib/Driver/Driver.cpp",
        )
        generated = normalize_source_path(
            scope,
            "/usr/src/llvm-oracle/build/tools/clang/lib/Basic/DiagnosticGroups.inc",
        )
        self.assertEqual("source/clang/lib/Driver/Driver.cpp", source)
        self.assertEqual("clang-lib-driver", shard_for_source_path(scope, source))
        self.assertEqual("generated-tools-clang", shard_for_source_path(scope, generated))

    def test_unmapped_ambiguous_and_shallow_paths_fail_closed(self) -> None:
        scope = self.load()
        with self.assertRaisesRegex(FullTreeScopeError, "0 explicit prefix maps"):
            normalize_source_path(scope, "/developer/tree/clang/lib/Driver/Driver.cpp")
        with self.assertRaisesRegex(FullTreeScopeError, "0 shard rules"):
            shard_for_source_path(scope, "source/cmake/Modules/Probe.cmake")
        with self.assertRaisesRegex(FullTreeScopeError, "lacks 2 shard components"):
            shard_for_source_path(scope, "generated/tools/file.cpp")

    def test_identity_bound_and_unknown_policy_mutations_are_rejected(self) -> None:
        base = json.loads(SCOPE.read_text(encoding="utf-8"))
        mutations = []
        wrong_hash = copy.deepcopy(base)
        wrong_hash["oracle"]["sourceLockSha256"] = "0" * 64
        mutations.append((wrong_hash, "source-lock binding"))
        unknown = copy.deepcopy(base)
        unknown["unchecked"] = True
        mutations.append((unknown, "fails JSON Schema"))
        over = copy.deepcopy(base)
        over["bounds"]["perShard"]["entities"] = over["bounds"]["wholeRun"]["entities"] + 1
        mutations.append((over, "per-shard entities"))
        overlap = copy.deepcopy(base)
        overlap["pathPolicy"]["prefixMaps"].append(
            {"from": "/usr/src/llvm-oracle/build/tools/", "to": "shadow/"},
        )
        mutations.append((overlap, "may not overlap"))

        for value, message in mutations:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "scope.json"
                path.write_bytes(canonical_json_bytes(value))
                with self.assertRaisesRegex(FullTreeScopeError, message):
                    load_full_tree_scope(path, source_lock_path=SOURCE_LOCK, artifact_manifest_path=MANIFEST)


if __name__ == "__main__":
    unittest.main()
