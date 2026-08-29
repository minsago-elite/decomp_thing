from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.bounded_shards import load_complete_shard_index  # noqa: E402
from oracle.full_tree_elf_functions import generate_full_tree_elf_function_index  # noqa: E402
from oracle.full_tree_function_baseline import (  # noqa: E402
    FullTreeFunctionBaselineError,
    generate_full_tree_function_baseline,
    require_no_function_baseline_regression,
)
from oracle.full_tree_function_observations import (  # noqa: E402
    MAX_FULL_TREE_NAME_CHARACTERS,
    run_full_tree_function_observations,
)
from oracle.full_tree_function_truth import (  # noqa: E402
    FullTreeFunctionTruthError,
    reconcile_full_tree_function_truth,
    validate_full_tree_function_truth_index,
)
from oracle.full_tree_inventory import generate_inventory  # noqa: E402
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402
from oracle.function_recovery_oracle import OracleGenerationError, _dwarf_names  # noqa: E402


class FullTreeFunctionObservationTest(unittest.TestCase):
    def test_full_tree_name_limit_covers_authenticated_large_template_spelling(self) -> None:
        name = b"T" * 8_192
        die = SimpleNamespace(
            attributes={"DW_AT_linkage_name": SimpleNamespace(value=name)},
            offset=0x123,
        )
        with self.assertRaisesRegex(OracleGenerationError, "4096-character name limit"):
            _dwarf_names(die, "rich")
        self.assertEqual(
            [name.decode("ascii")],
            list(
                _dwarf_names(
                    die,
                    "rich",
                    maximum_name_characters=MAX_FULL_TREE_NAME_CHARACTERS,
                )
            ),
        )

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
            self.assertTrue(
                any(
                    declaration["sourcePath"] is not None
                    for function in shard["emitted"]
                    for declaration in function["declarations"]
                )
            )
            self.assertEqual(
                sorted(item["rva"] for item in shard["emitted"]),
                [item["rva"] for item in shard["emitted"]],
            )
            isolated = root / "isolated-observations"
            isolated_index = run_full_tree_function_observations(
                artifact,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                output_root=isolated,
                maximum_workers=1,
                isolate_workers=True,
            )
            self.assertEqual(first, isolated_index)
            self.assertEqual(
                next((output / "outputs").glob("*.json")).read_bytes(),
                next((isolated / "outputs").glob("*.json")).read_bytes(),
            )
            stripped = root / "fixture.stripped"
            subprocess.run(
                ["objcopy", "--strip-all", artifact, stripped],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            scope["oracle"]["strippedArtifactSha256"] = hashlib.sha256(stripped.read_bytes()).hexdigest()
            scope_sha256 = hashlib.sha256(canonical_json_bytes(scope)).hexdigest()
            inventory = generate_inventory(artifact, scope, scope_sha256)
            reconciled_observations = root / "reconciled-observations"
            run_full_tree_function_observations(
                artifact,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                output_root=reconciled_observations,
                maximum_workers=2,
            )
            elf_index = generate_full_tree_elf_function_index(
                artifact,
                stripped,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
            )
            elf_path = root / "elf-functions.json"
            elf_path.write_bytes(canonical_json_bytes(elf_index))
            first_truth_root = root / "function-truth-first"
            first_truth = reconcile_full_tree_function_truth(
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                elf_index_path=elf_path,
                observation_root=reconciled_observations,
                output_root=first_truth_root,
            )
            second_truth_root = root / "function-truth-second"
            second_truth = reconcile_full_tree_function_truth(
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                elf_index_path=elf_path,
                observation_root=reconciled_observations,
                output_root=second_truth_root,
            )
            self.assertEqual(first_truth, second_truth)
            self.assertEqual(
                (first_truth_root / "index.json").read_bytes(),
                (second_truth_root / "index.json").read_bytes(),
            )
            self.assertEqual(
                first_truth["counts"]["elfRvas"],
                first_truth["counts"]["scoredRvas"] + first_truth["counts"]["elfOnlyRvas"],
            )
            self.assertEqual(
                first_truth["counts"]["dwarfRvas"],
                first_truth["counts"]["scoredRvas"] + first_truth["counts"]["dwarfOnlyRvas"],
            )
            self.assertGreater(first_truth["counts"]["scoredRvas"], 0)
            self.assertEqual(len(inventory["shards"]), len(first_truth["shards"]))
            mutated = json.loads(json.dumps(second_truth))
            mutated["counts"]["scoredRvas"] += 1
            without_hash = {key: value for key, value in mutated.items() if key != "indexSha256"}
            mutated["indexSha256"] = hashlib.sha256(canonical_json_bytes(without_hash)).hexdigest()
            with self.assertRaisesRegex(FullTreeFunctionTruthError, "aggregate counts"):
                validate_full_tree_function_truth_index(
                    mutated,
                    output_root=second_truth_root,
                    scope=scope,
                    scope_sha256=scope_sha256,
                    inventory=inventory,
                    observation_index_sha256=mutated["oracle"]["observationIndexSha256"],
                    elf_index_sha256=mutated["oracle"]["elfIndexSha256"],
                )
            baseline = generate_full_tree_function_baseline(
                first_truth,
                truth_root=first_truth_root,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
            )
            require_no_function_baseline_regression(baseline, baseline)
            regressed = json.loads(json.dumps(baseline))
            scored_shard = next(
                item for item in regressed["shards"] if item["id"] != "elf-only-exclusions"
            )
            scored_shard["metric"]["fabricated"] += 1
            regressed["aggregate"]["fabricated"] += 1
            report_without_hash = {
                key: value for key, value in regressed.items() if key != "reportSha256"
            }
            regressed["reportSha256"] = hashlib.sha256(
                canonical_json_bytes(report_without_hash)
            ).hexdigest()
            with self.assertRaisesRegex(FullTreeFunctionBaselineError, "regressed"):
                require_no_function_baseline_regression(regressed, baseline)


if __name__ == "__main__":
    unittest.main()
