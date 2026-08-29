from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.bounded_shards import load_complete_shard_index  # noqa: E402
from oracle.full_tree_elf_functions import generate_full_tree_elf_function_index  # noqa: E402
from oracle.full_tree_determinism import compare_full_tree_runs  # noqa: E402
from oracle.full_tree_call_observations import (  # noqa: E402
    _address,
    _target,
    call_shard_inputs,
    produce_call_observation_shard,
    run_full_tree_call_observations,
)
from oracle.full_tree_call_truth import generate_full_tree_call_truth  # noqa: E402
from oracle.full_tree_call_baseline import (  # noqa: E402
    FullTreeCallBaselineError,
    generate_full_tree_call_baseline,
    require_no_call_baseline_regression,
)
from oracle.full_tree_function_baseline import (  # noqa: E402
    FullTreeFunctionBaselineError,
    generate_full_tree_function_baseline,
    require_no_function_baseline_regression,
)
from oracle.full_tree_function_observations import (  # noqa: E402
    MAX_FULL_TREE_NAME_CHARACTERS,
    _process_resident_bytes,
    run_full_tree_function_observations,
)
from oracle.full_tree_function_truth import (  # noqa: E402
    FullTreeFunctionTruthError,
    reconcile_full_tree_function_truth,
    validate_full_tree_function_truth_index,
)
from oracle.full_tree_data_observations import (  # noqa: E402
    data_shard_inputs,
    produce_data_observation_shard,
    run_full_tree_data_observations,
)
from oracle.full_tree_data_truth import generate_full_tree_data_truth  # noqa: E402
from oracle.full_tree_inventory import generate_inventory  # noqa: E402
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402
from oracle.function_recovery_oracle import OracleGenerationError, _dwarf_names  # noqa: E402


class FullTreeFunctionObservationTest(unittest.TestCase):
    def test_virtual_call_origin_is_not_promoted_to_a_direct_target(self) -> None:
        origin = SimpleNamespace(
            attributes={
                "DW_AT_name": SimpleNamespace(value=b"Base::value"),
                "DW_AT_virtuality": SimpleNamespace(value=1),
            },
            offset=0x220,
        )
        die = SimpleNamespace(
            attributes={"DW_AT_call_origin": SimpleNamespace(value=0x220)},
            get_DIE_from_attribute=lambda _: origin,
            offset=0x330,
        )
        result = _target(die, SimpleNamespace(), 0, (), (object, object, lambda _: None))
        self.assertEqual("virtual-unresolved", result["kind"])
        self.assertIsNone(result["functionId"])

    def test_exact_indirect_address_expression_produces_a_bounded_target_set(self) -> None:
        from elftools.dwarf.structs import DWARFStructs

        structs = DWARFStructs(
            little_endian=True, dwarf_format=32, address_size=8, dwarf_version=5
        )
        expression = b"\x03" + (0x1234).to_bytes(8, "little")
        die = SimpleNamespace(
            attributes={"DW_AT_call_target": SimpleNamespace(value=expression)},
            cu=SimpleNamespace(structs=structs),
            offset=0x330,
        )
        result = _target(die, SimpleNamespace(), 0, ((0x1000, 0x2000),), (object, object, lambda _: None))
        self.assertEqual("indirect-proven", result["kind"])
        self.assertEqual(["function-rva-0x1234"], result["provenFunctionIds"])

    def test_three_shard_calls_preserve_tail_virtual_indirect_external_and_alias_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-tree-call-fixture-") as temporary:
            root = Path(temporary)
            include = root / "source/clang/include"
            include.mkdir(parents=True)
            (include / "api.hpp").write_text(
                "struct Base { virtual ~Base(); virtual int value(int); };\n"
                "int a(int); int b(int); int apply(int (*)(int), int); int call_virtual(Base *, int);\n",
                encoding="utf-8",
            )
            sources = {
                "A": "int b(int); int a(int x){ return x ? b(x-1) : 1; } extern \"C\" int alias_a(int) __attribute__((alias(\"_Z1ai\")));\n",
                "B": "int a(int); int b(int x){ return x ? a(x-1) : 2; } int apply(int (*fn)(int), int x){ return fn(x); }\n",
                "C": "#include <cstdio>\nBase::~Base()=default; int Base::value(int x){return x;} struct Derived final: Base { int value(int x) override { return x+1; } }; int call_virtual(Base *p,int x){return p->value(x);} static int leaf(int x){return x+3;} int main(){Derived d; std::puts(\"fixture\"); return a(2)+apply(leaf,2)+call_virtual(&d,2);}\n",
            }
            objects = []
            for component, body in sources.items():
                source = root / f"source/clang/lib/{component}/fixture.cpp"
                source.parent.mkdir(parents=True)
                source.write_text('#include "api.hpp"\n' + body, encoding="utf-8")
                target = root / f"{component}.o"
                subprocess.run(
                    ["g++", "-gdwarf-5", "-O2", "-I", include, "-c", source, "-o", target],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                objects.append(target)
            rich = root / "fixture.full"
            stripped = root / "fixture.stripped"
            subprocess.run(["g++", "-no-pie", *objects, "-o", rich], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["objcopy", "--strip-all", rich, stripped], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            scope = json.loads((REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-scope.json").read_text())
            scope["oracle"]["richArtifactSha256"] = hashlib.sha256(rich.read_bytes()).hexdigest()
            scope["oracle"]["strippedArtifactSha256"] = hashlib.sha256(stripped.read_bytes()).hexdigest()
            scope["pathPolicy"]["prefixMaps"] = [{"from": f"{root}/", "to": "source/"}]
            scope["sharding"]["rules"] = [{"componentDepth": 1, "pathPrefix": "source/source/clang/lib/", "shardPrefix": "clang-lib"}]
            scope_sha256 = hashlib.sha256(canonical_json_bytes(scope)).hexdigest()
            inventory = generate_inventory(rich, scope, scope_sha256)
            self.assertEqual(3, len(inventory["shards"]))
            function_observations = root / "function-observations"
            run_full_tree_function_observations(
                rich, scope=scope, scope_sha256=scope_sha256, inventory=inventory,
                output_root=function_observations, maximum_workers=2,
            )
            elf = generate_full_tree_elf_function_index(
                rich, stripped, scope=scope, scope_sha256=scope_sha256, inventory=inventory,
            )
            elf_path = root / "elf-functions.json"
            elf_path.write_bytes(canonical_json_bytes(elf))
            function_truth_root = root / "function-truth"
            reconcile_full_tree_function_truth(
                scope=scope, scope_sha256=scope_sha256, inventory=inventory,
                elf_index_path=elf_path, observation_root=function_observations,
                output_root=function_truth_root,
            )
            call_observations = root / "call-observations"
            run_full_tree_call_observations(
                rich, scope=scope, scope_sha256=scope_sha256, inventory=inventory,
                output_root=call_observations, maximum_workers=2,
            )
            call_truth_root = root / "call-truth"
            call_index = generate_full_tree_call_truth(
                scope=scope, scope_sha256=scope_sha256, inventory=inventory,
                elf_index_path=elf_path, function_truth_root=function_truth_root,
                call_observation_root=call_observations, output_root=call_truth_root,
            )
            self.assertGreater(call_index["counts"]["tailCalls"], 0)
            self.assertGreater(call_index["counts"]["indirectUnresolved"], 0)
            self.assertGreater(call_index["counts"]["external"], 0)
            function_owners = {}
            alias_groups = []
            for record in json.loads((function_truth_root / "index.json").read_text())["shards"]:
                document = json.loads((function_truth_root / record["path"]).read_text())
                for item in document["functions"]:
                    function_owners[item["id"]] = record["id"]
                    if {"_Z1ai", "alias_a"}.issubset({alias["name"] for alias in item["aliases"]}):
                        alias_groups.append(item)
            self.assertEqual(1, len(alias_groups))
            cross_shard = False
            for record in call_index["shards"]:
                document = json.loads((call_truth_root / record["path"]).read_text())
                cross_shard |= any(
                    item["physicalTargetId"] is not None
                    and function_owners[item["physicalTargetId"]] != record["id"]
                    for item in document["calls"]
                )
            self.assertTrue(cross_shard)

    def test_indexed_call_address_uses_pyelftools_resolved_value(self) -> None:
        attribute = SimpleNamespace(
            form="DW_FORM_addrx",
            raw_value=70,
            value=0x268F46C,
        )
        dwarf = SimpleNamespace(get_addr=lambda *_: self.fail("address resolved twice"))
        self.assertEqual(0x268F46C, _address(attribute, dwarf, SimpleNamespace()))

    def test_worker_without_kernel_memory_mapping_has_zero_current_resident_bytes(self) -> None:
        process = SimpleNamespace(pid=1234, poll=lambda: None)
        with patch.object(Path, "read_text", return_value="Name:\tpython\nState:\tR (running)\n"):
            self.assertEqual(0, _process_resident_bytes(process))

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
                "struct pair { int left; int right; };\n"
                "enum mode { MODE_FIRST = 1, MODE_SECOND = 2 };\n"
                "struct pair global_pair = {1, 2};\n"
                "__thread int global_tls = 3;\n"
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
            call_inputs, call_units = call_shard_inputs(
                inventory,
                scope_sha256=scope_sha256,
                rich_sha256=scope["oracle"]["richArtifactSha256"],
            )
            call_output = root / "call-observations.json"
            call_count = produce_call_observation_shard(
                artifact,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                shard=call_inputs[0],
                units=call_units[call_inputs[0].identifier],
                output=call_output,
                cancelled=threading.Event(),
            )
            call_document = json.loads(call_output.read_text(encoding="utf-8"))
            self.assertEqual(call_count, call_document["counts"]["observedCallSites"])
            self.assertGreater(call_count, 0)
            data_inputs, data_units = data_shard_inputs(
                inventory,
                scope_sha256=scope_sha256,
                rich_sha256=scope["oracle"]["richArtifactSha256"],
            )
            data_output = root / "data-observations.json"
            data_count = produce_data_observation_shard(
                artifact,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                shard=data_inputs[0],
                units=data_units[data_inputs[0].identifier],
                output=data_output,
                cancelled=threading.Event(),
            )
            data_document = json.loads(data_output.read_text(encoding="utf-8"))
            self.assertEqual(data_count, data_document["counts"]["globals"] + data_document["counts"]["types"])
            self.assertTrue(any("global_pair" in item["names"] for item in data_document["globals"]))
            self.assertTrue(any(item["tag"] == "struct" and item["name"] == "pair" for item in data_document["types"]))
            data_root = root / "bounded-data-observations"
            data_index = run_full_tree_data_observations(
                artifact,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                output_root=data_root,
                maximum_workers=1,
            )
            self.assertEqual(data_count, data_index["counts"]["entities"])
            data_execution = json.loads(
                (data_root / "execution-evidence.json").read_text(encoding="utf-8")
            )
            self.assertEqual(data_index["indexSha256"], data_execution["indexSha256"])
            self.assertEqual(
                data_output.read_bytes(),
                next((data_root / "outputs").glob("*.json")).read_bytes(),
            )
            data_truth_root = root / "data-truth"
            data_truth = generate_full_tree_data_truth(
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                observation_root=data_root,
                output_root=data_truth_root,
            )
            self.assertGreater(data_truth["counts"]["globals"], 0)
            self.assertGreater(data_truth["counts"]["types"], 0)
            call_root = root / "bounded-call-observations"
            call_index = run_full_tree_call_observations(
                artifact,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                output_root=call_root,
                maximum_workers=1,
            )
            self.assertEqual(call_count, call_index["counts"]["entities"])
            call_execution = json.loads(
                (call_root / "execution-evidence.json").read_text(encoding="utf-8")
            )
            self.assertEqual(call_index["indexSha256"], call_execution["indexSha256"])
            self.assertEqual(
                call_output.read_bytes(),
                next((call_root / "outputs").glob("*.json")).read_bytes(),
            )
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
            execution_evidence = json.loads(
                (isolated / "execution-evidence.json").read_text(encoding="utf-8")
            )
            self.assertEqual(first["indexSha256"], execution_evidence["indexSha256"])
            self.assertEqual(first["counts"]["entities"], execution_evidence["observed"]["entities"])
            determinism = compare_full_tree_runs(output, isolated)
            self.assertTrue(determinism["identical"])
            self.assertEqual(1, determinism["shards"])
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
            truth_call_root = root / "truth-call-observations"
            run_full_tree_call_observations(
                artifact,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                output_root=truth_call_root,
                maximum_workers=1,
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
            call_truth = generate_full_tree_call_truth(
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                elf_index_path=elf_path,
                function_truth_root=first_truth_root,
                call_observation_root=truth_call_root,
                output_root=root / "call-truth",
            )
            self.assertGreater(call_truth["counts"]["edges"], 0)
            self.assertEqual(
                call_truth["counts"]["edges"],
                call_truth["counts"]["directInternal"]
                + call_truth["counts"]["external"]
                + call_truth["counts"]["indirectProven"]
                + call_truth["counts"]["indirectUnresolved"]
                + call_truth["counts"]["virtualUnresolved"],
            )
            call_truth_root = root / "call-truth"
            call_baseline = generate_full_tree_call_baseline(
                call_truth,
                truth_root=call_truth_root,
                inventory=inventory,
            )
            self.assertEqual(
                call_baseline["aggregate"]["denominator"],
                call_baseline["aggregate"]["exact"]
                + call_baseline["aggregate"]["partial"]
                + call_baseline["aggregate"]["missing"],
            )
            require_no_call_baseline_regression(call_baseline, call_baseline)
            regressed_call_baseline = json.loads(json.dumps(call_baseline))
            metric = regressed_call_baseline["shards"][0]["metric"]
            if metric["exact"]:
                metric["exact"] -= 1
                metric["partial"] += 1
                aggregate = regressed_call_baseline["aggregate"]
                aggregate["exact"] -= 1
                aggregate["partial"] += 1
                without_hash = {
                    key: value
                    for key, value in regressed_call_baseline.items()
                    if key != "reportSha256"
                }
                regressed_call_baseline["reportSha256"] = hashlib.sha256(
                    canonical_json_bytes(without_hash)
                ).hexdigest()
                with self.assertRaisesRegex(FullTreeCallBaselineError, "regressed"):
                    require_no_call_baseline_regression(
                        regressed_call_baseline,
                        call_baseline,
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
