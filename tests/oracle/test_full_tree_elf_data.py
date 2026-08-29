from __future__ import annotations
import hashlib, json, subprocess, tempfile, unittest
from pathlib import Path
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
from oracle.full_tree_elf_data import FullTreeElfDataError, generate_full_tree_elf_data_index  # noqa: E402
from oracle.full_tree_data_observations import _boolean_attribute, run_full_tree_data_observations  # noqa: E402
from oracle.full_tree_data_reconciliation import (  # noqa: E402
    FullTreeDataReconciliationError,
    generate_full_tree_data_reconciliation,
    validate_full_tree_data_reconciliation,
)
from oracle.full_tree_data_truth import (  # noqa: E402
    FullTreeDataTruthError,
    _global_key,
    _merge_type_references,
    _type_key,
    generate_full_tree_data_truth,
    validate_full_tree_data_truth_index,
)
from oracle.full_tree_data_baseline import (  # noqa: E402
    FullTreeDataBaselineError,
    generate_full_tree_data_baseline,
    require_no_data_baseline_regression,
)
from oracle.full_tree_inventory import generate_inventory  # noqa: E402
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402

class FullTreeElfDataTest(unittest.TestCase):
    def test_dwarf_flag_present_is_a_true_boolean(self) -> None:
        class Die:
            attributes = {"DW_AT_declaration": type("Attribute", (), {"value": True})()}
            offset = 1

        self.assertTrue(_boolean_attribute(Die(), "DW_AT_declaration"))

    def test_odr_member_reference_uses_sole_source_aligned_target(self) -> None:
        base = {
            "evidenceDieOffsets": ["0x1"],
            "modifierTags": ["DW_TAG_pointer_type"],
            "reasonCode": None,
            "resolutionCode": "exact-dwarf-offset",
            "targetOwnerShardId": "owner",
            "targetTypeId": "type-" + "a" * 32,
            "_targetQuality": "source-aligned",
        }
        declaration = {
            **base,
            "evidenceDieOffsets": ["0x2"],
            "targetOwnerShardId": "declaration-owner",
            "targetTypeId": "type-" + "b" * 32,
            "_targetQuality": "producer-declaration",
        }
        merged = _merge_type_references([declaration, base], "fixture-member")
        self.assertEqual(base["targetTypeId"], merged["targetTypeId"])
        self.assertEqual("odr-member-sole-source-aligned-target", merged["resolutionCode"])
        conflicting = {**declaration, "_targetQuality": "source-aligned"}
        with self.assertRaisesRegex(FullTreeDataTruthError, "incompatible type references"):
            _merge_type_references([conflicting, base], "fixture-member")

    def test_odr_member_reference_preserves_ambiguous_producer_targets(self) -> None:
        references = [
            {
                "evidenceDieOffsets": [f"0x{index + 1:x}"],
                "modifierTags": ["DW_TAG_pointer_type"],
                "reasonCode": None,
                "resolutionCode": "exact-dwarf-offset",
                "targetOwnerShardId": f"owner-{index:02d}",
                "targetTypeId": f"type-{index:032x}",
                "_targetQuality": "producer-declaration",
            }
            for index in range(20)
        ]
        merged = _merge_type_references(references, "fixture-member")
        self.assertIsNone(merged["targetTypeId"])
        self.assertIsNone(merged["targetOwnerShardId"])
        self.assertEqual("ambiguous-producer-declaration-targets", merged["reasonCode"])
        self.assertEqual("unresolved-authenticated-target-set", merged["resolutionCode"])
        self.assertEqual(20, merged["candidateTargetCount"])
        self.assertEqual(16, len(merged["candidateTargets"]))
        self.assertEqual(20, merged["evidenceDieOffsetCount"])
        self.assertEqual(16, len(merged["evidenceDieOffsets"]))

    def test_source_unaligned_nonaddress_globals_do_not_merge_by_name(self) -> None:
        base = {
            "addressRva": None,
            "declaration": {"column": None, "externalPathSha256": None, "line": 7, "sourcePath": None},
            "id": "global-observation-a",
            "names": ["shared_name"],
        }
        self.assertNotEqual(_global_key(base), _global_key({**base, "id": "global-observation-b"}))

    def test_lambda_dependent_types_remain_producer_observations(self) -> None:
        base = {
            "context": ["DW_TAG_namespace:std"],
            "declaration": {"column": None, "externalPathSha256": "a" * 64, "line": 381, "sourcePath": None},
            "id": "type-observation-a",
            "name": "_Iter_negate<(lambda at /producer/source.cpp:2762:33)>",
            "tag": "class",
            "unitId": "same-unit",
        }
        self.assertNotEqual(_type_key(base), _type_key({**base, "id": "type-observation-b"}))
        ordinary = {**base, "name": "ArrayRef<int>", "id": "type-observation-a"}
        self.assertEqual(_type_key(ordinary), _type_key({**ordinary, "id": "type-observation-b"}))

    def test_source_aligned_anonymous_nested_types_merge_by_declaration(self) -> None:
        base = {
            "context": ["DW_TAG_namespace:llvm", "DW_TAG_class_type:Container"],
            "declaration": {"column": None, "externalPathSha256": None, "line": 104, "sourcePath": "source/container.h"},
            "id": "type-observation-a",
            "name": None,
            "tag": "union",
            "unitId": "unit-a",
        }
        self.assertEqual(
            _type_key(base),
            _type_key({**base, "id": "type-observation-b", "unitId": "unit-b"}),
        )
        producer_only = {**base, "declaration": {**base["declaration"], "sourcePath": None}}
        self.assertNotEqual(
            _type_key(producer_only),
            _type_key({**producer_only, "id": "type-observation-b", "unitId": "unit-b"}),
        )

    def test_lossy_anonymous_subprogram_types_remain_observation_owned(self) -> None:
        base = {
            "context": ["DW_TAG_subprogram:(anonymous)"],
            "declaration": {"column": None, "externalPathSha256": None, "line": 241, "sourcePath": "source/template.h"},
            "id": "type-observation-a",
            "name": None,
            "tag": "class",
            "unitId": "unit-a",
        }
        self.assertNotEqual(
            _type_key(base),
            _type_key({**base, "id": "type-observation-b", "unitId": "unit-b"}),
        )

    def test_cross_shard_type_references_use_authenticated_type_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-tree-type-references-") as temporary:
            root = Path(temporary)
            include = root / "source/clang/include"
            include.mkdir(parents=True)
            (include / "shared.hpp").write_text(
                "struct Shared { int value; };\n", encoding="utf-8"
            )
            objects = []
            for component, body in (
                ("A", "Shared first = {1}; int read_first(){return first.value;}\n"),
                ("B", "Shared second = {2}; int read_second(){return second.value;}\n"),
                ("C", "Shared third = {3}; int read_first(); int read_second(); int main(){return read_first()+read_second()+third.value;}\n"),
            ):
                source = root / f"source/clang/lib/{component}/fixture.cpp"
                source.parent.mkdir(parents=True)
                source.write_text('#include "shared.hpp"\n' + body, encoding="utf-8")
                target = root / f"{component}.o"
                subprocess.run(
                    ["g++", "-g", "-O0", "-I", include, "-c", source, "-o", target],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                objects.append(target)
            rich = root / "fixture.full"
            subprocess.run(
                ["g++", "-no-pie", *objects, "-o", rich],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            scope = json.loads((REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-scope.json").read_text())
            scope["oracle"]["richArtifactSha256"] = hashlib.sha256(rich.read_bytes()).hexdigest()
            scope["pathPolicy"]["prefixMaps"] = [{"from": f"{root}/", "to": "source/"}]
            scope["sharding"]["rules"] = [{"componentDepth": 1, "pathPrefix": "source/source/clang/lib/", "shardPrefix": "clang-lib"}]
            scope_sha256 = hashlib.sha256(canonical_json_bytes(scope)).hexdigest()
            inventory = generate_inventory(rich, scope, scope_sha256)
            self.assertEqual(3, len(inventory["shards"]))
            observations = root / "observations"
            run_full_tree_data_observations(
                rich,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                output_root=observations,
                maximum_workers=2,
            )
            truth_root = root / "truth"
            index = generate_full_tree_data_truth(
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                observation_root=observations,
                output_root=truth_root,
            )
            self.assertGreaterEqual(index["counts"]["crossShardTypeReferences"], 2)
            forged_root = root / "forged"
            forged_root.mkdir()
            for record in index["shards"]:
                source = truth_root / record["path"]
                target = forged_root / record["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
            forged = json.loads(json.dumps(index))
            record = next(item for item in forged["shards"] if item["crossShardTypeReferences"])
            path = forged_root / record["path"]
            document = json.loads(path.read_text())
            reference = next(
                item["typeReference"]
                for item in document["globals"]
                if item["typeReference"]["targetTypeId"] is not None
                and item["typeReference"]["targetOwnerShardId"] != document["shard"]["id"]
            )
            reference["targetOwnerShardId"] = "forged-owner"
            payload = canonical_json_bytes(document)
            path.write_bytes(payload)
            record["bytes"] = len(payload)
            record["sha256"] = hashlib.sha256(payload).hexdigest()
            without_hash = {key: value for key, value in forged.items() if key != "indexSha256"}
            forged["indexSha256"] = hashlib.sha256(canonical_json_bytes(without_hash)).hexdigest()
            with self.assertRaisesRegex(FullTreeDataTruthError, "dangling or substituted owner"):
                validate_full_tree_data_truth_index(
                    forged,
                    output_root=forged_root,
                    scope_sha256=scope_sha256,
                    inventory=inventory,
                )

    def test_anonymous_namespace_type_identity_is_producer_owned(self) -> None:
        base = {
            "context": [],
            "declaration": {
                "column": None,
                "externalPathSha256": "a" * 64,
                "line": 7,
                "sourcePath": None,
            },
            "id": "type-observation-a",
            "name": "Box<(anonymous namespace)::Value>",
            "tag": "struct",
            "unitId": "cu-a",
        }
        other = {**base, "id": "type-observation-b", "unitId": "cu-b"}
        self.assertNotEqual(_type_key(base), _type_key(other))

    def test_nested_type_identity_includes_lexical_context(self) -> None:
        base = {
            "context": [
                "DW_TAG_class_type:OnDiskChainedHashTableGenerator<KeyA>",
            ],
            "declaration": {
                "column": 9,
                "externalPathSha256": None,
                "line": 60,
                "sourcePath": "source/llvm/include/llvm/Support/OnDiskHashTable.h",
            },
            "id": "type-observation-a",
            "name": "Item",
            "tag": "class",
            "unitId": "cu-a",
        }
        other = {
            **base,
            "context": [
                "DW_TAG_class_type:OnDiskChainedHashTableGenerator<KeyB>",
            ],
            "id": "type-observation-b",
        }
        self.assertNotEqual(_type_key(base), _type_key(other))

    def test_globals_tls_vtable_rtti_and_slots_are_twin_bound(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-tree-elf-data-") as temporary:
            root = Path(temporary); source = root / "source/clang/lib/CodeGen"; source.mkdir(parents=True)
            (source / "fixture.cpp").write_text("struct Base { virtual int value(); virtual ~Base(); }; int Base::value(){return 42;} Base::~Base()=default; Base global_base; thread_local int global_tls=3; int main(){return global_base.value()+global_tls;}\n", encoding="utf-8")
            rich = root / "fixture.full"; stripped = root / "fixture.stripped"
            subprocess.run(["g++", "-g", "-O0", "-no-pie", source / "fixture.cpp", "-o", rich], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["objcopy", "--strip-debug", "--strip-unneeded", rich, stripped], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            scope = json.loads((REPOSITORY_ROOT / "oracle/llvm/22.1.6/full-tree-scope.json").read_text())
            scope["oracle"]["richArtifactSha256"] = hashlib.sha256(rich.read_bytes()).hexdigest(); scope["oracle"]["strippedArtifactSha256"] = hashlib.sha256(stripped.read_bytes()).hexdigest()
            scope["pathPolicy"]["prefixMaps"] = [{"from": f"{root}/", "to": "source/"}]; scope["sharding"]["rules"] = [{"componentDepth": 1, "pathPrefix": "source/source/clang/lib/", "shardPrefix": "clang-lib"}]
            scope_sha256 = hashlib.sha256(canonical_json_bytes(scope)).hexdigest(); inventory = generate_inventory(rich, scope, scope_sha256)
            first = generate_full_tree_elf_data_index(rich, stripped, scope=scope, scope_sha256=scope_sha256, inventory=inventory)
            second = generate_full_tree_elf_data_index(rich, stripped, scope=scope, scope_sha256=scope_sha256, inventory=inventory)
            self.assertEqual(canonical_json_bytes(first), canonical_json_bytes(second)); aliases = [alias for item in first["globals"] for alias in item["aliases"]]
            self.assertTrue(any(alias["name"] == "global_base" for alias in aliases)); self.assertTrue(any(alias["kind"] == "tls" for alias in aliases))
            vtables = [alias for alias in aliases if alias["abi"] and alias["abi"]["kind"] == "vtable"]
            self.assertTrue(vtables); self.assertGreater(len(vtables[0]["abi"]["slots"]), 0)
            self.assertGreater(first["counts"]["abiResolvedSlots"], 0)
            self.assertTrue(any(slot["targetKind"] == "code" for alias in vtables for slot in alias["abi"]["slots"]))
            observations = root / "data-observations"
            run_full_tree_data_observations(
                rich,
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                output_root=observations,
                maximum_workers=1,
            )
            truth_root = root / "data-truth"
            generate_full_tree_data_truth(
                scope=scope,
                scope_sha256=scope_sha256,
                inventory=inventory,
                observation_root=observations,
                output_root=truth_root,
            )
            elf_path = root / "elf-data.json"
            elf_path.write_bytes(canonical_json_bytes(first))
            reconciliation = generate_full_tree_data_reconciliation(
                data_truth_root=truth_root,
                elf_data_index_path=elf_path,
                inventory=inventory,
                scope=scope,
                scope_sha256=scope_sha256,
            )
            self.assertEqual(0, reconciliation["counts"]["unexplainedEntities"])
            self.assertGreater(
                reconciliation["counts"]["matchedElfGlobals"],
                0,
                reconciliation,
            )
            self.assertGreater(reconciliation["counts"]["dwarfTypes"], 0)
            reconciliation_path = root / "data-reconciliation.json"
            reconciliation_path.write_bytes(canonical_json_bytes(reconciliation))
            baseline = generate_full_tree_data_baseline(
                data_truth_root=truth_root,
                reconciliation_report_path=reconciliation_path,
                inventory=inventory,
                scope_sha256=scope_sha256,
            )
            self.assertGreater(baseline["aggregate"]["types"]["exact"], 0)
            self.assertEqual(
                baseline["aggregate"]["globals"]["denominator"],
                baseline["aggregate"]["globals"]["exact"]
                + baseline["aggregate"]["globals"]["partial"]
                + baseline["aggregate"]["globals"]["missing"],
            )
            require_no_data_baseline_regression(baseline, baseline)
            regressed = json.loads(json.dumps(baseline))
            owner = next(
                shard for shard in regressed["shards"] if shard["types"]["exact"]
            )
            owner["types"]["exact"] -= 1
            owner["types"]["partial"] += 1
            regressed["aggregate"]["types"]["exact"] -= 1
            regressed["aggregate"]["types"]["partial"] += 1
            without_hash = {key: value for key, value in regressed.items() if key != "reportSha256"}
            regressed["reportSha256"] = hashlib.sha256(canonical_json_bytes(without_hash)).hexdigest()
            with self.assertRaisesRegex(FullTreeDataBaselineError, "regressed"):
                require_no_data_baseline_regression(regressed, baseline)
            forged = json.loads(json.dumps(first)); forged_vtable = next(alias for item in forged["globals"] for alias in item["aliases"] if alias["abi"] and alias["abi"]["kind"] == "vtable"); current_slot = forged_vtable["abi"]["slots"][0]["rawLittleEndian"]; forged_vtable["abi"]["slots"][0]["rawLittleEndian"] = ("ff" if current_slot == "00" * 8 else "00") * 8
            with self.assertRaisesRegex(FullTreeElfDataError, "hash"):
                from oracle.full_tree_elf_data import validate_full_tree_elf_data_index
                validate_full_tree_elf_data_index(forged, scope=scope, scope_sha256=scope_sha256, inventory=inventory)
            forged_report = json.loads(json.dumps(reconciliation))
            forged_report["globals"][0]["ownerShardIds"] = ["forged-owner"]
            with self.assertRaisesRegex(FullTreeDataReconciliationError, "hash"):
                validate_full_tree_data_reconciliation(
                    forged_report,
                    data_truth_index_sha256=hashlib.sha256((truth_root / "index.json").read_bytes()).hexdigest(),
                    elf_data_index_sha256=hashlib.sha256(elf_path.read_bytes()).hexdigest(),
                    inventory=inventory,
                    scope_sha256=scope_sha256,
                )
            substituted = json.loads(json.dumps(scope)); substituted["oracle"]["richArtifactSha256"] = "0" * 64
            with self.assertRaisesRegex(FullTreeElfDataError, "SHA-256"):
                generate_full_tree_elf_data_index(rich, stripped, scope=substituted, scope_sha256=scope_sha256, inventory=inventory)

if __name__ == "__main__": unittest.main()
