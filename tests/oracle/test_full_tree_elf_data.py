from __future__ import annotations
import hashlib, json, subprocess, tempfile, unittest
from pathlib import Path
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
from oracle.full_tree_elf_data import FullTreeElfDataError, generate_full_tree_elf_data_index  # noqa: E402
from oracle.full_tree_data_observations import run_full_tree_data_observations  # noqa: E402
from oracle.full_tree_data_reconciliation import (  # noqa: E402
    FullTreeDataReconciliationError,
    generate_full_tree_data_reconciliation,
    validate_full_tree_data_reconciliation,
)
from oracle.full_tree_data_truth import _type_key, generate_full_tree_data_truth  # noqa: E402
from oracle.full_tree_data_baseline import (  # noqa: E402
    FullTreeDataBaselineError,
    generate_full_tree_data_baseline,
    require_no_data_baseline_regression,
)
from oracle.full_tree_inventory import generate_inventory  # noqa: E402
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402

class FullTreeElfDataTest(unittest.TestCase):
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
